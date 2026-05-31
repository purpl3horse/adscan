"""Proactive posture probe engine.

Runs lightweight, single-purpose probes against a Domain Controller to elicit
posture signals BEFORE the first real scan operation pays for the discovery.
Each probe targets exactly one ``ConstraintCategory``. All probes are
READ-ONLY and target only the DC the operator already pointed ADscan at —
same network scope as a regular ``start_unauth`` / ``start_auth`` phase.

Concurrency:
    - ``probe_unauth`` runs its four physical probes (U1/U4/U2/U3) FULLY
      SEQUENTIALLY — no ``asyncio.gather``. Concurrent execution caused
      event-loop starvation: the vendor TLS/NTLM path does not yield the
      loop cleanly, inflating each probe's wall-clock to seconds even though
      its real latency is ~50-150ms. See :func:`probe_unauth` docstring.
    - ``probe_auth`` Kerberos probes share the KDC connection — sequential;
      NTLM and SMB-signing probes are independent and still use
      ``asyncio.gather``.
    - ``timeout_per_probe`` is enforced per probe; one hung probe does not
      hang the others.

Idempotency:
    Re-running ``probe_unauth`` / ``probe_auth`` produces the same posture.
    Probes whose category is already known at HIGH confidence and not stale
    are skipped silently unless ``force=True``.

This module emits ``PostureSignal`` instances through the provided
``PostureSink``; it never touches the workspace directly. It does not print
to the console (only ``print_info_debug`` traces) and never wires itself into
``start.py`` — Batch 3 owns lifecycle integration.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    IntelligenceFinding,
    PostureSignal,
    SignalConfidence,
    TriState,
)
from adscan_internal.services.posture_sink import PostureSink


# --------------------------------------------------------------------------- #
# Public types
# --------------------------------------------------------------------------- #


class ProbePhase(str, Enum):
    """Logical phase a probe runs in."""

    UNAUTH = "unauth"
    AUTH = "auth"


@dataclass(frozen=True)
class ProbeResult:
    """Outcome of a single probe.

    Attributes:
        category: The primary ``ConstraintCategory`` this probe targets.
        state: Resolved tri-state (``UNKNOWN`` when ``succeeded=False``).
        confidence: Confidence level for the resolved state.
        signal_code: Stable machine-readable code (``"SKIPPED_ALREADY_KNOWN"``
            when ``skipped=True``, ``"PROBE_FAILED"`` when ``succeeded=False``).
        message: Human-readable description.
        duration_ms: Wall-clock time spent on the probe (0.0 when skipped).
        succeeded: ``False`` when the probe could not run to a useful answer
            (timeout, transport refused). ``state`` stays ``UNKNOWN``.
        skipped: ``True`` when no network call was made because the existing
            posture already records this category at HIGH confidence and is
            not stale.
    """

    category: ConstraintCategory
    state: TriState
    confidence: SignalConfidence
    signal_code: str
    message: str
    duration_ms: float
    succeeded: bool
    skipped: bool = False


@dataclass(frozen=True)
class ProbeCredentials:
    """Credential bundle accepted by ``probe_auth``.

    A probe that needs a specific credential type (plaintext password for
    explicit-etype AS-REQ, password-or-hash for NTLM bind, etc.) is skipped
    silently when the bundle does not provide it.
    """

    username: str
    password: Optional[str] = None
    nt_hash: Optional[str] = None
    aes_key: Optional[str] = None
    ccache_path: Optional[str] = None

    def __post_init__(self) -> None:
        # Auto-route an NT hash that landed in the password field; otherwise
        # ``can_do_explicit_etype_asreq`` would lie and the probe would build
        # an AS-REQ with a wrong AES key derived from the hash as plaintext.
        from adscan_internal.services.credential_routing import (
            promote_credential_fields,
        )

        new_pwd, new_hash, new_aes, new_cc = promote_credential_fields(
            password=self.password,
            nt_hash=self.nt_hash,
            aes_key=self.aes_key,
            ccache_path=self.ccache_path,
        )
        if new_pwd != self.password:
            object.__setattr__(self, "password", new_pwd)
        if new_hash != self.nt_hash:
            object.__setattr__(self, "nt_hash", new_hash)
        if new_aes != self.aes_key:
            object.__setattr__(self, "aes_key", new_aes)
        if new_cc != self.ccache_path:
            object.__setattr__(self, "ccache_path", new_cc)

    @property
    def can_do_explicit_etype_asreq(self) -> bool:
        """True when we can craft a controlled-etype AS-REQ (needs plaintext)."""
        return self.password is not None


# Convention:
#   on_progress(category, None)    -> probe is starting
#   on_progress(category, result)  -> probe finished (or was skipped)
ProbeProgressCallback = Callable[[ConstraintCategory, Optional[ProbeResult]], None]


# --------------------------------------------------------------------------- #
# Probe schema version — bump this when a probe's logic changes in a way that
# invalidates previously-cached results. All ``_emit`` calls stamp the current
# version into the persisted ``ConstraintState``; the freshness check treats
# a version mismatch as STALE, forcing a re-probe.
#
# Why this exists. Posture caches persist for hours-to-days (24h default, 7d
# for structural Kerberos constraints). If a probe's logic changes (new
# technique, different signal classification, fixed false-positive path)
# without bumping this version, all existing caches keep returning the OLD
# probe's verdict until their natural TTL expires — even though the new
# code would yield a different (correct) answer. Bumping the version
# transparently invalidates every cache the moment the new code runs.
#
# When to bump:
#   * Probe technique changes (e.g. bind-based U1 -> TCP+TLS U1).
#   * Classification changes (e.g. ``timeout -> DISABLED HIGH`` becomes
#     ``timeout -> UNKNOWN LOW, no emit``).
#   * New states / signal codes that change downstream interpretation.
#
# When NOT to bump:
#   * Cosmetic changes (renamed variables, comments, refactors that don't
#     change emitted state/confidence/signal_code).
#   * Bug fixes that only affect failure paths NOT writing to the sink.
#
# Version history:
#   v1 (2026-05-26): Initial. Introduced alongside the U1 TCP+TLS rewrite
#                    and the cache-only-observations policy refactor; both
#                    invalidate any pre-existing posture cache.
#   v2 (2026-05-29): Added U4 (``_probe_ldap_starttls_available``) — a new
#                    probe with new states/signal codes (LDAP_STARTTLS_*),
#                    which changes downstream interpretation (new
#                    ``LDAP_STARTTLS_AVAILABLE`` category). Bumped so any
#                    workspace written by v1 re-probes on first contact.
_PROBE_SCHEMA_VERSION: int = 2


# --------------------------------------------------------------------------- #
# Internal helpers
# --------------------------------------------------------------------------- #


def _safe_progress(
    callback: Optional[ProbeProgressCallback],
    category: ConstraintCategory,
    result: Optional[ProbeResult],
) -> None:
    """Invoke ``callback`` swallowing every exception (telemetry only).

    The probe engine must not fail because the UI layer raised.
    """
    if callback is None:
        return
    try:
        callback(category, result)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] on_progress raised: {type(exc).__name__}: {exc}"
        )


def _should_skip(
    posture: Optional[DomainPosture],
    category: ConstraintCategory,
    force: bool,
) -> tuple[bool, Optional[ProbeResult]]:
    """Return ``(skip, skipped_result)`` for the given category.

    A probe is skipped when ALL of the following hold:
      * ``force`` is False.
      * The posture records a non-UNKNOWN HIGH-confidence value.
      * The constraint is not stale (within its TTL).
      * The persisted ``probe_schema_version`` matches the current
        ``_PROBE_SCHEMA_VERSION`` — a mismatch means the cached
        observation came from a now-obsolete probe and must be
        re-validated. Legacy records (``probe_schema_version=None``)
        are also treated as obsolete, so existing workspaces
        transparently re-probe on first contact with the new code.

    Returning ``(True, skipped_result)`` short-circuits the probe and
    returns the cached state to the caller. ``(False, None)`` means
    "run the probe".
    """
    if force or posture is None:
        return False, None
    constraint = posture.get(category)
    if constraint.state == TriState.UNKNOWN:
        return False, None
    if constraint.confidence != SignalConfidence.HIGH:
        return False, None
    if constraint.is_stale:
        return False, None
    if constraint.is_schema_outdated(_PROBE_SCHEMA_VERSION):
        return False, None
    skipped = ProbeResult(
        category=category,
        state=constraint.state,
        confidence=constraint.confidence,
        signal_code="SKIPPED_ALREADY_KNOWN",
        message=f"Already known: {constraint.state.value} ({constraint.confidence.value})",
        duration_ms=0.0,
        succeeded=True,
        skipped=True,
    )
    return True, skipped


def _walk_chain(exc: BaseException) -> list[BaseException]:
    """Walk ``__cause__``/``__context__`` chain, returning every linked exception."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _chain_text(exc: BaseException) -> str:
    """Render the exception chain as one lowercase string for substring matches."""
    return " ".join(f"{type(c).__name__}: {c}".lower() for c in _walk_chain(exc))


def _emit(
    sink: PostureSink,
    *,
    domain: str,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str,
    source: str = "posture_probe",
) -> None:
    """Best-effort emission of one ``PostureSignal`` through ``sink``.

    Stamps ``_PROBE_SCHEMA_VERSION`` on every emission so the persisted
    record carries the version of the probe-code that produced it. The
    freshness check in :func:`_should_skip` treats a version mismatch
    (or a missing version on legacy records) as STALE and forces a
    re-probe.
    """
    try:
        signal = PostureSignal(
            domain=domain,
            category=category,
            state=state,
            confidence=confidence,
            source=source,
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
            probe_schema_version=_PROBE_SCHEMA_VERSION,
        )
        sink(signal)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[posture_probe] sink raised: {type(exc).__name__}: {exc}")


def _now_ms() -> float:
    return time.perf_counter() * 1000.0


# --------------------------------------------------------------------------- #
# Unauth probes
# --------------------------------------------------------------------------- #


async def _probe_ldaps_available(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U1 — LDAPS reachability AND functionality on TCP/636.

    The question this probe answers is: **"is LDAPS actually usable
    against this DC?"**. We discriminate three failure modes the
    posture system cares about distinctly:

    * ``LDAPS_PORT_CLOSED`` — TCP/636 returns RST or is unreachable.
      The port is not listening at all.
    * ``LDAPS_TLS_BROKEN`` — TCP/636 accepts the connection but the
      TLS handshake fails (cert expired, cipher mismatch, unsupported
      TLS version, broken cert chain). Port is open but LDAPS is not
      functional. Observed in real customer environments where a DC
      had a stale self-signed cert that no client could negotiate.
    * ``LDAPS_HANDSHAKE_TIMEOUT`` — neither side completes within
      the budget. Treat as DISABLED (any subsequent LDAPS operation
      would suffer the same hang).

    Two-step in a single call. ``asyncio.open_connection(ssl=ctx)``
    does TCP + TLS handshake in one shot, and the exception type
    discriminates the layer:

    * ``ConnectionRefusedError`` / generic ``OSError`` → TCP layer.
    * ``ssl.SSLError`` → TLS layer (TCP succeeded, handshake failed).
    * ``asyncio.TimeoutError`` → either layer hung past the budget.

    We deliberately do NOT speak LDAP after the TLS handshake. The
    posture question is "can we negotiate LDAPS"; what we'd do with
    the channel is a separate concern owned by ``_probe_ldap_signing``
    and ``_probe_ldaps_channel_binding``.

    Certificate validation is intentionally disabled (``CERT_NONE``,
    ``check_hostname=False``). AD DCs frequently present self-signed
    or domain-CA-issued certificates whose hostname does not match
    the DC's IP. A strict TLS context would reject those even though
    every real LDAPS client (impacket, badldap, native Windows) also
    accepts them. The goal is to mirror what a functional LDAPS
    client would see, not to validate the PKI.

    Why a short timeout (capped at 2s of the caller's budget): TLS
    handshake to a reachable DC on a LAN completes well under 200ms.
    Anything taking longer is either congested or filtered. A short
    cap also keeps the posture cycle bounded — U1's outcome gates U3,
    so a 5s wait here delays the entire unauth wave by 5s for nothing.
    """
    import ssl as _ssl  # noqa: PLC0415 — kept local; only U1 needs it

    cat = ConstraintCategory.LDAPS_AVAILABLE
    started = _now_ms()
    handshake_timeout = min(timeout, 2.0)

    # AD DCs commonly present certs that don't match the IP/hostname
    # we connect with. Every real LDAPS client (impacket, badldap,
    # native Windows) skips strict validation here — we mirror that.
    ssl_ctx = _ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = _ssl.CERT_NONE

    print_info_debug(
        f"[posture_probe] U1 LDAPS opening TCP+TLS to {dc_ip}:636 "
        f"(timeout={handshake_timeout}s, ssl_check_hostname=False, "
        f"ssl_verify_mode=CERT_NONE)"
    )
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host=dc_ip, port=636, ssl=ssl_ctx),
            timeout=handshake_timeout,
        )
        print_info_debug(
            f"[posture_probe] U1 LDAPS TCP+TLS handshake OK on {dc_ip}:636 "
            f"in {_now_ms() - started:.0f}ms"
        )
        # TCP + TLS both succeeded → LDAPS is functional.
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_OK",
            message="TCP/636 reachable and TLS handshake succeeded — LDAPS functional",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_OK",
            message="TCP/636 reachable and TLS handshake succeeded — LDAPS functional",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except _ssl.SSLError as exc:
        # TCP succeeded but TLS layer failed (cert expired, cipher
        # mismatch, broken chain, ...). Port is open but LDAPS is not
        # functional — distinct from "port closed".
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS ssl.SSLError on {dc_ip}:636 after "
            f"{_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc} "
            f"(args={exc.args!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_BROKEN",
            message=f"TCP/636 open but TLS handshake failed: {type(exc).__name__}",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TLS_BROKEN",
            message=f"TCP/636 open but TLS handshake failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        # A timeout is NOT an observation about LDAPS availability — it's
        # an observation about OUR clock. The handshake might be slow,
        # the event loop might be saturated by concurrent probes, or the
        # DC might be transiently busy. Treating timeout as DISABLED HIGH
        # was the bug that poisoned posture caches for 24h after a single
        # bad run (see CLAUDE.md § "Posture caching policy"). The correct
        # answer is UNKNOWN LOW + NO sink emit — the cache stays untouched
        # and the next operation re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS asyncio.TimeoutError on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms (budget={handshake_timeout}s) — "
            "did NOT complete TCP+TLS handshake. Likely causes: DC TLS slow, "
            "filtered, or SNI mismatch (no server_hostname supplied). "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        # NOTE: no ``_emit`` here — timeout does not persist to posture.
        # The probe failed to characterise the DC; cache stays untouched.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAPS_HANDSHAKE_TIMEOUT",
            message=f"TCP/636 + TLS handshake hung past {handshake_timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except ConnectionRefusedError as exc:
        # Explicit TCP RST from the DC — port is closed. This IS an
        # observation; cache HIGH normally.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS ConnectionRefused on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms — {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_CLOSED",
            message="TCP/636 returned RST — port closed",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_CLOSED",
            message="TCP/636 returned RST — port closed",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except OSError as exc:
        # Generic OSError covers ``ENETUNREACH`` / ``EHOSTUNREACH`` — the
        # kernel telling us the DC is not routable. That IS an
        # observation (the network layer answered) so we cache HIGH.
        # Other rare OSErrors are also captured here — if the kernel
        # answered, the answer is authoritative for this network state.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U1 LDAPS OSError on {dc_ip}:636 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: "
            f"{exc} (errno={getattr(exc, 'errno', None)!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_NETWORK_UNREACHABLE",
            message=f"TCP/636 network unreachable ({type(exc).__name__})",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_NETWORK_UNREACHABLE",
            message=f"TCP/636 network unreachable ({type(exc).__name__})",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    finally:
        # Best-effort close — never let an open socket leak into the
        # event loop after the probe answers.
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception as close_exc:  # noqa: BLE001
                telemetry.capture_exception(close_exc)


async def _probe_ldap_starttls_available(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U4 — StartTLS (RFC 2830) availability on plain LDAP/389.

    The question this probe answers is: **"can a plain LDAP/389 session be
    upgraded to TLS via StartTLS against this DC?"**. StartTLS is the only
    confidentiality mechanism that protects *anonymous/SIMPLE* binds without
    an LDAPS (636) listener, so its availability is a distinct posture fact
    from ``LDAPS_AVAILABLE`` — a DC can have 636 filtered yet still present a
    usable cert on 389, or vice-versa.

    Technique (modeled on :func:`_probe_ldaps_available`): open a raw
    ``MSLDAPClientConnection`` to ``ldap://<dc_ip>`` (plain 389, anonymous,
    no bind), then call the vendor StartTLS primitive
    (``MSLDAPClientConnection.starttls()`` in
    ``vendor/badldap/badldap/connection.py``). That primitive sends the
    StartTLS extendedReq (OID ``1.3.6.1.4.1.1466.20037``) and, on a success
    result code, wraps the socket in TLS. We never bind — the posture
    question is purely "does the StartTLS handshake complete", what we would
    do with the channel is a separate concern.

    Observed-vs-inferred discrimination (CLAUDE.md § Posture caching policy):

    * ``LDAP_STARTTLS_OK`` — extendedReq accepted AND TLS handshake completed
      (``starttls()`` returned ``ok=True``). ENABLED HIGH — OBSERVED.
    * ``LDAP_STARTTLS_REFUSED`` — extendedReq returned a non-success result
      code (``unwillingToPerform`` / refused), surfaced as
      ``LDAPBindException``. DISABLED HIGH — OBSERVED (the DC told us no).
    * ``LDAP_STARTTLS_TLS_BROKEN`` — extendedReq accepted but the TLS wrap
      raised ``ssl.SSLError`` (absent/broken/expired cert). DISABLED HIGH —
      OBSERVED.
    * ``LDAP_STARTTLS_PORT_CLOSED`` — TCP/389 refused or unreachable
      (``ConnectionRefusedError`` / ``OSError``). DISABLED HIGH — OBSERVED
      (the network layer answered).
    * ``LDAP_STARTTLS_TIMEOUT`` — ``asyncio.TimeoutError`` / event-loop
      saturation / anything we cannot classify. UNKNOWN LOW, **NO ``_emit``**
      — a timeout is an observation about OUR clock, not about the DC.
      Caching it would poison the category for 24h after a single transient
      hang (the exact bug class documented in CLAUDE.md § Posture caching
      policy, Invariant 2). The cache stays clean; the next caller re-probes.

    Certificate validation is intentionally disabled — AD DCs commonly
    present self-signed / domain-CA certs whose SAN does not match the IP we
    connect with, and the vendor target's SSL context mirrors what every real
    LDAPS/StartTLS client (impacket, badldap, native Windows) accepts. The
    goal is to mirror a functional client, not to validate the PKI.
    """
    import ssl as _ssl  # noqa: PLC0415 — kept local; only U4 needs the type

    from badldap.commons.exceptions import (  # noqa: PLC0415
        LDAPBindException,
    )
    from badldap.commons.factory import (  # noqa: PLC0415
        LDAPConnectionFactory,
    )

    cat = ConstraintCategory.LDAP_STARTTLS_AVAILABLE
    started = _now_ms()
    handshake_timeout = min(timeout, 5.0)

    # Anonymous, plain LDAP/389 URL. ``MSLDAPTarget.from_url`` defaults to
    # port 389 + plain (non-TLS) transport for the bare ``ldap://`` scheme.
    url = f"ldap://{dc_ip}"

    print_info_debug(
        f"[posture_probe] U4 StartTLS opening plain LDAP/389 to {dc_ip} "
        f"(timeout={handshake_timeout}s, anonymous, no bind, "
        "ssl_verify disabled per vendor target default)"
    )

    raw_conn = None
    try:
        factory = LDAPConnectionFactory.from_url(url)
        raw_conn = factory.get_connection()
        # StartTLS (RFC 2830) does not enforce channel binding, and we never
        # bind — keep both off so the probe exercises the bare upgrade path.
        if hasattr(raw_conn, "_disable_signing"):
            raw_conn._disable_signing = True
        if hasattr(raw_conn, "_disable_channel_binding"):
            raw_conn._disable_channel_binding = True

        async def _connect_and_starttls() -> tuple[bool, Optional[BaseException]]:
            ok, err = await raw_conn.connect()
            if not ok:
                # Surface the connect failure as the StartTLS outcome — a
                # dead TCP/389 means StartTLS is unreachable. ``connect()``
                # returns ``(False, err)`` rather than raising for some
                # transport failures; re-raise so the classifier below sees
                # the same exception type a raising path would produce.
                raise err or ConnectionRefusedError(
                    f"plain LDAP/389 connect to {dc_ip} returned ok=False"
                )
            return await raw_conn.starttls()

        starttls_ok, starttls_err = await asyncio.wait_for(
            _connect_and_starttls(), timeout=handshake_timeout
        )

        if starttls_ok and starttls_err is None:
            # extendedReq accepted AND TLS handshake completed.
            print_info_debug(
                f"[posture_probe] U4 StartTLS OK on {dc_ip}:389 in "
                f"{_now_ms() - started:.0f}ms — RFC 2830 upgrade succeeded"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_OK",
                message="StartTLS extendedReq accepted and TLS handshake succeeded on LDAP/389",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_OK",
                message="StartTLS extendedReq accepted and TLS handshake succeeded on LDAP/389",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        # ``starttls()`` returns ``(False, err)`` for both a refused result
        # code (``LDAPBindException``) and a TLS-layer failure (``ssl.SSLError``
        # caught inside the vendor primitive and returned as ``err``). Branch
        # on the error type to discriminate REFUSED vs TLS_BROKEN.
        if isinstance(starttls_err, _ssl.SSLError):
            telemetry.capture_exception(starttls_err)
            print_info_debug(
                f"[posture_probe] U4 StartTLS ssl.SSLError on {dc_ip}:389 after "
                f"{_now_ms() - started:.0f}ms — extendedReq accepted but TLS "
                f"handshake failed: {type(starttls_err).__name__}: {starttls_err}"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_TLS_BROKEN",
                message=(
                    "StartTLS accepted but TLS handshake failed "
                    f"({type(starttls_err).__name__}) — no usable DC cert on 389"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_TLS_BROKEN",
                message=(
                    "StartTLS accepted but TLS handshake failed "
                    f"({type(starttls_err).__name__}) — no usable DC cert on 389"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        if isinstance(starttls_err, LDAPBindException):
            telemetry.capture_exception(starttls_err)
            print_info_debug(
                f"[posture_probe] U4 StartTLS refused on {dc_ip}:389 after "
                f"{_now_ms() - started:.0f}ms — DC returned non-success result "
                f"code: {starttls_err}"
            )
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_REFUSED",
                message="DC refused StartTLS extendedReq (unwillingToPerform) — StartTLS not offered",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STARTTLS_REFUSED",
                message="DC refused StartTLS extendedReq (unwillingToPerform) — StartTLS not offered",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )

        # ``starttls()`` returned a non-success without a recognised error
        # type. We could not characterise the DC's answer — treat as
        # inferred-by-absence: UNKNOWN/LOW, NO emit, cache stays clean.
        if starttls_err is not None:
            telemetry.capture_exception(starttls_err)
        print_info_debug(
            f"[posture_probe] U4 StartTLS unclassifiable result on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — "
            f"err={type(starttls_err).__name__ if starttls_err else None}. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message="StartTLS returned an unclassifiable result — re-probe next time",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except asyncio.TimeoutError as exc:
        # A timeout is NOT an observation about StartTLS availability — it's
        # an observation about OUR clock. The event loop may be saturated by
        # concurrent probes, or the DC transiently busy. Caching DISABLED HIGH
        # here is the exact bug that poisoned ``LDAPS_AVAILABLE`` for 24h after
        # a single bad run (CLAUDE.md § Posture caching policy, Invariant 2).
        # Correct answer: UNKNOWN LOW + NO sink emit — the cache stays
        # untouched and the next operation re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS asyncio.TimeoutError on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms (budget={handshake_timeout}s) — "
            "did NOT complete the StartTLS upgrade. NOT persisting to posture "
            "(cache-only-observations policy)."
        )
        # NOTE: no ``_emit`` here — timeout does not persist to posture.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message=f"StartTLS upgrade hung past {handshake_timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except ConnectionRefusedError as exc:
        # Explicit TCP RST from the DC — port 389 is closed. This IS an
        # observation; cache DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS ConnectionRefused on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message="TCP/389 returned RST — plain LDAP port closed, StartTLS unreachable",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message="TCP/389 returned RST — plain LDAP port closed, StartTLS unreachable",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except _ssl.SSLError as exc:
        # TLS layer failed during the wrap (if it escaped the vendor
        # primitive rather than being returned as ``err``). extendedReq was
        # accepted, the cert is broken/absent — OBSERVED DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS ssl.SSLError (raised) on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc}"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_TLS_BROKEN",
            message=f"StartTLS accepted but TLS handshake failed: {type(exc).__name__}",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_TLS_BROKEN",
            message=f"StartTLS accepted but TLS handshake failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except OSError as exc:
        # Generic OSError covers ``ENETUNREACH`` / ``EHOSTUNREACH`` — the
        # kernel telling us the DC is not routable. The network layer
        # answered, so this IS an observation; cache DISABLED HIGH.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS OSError on {dc_ip}:389 after "
            f"{_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc} "
            f"(errno={getattr(exc, 'errno', None)!r})"
        )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message=f"TCP/389 network unreachable ({type(exc).__name__}) — StartTLS unreachable",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STARTTLS_PORT_CLOSED",
            message=f"TCP/389 network unreachable ({type(exc).__name__}) — StartTLS unreachable",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except Exception as exc:  # noqa: BLE001
        # Anything we cannot classify is inferred-by-absence: it tells us
        # about OUR state, not the DC's. UNKNOWN/LOW, NO emit — cache clean,
        # next caller re-probes.
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture_probe] U4 StartTLS unclassifiable exception on {dc_ip}:389 "
            f"after {_now_ms() - started:.0f}ms — {type(exc).__name__}: {exc}. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_STARTTLS_TIMEOUT",
            message=f"StartTLS probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    finally:
        # Best-effort close — never let a raw socket leak into the event loop
        # after the probe answers.
        if raw_conn is not None:
            try:
                disc = getattr(raw_conn, "disconnect", None)
                if disc is not None:
                    res = disc()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as close_exc:  # noqa: BLE001
                telemetry.capture_exception(close_exc)


# --------------------------------------------------------------------------- #
# Bogus-credential constants
#
# U2 (signing) and U3 (CBT) borrow NetExec's elegant insight: the DC
# evaluates **transport-policy** (signing requirement, CBT requirement)
# **before** it validates the supplied credential. So if we send a bind
# with deliberately invalid credentials, the DC's response code tells us
# which policy is in force:
#
#   * If the policy is REQUIRED, the bind fails on the policy check
#     with a transport-specific code (``strongerAuthRequired`` for
#     signing; ``SEC_E_BAD_BINDINGS`` for CBT) — the DC never gets to
#     evaluate the bad credential.
#   * If the policy is NOT required, the DC evaluates the credential
#     and rejects it with ``STATUS_LOGON_FAILURE`` (LDAP "data 52e").
#
# Either way the policy answer is HIGH confidence. No real credential
# is needed in either ``start_unauth`` or ``start_auth`` flows — these
# transport-policy questions belong in the unauth phase, full stop.
#
# OPSEC note: the bogus bind generates a ``4625`` audit event on the
# DC. NetExec produces the same event with every ``nxc ldap`` invocation,
# so this is industry-norm noise for an authorised engagement. Operators
# who need a quieter probe can opt out via ``ADSCAN_NO_POSTURE_PROBE=1``.
# --------------------------------------------------------------------------- #
_BOGUS_CRED_USER = " "
_BOGUS_CRED_PASSWORD = " "

# DC response signatures. Sourced from:
#   * ``vendor/badldap/badldap/protocol/messages.py`` (LDAP result codes)
#   * ``vendor/badldap/badldap/wintypes/winerror.py`` (Windows error codes)
#
# Matched defensively against the rendered exception chain in both their
# code-name and raw-hex forms — badldap's formatter normally prints the
# code name, but a code path that bypasses it would still surface the hex.
_LDAP_SIGNING_REQUIRED_SIGS = (
    "strongerauthrequired",
    "ldap_strong_auth_required",
    "error_ds_strong_auth_required",
    "0x00002028",
    "0x2028",
    "00002028",
)
_LDAP_CBT_REQUIRED_SIGS = (
    "sec_e_bad_bindings",
    "channel bindings were incorrect",
    "channel binding",
    "0x80090346",
    "80090346",
)
# ``STATUS_LOGON_FAILURE`` (Windows error ``0xC000006D``, NTLM "data 52e"
# in LDAP error text). Surfaces from badauth's NTLM client when the DC
# rejects the bogus credential — meaning the transport policy passed and
# the DC moved on to the credential check, i.e. the policy is NOT required.
_LDAP_LOGON_FAILURE_SIGS = (
    "status_logon_failure",
    "data 52e",
    "0xc000006d",
    "c000006d",
    "logon_failure",
    "invalidcredentials",
)


def _classify_ldap_policy_response(exc: BaseException) -> str:
    """Classify a bogus-cred LDAP bind exception against the DC.

    Returns one of:
      * ``"signing_required"`` — DC rejected with ``strongerAuthRequired``
        before credential check (policy: signing REQUIRED).
      * ``"cbt_required"`` — DC rejected with ``SEC_E_BAD_BINDINGS`` before
        credential check (policy: CBT REQUIRED).
      * ``"logon_failure"`` — DC accepted the transport but rejected the
        bogus credential (policy: NOT required for this bind type).
      * ``"unknown"`` — other failure (network, TLS, clock skew, ...).
    """
    text = _chain_text(exc)
    # Order matters: signing/CBT codes are checked first because the DC
    # short-circuits on policy violations BEFORE the credential check.
    # A ``strongerAuthRequired`` or ``bad_bindings`` always precedes any
    # ``logon_failure`` text in the same exception chain.
    if any(sig in text for sig in _LDAP_CBT_REQUIRED_SIGS):
        return "cbt_required"
    if any(sig in text for sig in _LDAP_SIGNING_REQUIRED_SIGS):
        return "signing_required"
    if any(sig in text for sig in _LDAP_LOGON_FAILURE_SIGS):
        return "logon_failure"
    return "unknown"


async def _probe_ldap_signing(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U2 — LDAP signing enforcement via a bogus-cred NTLM bind.

    Sends an NTLM LDAP bind on port 389 with deliberately invalid
    credentials (``user=" "``, ``password=" "``) and ``sign=False``. The
    DC validates signing policy **before** credentials, so:

      * Signing REQUIRED → ``strongerAuthRequired`` (LDAP result code 8 /
        ``ERROR_DS_STRONG_AUTH_REQUIRED`` = 0x00002028) — HIGH confidence.
      * Signing NOT REQUIRED → ``STATUS_LOGON_FAILURE`` (NTLM data 52e /
        ``0xC000006D``) because the DC accepted the unsigned bind and
        then rejected the bogus credential — HIGH confidence.

    Either response is conclusive. No anonymous-bind inconclusive path
    exists in this design.

    Why bogus creds instead of an anonymous bind: an anonymous LDAP bind
    on port 389 may succeed (DC accepts it) **even when signing is
    enforced for authenticated principals**, because the GPO can be
    configured to apply only to authenticated binds. The bogus-cred NTLM
    bind always exercises the authenticated path, so the policy answer
    is unambiguous.

    Operational note: emits a ``4625`` audit event on the DC. See
    ``_BOGUS_CRED_USER`` block comment for OPSEC discussion.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cat = ConstraintCategory.LDAP_SIGNING
    started = _now_ms()
    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=False,
        use_kerberos=False,
        username=_BOGUS_CRED_USER,
        password=_BOGUS_CRED_PASSWORD,
        # Explicit OFF — the probe's purpose is to ask the DC whether it
        # enforces signing. A planner that already learned signing=REQUIRED
        # from a previous run might have flipped this on; that would mask
        # the result.
        sign=False,
        # The probe INTENTIONALLY elicits ``strongerAuthRequired``. The
        # transport's self-heal would silently retry with ``sign=True``
        # and "succeed", falsifying the answer. See ``disable_self_heal``.
        disable_self_heal=True,
    )

    print_info_debug(
        f"[posture_probe] U2 signing opening LDAP/389 bogus-cred bind to {dc_ip}:389 "
        f"(timeout={timeout}s, sign=False, disable_self_heal=True)"
    )
    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg), timeout=timeout
        )
        # The bogus credential SHOULD have been rejected — if we got a
        # bound connection something is off (perhaps a DC that accepts
        # any credential? extremely unusual). Treat as unknown rather
        # than guessing.
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_BOGUS_CRED_BIND_UNEXPECTEDLY_OK",
            message="Bogus-credential bind unexpectedly succeeded — DC config is unusual",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        # elapsed-vs-budget delta is the key diagnostic: elapsed ~ budget
        # → genuine latency/slow DC; elapsed << budget → the coroutine was
        # starved (event-loop contention), which would argue for serializing
        # the bogus-cred binds rather than running them in the same wave.
        print_info_debug(
            f"[posture_probe] U2 signing timed out after {timeout}s on {dc_ip}:389 "
            f"— elapsed {_now_ms() - started:.0f}ms. "
            "NOT persisting to posture (cache-only-observations policy)."
        )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"LDAP signing probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        verdict = _classify_ldap_policy_response(exc)
        print_info_debug(
            f"[posture_probe] U2 signing -> {verdict} on {dc_ip}:389 "
            f"in {_now_ms() - started:.0f}ms"
        )
        if verdict == "signing_required":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.REQUIRED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_STRONG_AUTH_REQUIRED",
                message="DC requires LDAP signing",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        if verdict == "logon_failure":
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_BIND_NO_SIGN_OK",
                message=(
                    "Unsigned LDAP bind accepted (credential rejected at credential check) — "
                    "signing not required"
                ),
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAP_BIND_NO_SIGN_OK",
                message=(
                    "Unsigned LDAP bind accepted (credential rejected at credential check) — "
                    "signing not required"
                ),
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"LDAP signing probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_ldaps_channel_binding(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
    posture: Optional[DomainPosture] = None,
) -> ProbeResult:
    """Probe U3 — LDAPS channel binding requirement via a bogus-cred NTLM bind.

    Two-step probe modelled on NetExec's ``check_ldaps_cbt`` (see
    ``reference/NetExec/nxc/protocols/ldap.py``):

      1. **No-CBT bind**. NTLM bind on LDAPS (port 636) with the CBT
         field omitted and bogus credentials. The DC's response:
           * ``SEC_E_BAD_BINDINGS`` (0x80090346) → CBT enforced for ALL
             binds, regardless of credential validity. Emit
             ``REQUIRED`` HIGH and return.
           * ``STATUS_LOGON_FAILURE`` → the DC accepted the no-CBT bind
             and then rejected the bogus credential. CBT is **not**
             enforced for absent CBT — but the policy could still be
             "When Supported" (enforce CBT only when a CBT token IS
             supplied). Go to step 2 to disambiguate.

      2. **Wrong-CBT bind**. Same NTLM bind, but this time with a
         deliberately invalid CBT token populated (via
         ``null_channel_binding`` → wired through ``_null_channel_binding``
         in badldap connection). DC response:
           * ``SEC_E_BAD_BINDINGS`` → DC validates CBT when present →
             policy is "When Supported". Emit ``REQUIRED`` HIGH (treated
             as required because any client that sends CBT must send a
             valid one).
           * ``STATUS_LOGON_FAILURE`` → DC ignored the wrong CBT
             entirely → policy is "Never". Emit ``DISABLED`` HIGH.

    Skipped when LDAPS is known to be unavailable — CBT lives only on
    TLS, so there's nothing to bind to.

    Operational note: each bogus bind generates a ``4625`` audit event
    on the DC. See ``_BOGUS_CRED_USER`` block comment for OPSEC discussion.
    """
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
        is_ldaps_transport_failure,
    )

    cat = ConstraintCategory.LDAP_CHANNEL_BINDING
    started = _now_ms()

    # Early skip when LDAPS is known to be unavailable.
    if posture is not None:
        ldaps = posture.get(ConstraintCategory.LDAPS_AVAILABLE)
        if (
            ldaps is not None
            and ldaps.state == TriState.DISABLED
            and ldaps.confidence == SignalConfidence.HIGH
            and not ldaps.is_stale
        ):
            return _make_skipped(
                cat,
                reason=(
                    "Skipped: LDAPS not available on this DC — channel "
                    "binding cannot exist without a TLS channel"
                ),
            )

    def _make_cfg(*, null_cbt: bool) -> "ADscanLDAPConfig":
        return ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=False,
            username=_BOGUS_CRED_USER,
            password=_BOGUS_CRED_PASSWORD,
            # Default: no CBT in the bind. When ``null_cbt`` is True the
            # CBT field IS populated, but with garbage — used in step 2
            # to discriminate "When Supported" from "Never".
            channel_binding=False,
            null_channel_binding=null_cbt,
            disable_self_heal=True,
        )

    async def _attempt(
        cfg: "ADscanLDAPConfig", *, step: int
    ) -> tuple[Optional[Exception], bool]:
        """Run a single bind; return (exception_or_None, opened_ok)."""
        attempt_started = _now_ms()
        print_info_debug(
            f"[posture_probe] U3 CBT opening LDAPS bogus-cred bind to {dc_ip}:636 "
            f"(timeout={timeout}s, step={step}, "
            f"null_cbt={getattr(cfg, 'null_channel_binding', False)})"
        )
        try:
            conn, _ = await asyncio.wait_for(
                async_connect_with_ldap_fallback(cfg), timeout=timeout
            )
            try:
                disc = getattr(conn, "disconnect", None)
                if disc is not None:
                    res = disc()
                    if asyncio.iscoroutine(res):
                        await res
            except Exception as disc_exc:  # noqa: BLE001
                telemetry.capture_exception(disc_exc)
            return None, True
        except asyncio.TimeoutError as exc:
            # elapsed-vs-budget delta is the key diagnostic: elapsed ~ budget
            # → genuine latency/slow DC; elapsed << budget → the coroutine was
            # starved (event-loop contention with U2), which would argue for
            # serializing the two bogus-cred binds rather than running them in
            # the same wave.
            print_info_debug(
                f"[posture_probe] U3 CBT timed out after {timeout}s (step {step}) "
                f"on {dc_ip}:636 — elapsed {_now_ms() - attempt_started:.0f}ms"
            )
            return exc, False
        except Exception as exc:  # noqa: BLE001
            return exc, False

    # ---------------- Step 1 — no-CBT bind ----------------
    exc, opened = await _attempt(_make_cfg(null_cbt=False), step=1)
    if opened:
        # Bogus credential accepted — unusual but treat as unknown.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_BOGUS_CRED_BIND_UNEXPECTEDLY_OK",
            message="Bogus-credential LDAPS bind unexpectedly succeeded — DC config is unusual",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    assert exc is not None
    telemetry.capture_exception(exc)
    if isinstance(exc, asyncio.TimeoutError):
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"CBT probe timed out after {timeout}s (step 1)",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    if is_ldaps_transport_failure(exc):
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAPS_UNAVAILABLE",
            message="LDAPS unreachable; CBT requirement undetermined",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    verdict = _classify_ldap_policy_response(exc)
    print_info_debug(
        f"[posture_probe] U3 CBT step 1 -> {verdict} on {dc_ip}:636 "
        f"in {_now_ms() - started:.0f}ms"
    )
    if verdict == "cbt_required":
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS",
            message="DC rejected LDAPS bind without CBT (SEC_E_BAD_BINDINGS)",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_REJECTED_BAD_BINDINGS",
            message="DC rejected LDAPS bind without CBT (SEC_E_BAD_BINDINGS)",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    if verdict != "logon_failure":
        # Some other failure — cannot classify CBT requirement.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"CBT probe step 1 failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )

    # ---------------- Step 2 — wrong-CBT bind to disambiguate ----------------
    # Step 1 returned STATUS_LOGON_FAILURE, meaning the DC accepted the
    # no-CBT bind. Now try with a deliberately wrong CBT token: if the
    # DC validates CBT when present, this fails with SEC_E_BAD_BINDINGS
    # ("When Supported"); if the DC ignores CBT entirely, it falls back
    # to credential validation and returns STATUS_LOGON_FAILURE ("Never").
    exc2, opened2 = await _attempt(_make_cfg(null_cbt=True), step=2)
    if opened2:
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_BOGUS_CRED_BIND_UNEXPECTEDLY_OK",
            message="Bogus-credential LDAPS bind unexpectedly succeeded (step 2)",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    assert exc2 is not None
    telemetry.capture_exception(exc2)
    verdict2 = _classify_ldap_policy_response(exc2)
    print_info_debug(
        f"[posture_probe] U3 CBT step 2 -> {verdict2} on {dc_ip}:636 "
        f"in {_now_ms() - started:.0f}ms"
    )
    if verdict2 == "cbt_required":
        # DC validates CBT when present → "When Supported" policy. Treat
        # as REQUIRED because any client that sends CBT MUST send a valid
        # one — and any well-behaved client (badldap, impacket, native
        # Windows) sends CBT on LDAPS.
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_WHEN_SUPPORTED",
            message=(
                "DC accepts no-CBT bind but rejects wrong-CBT bind (When Supported policy)"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_WHEN_SUPPORTED",
            message=(
                "DC accepts no-CBT bind but rejects wrong-CBT bind (When Supported policy)"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    if verdict2 == "logon_failure":
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CBT_NOT_ENFORCED",
            message=(
                "DC ignored both missing and wrong CBT tokens — channel binding not enforced"
            ),
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    return ProbeResult(
        category=cat,
        state=TriState.UNKNOWN,
        confidence=SignalConfidence.LOW,
        signal_code="PROBE_FAILED",
        message=f"CBT probe step 2 failed: {type(exc2).__name__}",
        duration_ms=_now_ms() - started,
        succeeded=False,
    )


# --------------------------------------------------------------------------- #
# Auth probes
# --------------------------------------------------------------------------- #


async def _probe_kerberos_rc4(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    posture: Optional[DomainPosture],
    force: bool,
    timeout: float,
) -> ProbeResult:
    """Probe A1 — explicit etype=23 AS-REQ; emits RC4 + AES_ONLY signals."""
    from adscan_internal.services.kerberos_transport import (
        KerberosConfig,
        KerberosEtypeError,
        get_tgt,
    )

    cat = ConstraintCategory.KERBEROS_RC4
    aes_only_cat = ConstraintCategory.KERBEROS_AES_ONLY
    started = _now_ms()
    cfg = KerberosConfig(
        domain=domain,
        kdc_ip=dc_ip,
        username=creds.username,
        password=creds.password,
        etypes=[23],
        # Probe wants the raw KDC_ERR_ETYPE_NOTSUPP to propagate so it
        # can emit ``KERBEROS_RC4=DISABLED + AES_ONLY=ENABLED``.
        # Without this flag, get_tgt's self-heal silently retries with
        # AES, the TGT succeeds, and the probe falsely concludes that
        # RC4 is supported.
        disable_self_heal=True,
    )

    def _emit_aes_only(state: TriState, signal_code: str, message: str) -> None:
        if not force and posture is not None:
            existing = posture.get(aes_only_cat)
            if (
                existing.state != TriState.UNKNOWN
                and existing.confidence == SignalConfidence.HIGH
                and not existing.is_stale
            ):
                return
        _emit(
            sink,
            domain=domain,
            category=aes_only_cat,
            state=state,
            confidence=SignalConfidence.HIGH,
            signal_code=signal_code,
            message=message,
            protocol="kerberos",
        )

    try:
        await asyncio.wait_for(get_tgt(cfg), timeout=timeout)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="RC4_TGT_OK",
            message="KDC issued RC4 TGT",
            protocol="kerberos",
        )
        _emit_aes_only(
            TriState.DISABLED,
            "RC4_TGT_OK",
            "KDC issued RC4 TGT — AES-only is not enforced",
        )
        return ProbeResult(
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="RC4_TGT_OK",
            message="KDC issued RC4 TGT",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except KerberosEtypeError as exc:
        telemetry.capture_exception(exc)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="KDC_ERR_ETYPE_NOTSUPP",
            message="KDC rejected RC4 — domain enforces AES-only Kerberos",
            protocol="kerberos",
        )
        _emit_aes_only(
            TriState.ENABLED,
            "KDC_ERR_ETYPE_NOTSUPP",
            "AES-only Kerberos enforced by KDC",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="KDC_ERR_ETYPE_NOTSUPP",
            message="KDC rejected RC4 — domain enforces AES-only Kerberos",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Kerberos RC4 probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Kerberos RC4 probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_kerberos_etype(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe A2 — drives the existing ETYPE-INFO2 salt probe and reports outcome."""
    from adscan_internal.services.kerberos_transport import (
        KerberosConfig,
        _probe_and_set_etype_info2_salt,
    )

    cat = ConstraintCategory.KERBEROS_ETYPE_PROBE
    started = _now_ms()
    cfg = KerberosConfig(
        domain=domain,
        kdc_ip=dc_ip,
        username=creds.username,
        password=creds.password,
        disable_self_heal=True,
    )
    try:
        from kerbad.common.factory import KerberosClientFactory  # noqa: PLC0415

        # Re-use the same URL builder the transport uses.
        from adscan_internal.services.kerberos_transport import (
            _build_kerberos_url,
        )

        url = _build_kerberos_url(cfg, use_auth_kdc=True)
        cu = KerberosClientFactory.from_url(url)
        client = cu.get_client()

        nondefault = await asyncio.wait_for(
            _probe_and_set_etype_info2_salt(client, cfg), timeout=timeout
        )
        if nondefault:
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="ETYPE_INFO2_NONDEFAULT_SALT",
                message="KDC advertises non-default AES salt",
                protocol="kerberos",
            )
            return ProbeResult(
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="ETYPE_INFO2_NONDEFAULT_SALT",
                message="KDC advertises non-default AES salt",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="STANDARD_SALT_OK",
            message="Standard Kerberos salt",
            protocol="kerberos",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="STANDARD_SALT_OK",
            message="Standard Kerberos salt",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"Etype probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Etype probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_ntlm_authentication(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe A3 — NTLM bind via plain LDAP to detect NTLM enforcement state."""
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cat = ConstraintCategory.NTLM_AUTHENTICATION
    started = _now_ms()
    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=False,
        use_kerberos=False,
        username=creds.username,
        password=creds.password,
        # Wire NT hash via the password slot when the config supports the
        # standard "NT hash as password" convention used by badldap's
        # ldap+ntlm-nt scheme. ``ADscanLDAPConfig`` autodetects via
        # ``_is_nt_hash`` inside ``_build_ldap_connection_url``.
        # Probe needs the raw NTLM rejection to surface so it can emit
        # ``NTLM_AUTHENTICATION=DISABLED``. Without this flag, the
        # transport's signing self-heal could retry with sign=True and
        # the NTLM bind would succeed, falsifying the result.
        disable_self_heal=True,
    )
    if creds.password is None and creds.nt_hash is not None:
        cfg.password = creds.nt_hash

    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg), timeout=timeout
        )
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="NTLM_BIND_OK",
            message="NTLM bind via LDAP succeeded",
            protocol="ldap",
        )
        return ProbeResult(
            category=cat,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="NTLM_BIND_OK",
            message="NTLM bind via LDAP succeeded",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"NTLM probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        text = _chain_text(exc)
        if "invalidcredentials" in text and "sec_e_logon_denied" in text:
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="NTLM_REJECTED_VIA_LDAP",
                message="DC rejected NTLM bind with SEC_E_LOGON_DENIED",
                protocol="ldap",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="NTLM_REJECTED_VIA_LDAP",
                message="DC rejected NTLM bind with SEC_E_LOGON_DENIED",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"NTLM probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_smb_signing(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe A4 — SMB session-setup; reads ``signing_required`` after login."""
    from adscan_internal.services.smb_transport import SMBConfig, smb_machine_for

    cat = ConstraintCategory.SMB_SIGNING
    started = _now_ms()
    use_kerberos = (
        creds.password is None
        and creds.nt_hash is None
        and creds.ccache_path is not None
    )
    cfg = SMBConfig(
        target_ip=dc_ip,
        domain=domain,
        username=creds.username,
        password=creds.password,
        nt_hash=creds.nt_hash,
        ccache_path=creds.ccache_path,
        kdc_ip=dc_ip,
        use_kerberos=use_kerberos,
        # Sink is wired so smb_transport's success/failure classifiers
        # emit SMB_SIGNING / NTLM_AUTHENTICATION signals via the same
        # sink we hand the caller.
        posture_sink=sink,
        # Probe wants the raw SMBSigningRequiredError to surface for
        # ``SMB_SIGNING=REQUIRED``. Without this flag, smb_machine_for's
        # self-heal silently retries with sign=True and the negotiate
        # succeeds — the probe then sees signing_required=False on the
        # connection (because we ARE signing now) and falsely concludes
        # signing is not required.
        disable_self_heal=True,
    )

    async def _run() -> ProbeResult:
        async with smb_machine_for(cfg) as _machine:
            # smb_transport._emit_smb_success_posture has already emitted
            # SMB_SIGNING REQUIRED HIGH when the connection negotiated it.
            # Mirror that into a ProbeResult by best-effort reading the
            # connection's signing_required flag through the machine.
            connection = getattr(_machine, "connection", None)
            signing = False
            if connection is not None:
                try:
                    signing = bool(getattr(connection, "signing_required", False))
                except Exception as attr_exc:  # noqa: BLE001
                    telemetry.capture_exception(attr_exc)
            if signing:
                _emit(
                    sink,
                    domain=domain,
                    category=cat,
                    state=TriState.REQUIRED,
                    confidence=SignalConfidence.HIGH,
                    signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                    message="DC negotiated SMB signing as required",
                    protocol="smb",
                )
                return ProbeResult(
                    category=cat,
                    state=TriState.REQUIRED,
                    confidence=SignalConfidence.HIGH,
                    signal_code="SMB_SIGNING_NEGOTIATED_REQUIRED",
                    message="DC negotiated SMB signing as required",
                    duration_ms=_now_ms() - started,
                    succeeded=True,
                )
            return ProbeResult(
                category=cat,
                state=TriState.UNKNOWN,
                confidence=SignalConfidence.LOW,
                signal_code="SMB_SIGNING_NOT_NEGOTIATED",
                message="SMB negotiated without required signing — inconclusive",
                duration_ms=_now_ms() - started,
                succeeded=False,
            )

    try:
        return await asyncio.wait_for(_run(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_TIMEOUT",
            message=f"SMB signing probe timed out after {timeout}s",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"SMB signing probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


# --------------------------------------------------------------------------- #
# Orchestration helpers
# --------------------------------------------------------------------------- #


async def _run_with_lifecycle(
    *,
    category: ConstraintCategory,
    runner: Callable[[], "asyncio.Future[ProbeResult] | Any"],
    on_progress: Optional[ProbeProgressCallback],
    posture: Optional[DomainPosture],
    force: bool,
) -> ProbeResult:
    """Apply skip logic, fire ``on_progress`` start/end, and run ``runner``."""
    skip, skipped_result = _should_skip(posture, category, force)
    if skip and skipped_result is not None:
        _safe_progress(on_progress, category, None)
        _safe_progress(on_progress, category, skipped_result)
        return skipped_result

    _safe_progress(on_progress, category, None)
    try:
        result = await runner()
    except Exception as exc:  # noqa: BLE001
        # Defensive net — every individual probe already wraps its failure
        # paths, but if something unexpected escapes, surface it as a failed
        # ProbeResult rather than tearing down the orchestrator.
        telemetry.capture_exception(exc)
        result = ProbeResult(
            category=category,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"Probe crashed: {type(exc).__name__}: {exc}",
            duration_ms=0.0,
            succeeded=False,
        )
    _safe_progress(on_progress, category, result)
    return result


def _make_skipped(
    category: ConstraintCategory,
    *,
    reason: str,
) -> ProbeResult:
    """Build a synthetic skipped ``ProbeResult`` for credential-gated probes."""
    return ProbeResult(
        category=category,
        state=TriState.UNKNOWN,
        confidence=SignalConfidence.LOW,
        signal_code="SKIPPED_NO_CREDENTIAL",
        message=reason,
        duration_ms=0.0,
        succeeded=True,
        skipped=True,
    )


# --------------------------------------------------------------------------- #
# Public entry points
# --------------------------------------------------------------------------- #


async def probe_unauth(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    on_progress: Optional[ProbeProgressCallback] = None,
    timeout_per_probe: float = 5.0,
    force: bool = False,
    posture: Optional[DomainPosture] = None,
) -> list[ProbeResult]:
    """Run the unauth probe set against the DC.

    Probes:
        U1 — ``LDAPS_AVAILABLE`` (anonymous LDAPS bind).
        U2 — ``LDAP_SIGNING`` (bogus-cred NTLM bind on port 389, see
             :func:`_probe_ldap_signing`).
        U3 — ``LDAP_CHANNEL_BINDING`` (bogus-cred NTLM bind on LDAPS,
             two steps to disambiguate Required / When-Supported / Never;
             see :func:`_probe_ldaps_channel_binding`).
        U4 — ``LDAP_STARTTLS_AVAILABLE`` (StartTLS upgrade on plain
             LDAP/389, see :func:`_probe_ldap_starttls_available`).

    Concurrency layout — **fully sequential**: U1 → U4 → U2 → U3. No
    ``asyncio.gather``, no overlapping background tasks. Each probe runs to
    completion before the next one starts.

    Why fully sequential and not "fast handshakes in parallel, binds
    serialized": per-step instrumentation against a real DC (2026-05-29)
    proved that the vendor TLS/NTLM operations do NOT yield the event loop
    cleanly. The low-level network primitives are fast in isolation —
    ``async_connect_with_ldap_fallback`` completes in ~122ms and
    ``conn.connect()`` in 9-52ms — yet each probe's function-level
    wall-clock was ~3.7-8.7s whenever probes ran concurrently. The gap is
    NOT in ADscan code: it is event-loop starvation during the concurrent
    wave. The vendor TLS handshake and NTLM/SPNEGO negotiation block the
    loop long enough that the "parallel" probes serialize de-facto AND
    inflate each other's wall-clock past their ``asyncio.wait_for`` budgets,
    tripping spurious ``PROBE_TIMEOUT`` / ``LDAPS_HANDSHAKE_TIMEOUT`` even
    when LDAPS/StartTLS is perfectly reachable. The decisive proof: the
    sequential post-wave reads (password policy) ran in 17-152ms — fast
    when alone. So running the probes concurrently is SLOWER (and
    timeout-prone) than running them one at a time, where each probe
    measures its true ~50-150ms of real latency.

    Ordering preserves the one data dependency: U1 (``LDAPS_AVAILABLE``)
    must complete before U3 (``LDAP_CHANNEL_BINDING``), because U3's
    self-skip consults U1's verdict via ``posture_for_u3`` (CBT lives only
    on TLS — no point binding LDAPS when U1 already proved 636 is closed).
    Sequential ordering satisfies this naturally; ``posture_for_u3`` is
    still built from U1's finished result below.

    Deferred alternative (backlog): making the vendor SSL/NTLM operations
    non-blocking — e.g. running the blocking handshake/negotiation under
    ``loop.run_in_executor`` so they genuinely yield the loop — would let
    these probes run in true parallel and reclaim the wall-clock. That is a
    vendor-layer change with wider blast radius; until then, sequential is
    both faster (no contention inflation) and timeout-safe.

    Evolution of this layout (kept for the historical record): the earliest
    "all probes parallel" design wasted ~10s on DCs without LDAPS (U3 burned
    two 5s timeouts on a question U1 had already answered). Intermediate
    designs — "U1+U2 parallel, U3 after", then "U1+U4 parallel + U2 then
    U3 sequential" — each removed one race but left another (a spurious
    ``LDAPS_HANDSHAKE_TIMEOUT`` from the U1↔bind contention, or a U2↔U3
    overlap). Full sequentialisation removes every remaining race in one
    move; the cost (one probe's latency at a time, all at their true
    ~50-150ms) is lower than the concurrent design's contention-inflated
    wall-clock.

    Why these live in UNAUTH even though they exercise an NTLM bind:
    the bogus-credential technique (see ``_BOGUS_CRED_USER`` comment
    block) does not require a real principal — it only exercises the
    DC's transport-policy validation, which runs **before** credential
    validation. So the same code path produces an authoritative answer
    in ``start_unauth`` and ``start_auth``, no second pass required.

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP to probe.
        sink: Posture sink that receives every emitted signal.
        on_progress: Optional callback fired twice per physical probe
            (``(cat, None)`` start, ``(cat, result)`` finish).
        timeout_per_probe: Per-probe wall-clock cap, seconds.
        force: When ``True``, run every probe even if the posture already
            records a HIGH-confidence non-stale value for its category.
        posture: Optional pre-loaded ``DomainPosture`` used for skip logic.

    Returns:
        One ``ProbeResult`` per physical probe, in the order
        ``[U1, U2, U3, U4]``.
    """

    async def _u1() -> ProbeResult:
        return await _probe_ldaps_available(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    async def _u2() -> ProbeResult:
        return await _probe_ldap_signing(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    async def _u4() -> ProbeResult:
        return await _probe_ldap_starttls_available(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    # ----------------- Fully sequential: U1 -> U4 -> U2 -> U3 ----------------- #
    # NO asyncio.gather, NO overlapping background tasks. Per-step
    # instrumentation against a real DC (2026-05-29) proved that running these
    # probes concurrently causes event-loop starvation: the vendor TLS/NTLM
    # operations do not yield the loop cleanly, so the "parallel" probes
    # serialize de-facto AND inflate each other's wall-clock to ~3.7-8.7s
    # (tripping spurious PROBE_TIMEOUT / LDAPS_HANDSHAKE_TIMEOUT) even though
    # each probe's real latency is only ~50-150ms in isolation. Running them
    # one at a time lets each measure its true latency under its own
    # wait_for budget. See the docstring "Concurrency layout" section for the
    # evidence and the deferred run_in_executor alternative.

    # U1 first — its LDAPS verdict gates U3's self-skip below.
    u1 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAPS_AVAILABLE,
        runner=_u1,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # U4 — StartTLS availability on port 389. Independent of U1's verdict.
    u4 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_STARTTLS_AVAILABLE,
        runner=_u4,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # Build a posture snapshot that includes U1's verdict so U3's self-skip
    # logic short-circuits when LDAPS is unavailable. The caller's ``posture``
    # argument is the BEFORE-probes snapshot; we layer U1's finished result on
    # top of it for the purpose of U3.
    posture_for_u3 = posture
    if u1.state == TriState.DISABLED and u1.confidence == SignalConfidence.HIGH:
        from adscan_internal.services.domain_posture import (
            ConstraintState as _CState,
            DomainPosture as _DP,
        )

        ldaps_state = _CState(
            category=ConstraintCategory.LDAPS_AVAILABLE,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
        )
        if posture_for_u3 is None:
            posture_for_u3 = _DP(
                domain=domain,
                constraints={ConstraintCategory.LDAPS_AVAILABLE: ldaps_state},
            )
        else:
            posture_for_u3 = _DP(
                domain=posture_for_u3.domain or domain,
                constraints={
                    **posture_for_u3.constraints,
                    ConstraintCategory.LDAPS_AVAILABLE: ldaps_state,
                },
                updated_at=posture_for_u3.updated_at,
                password_policy=posture_for_u3.password_policy,
            )

    async def _u3() -> ProbeResult:
        return await _probe_ldaps_channel_binding(
            domain=domain,
            dc_ip=dc_ip,
            sink=sink,
            timeout=timeout_per_probe,
            posture=posture_for_u3,
        )

    # U2 — bogus-cred unsigned NTLM bind on port 389.
    u2 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_SIGNING,
        runner=_u2,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )

    # U3 — bogus-cred NTLM bind on LDAPS/636 (uses posture_for_u3 from U1).
    u3 = await _run_with_lifecycle(
        category=ConstraintCategory.LDAP_CHANNEL_BINDING,
        runner=_u3,
        on_progress=on_progress,
        posture=posture_for_u3,
        force=force,
    )

    return [u1, u2, u3, u4]


async def probe_auth(
    *,
    domain: str,
    dc_ip: str,
    creds: ProbeCredentials,
    sink: PostureSink,
    on_progress: Optional[ProbeProgressCallback] = None,
    timeout_per_probe: float = 5.0,
    force: bool = False,
    posture: Optional[DomainPosture] = None,
) -> list[ProbeResult]:
    """Run the auth-mechanism probe set against the DC.

    The auth phase exists to characterise the **credential and Kerberos
    machinery**, nothing else. Properties of the DC that can be measured
    without credentials (LDAP signing requirement, LDAPS channel binding
    requirement) live in :func:`probe_unauth` so the same answer surfaces
    in ``start_unauth`` and ``start_auth``, and the AUTH phase stays
    purely about what authentication actually requires a credential.

    Probes (4 physical, 5 distinct posture signals):
        A1 — ``KERBEROS_RC4`` + ``KERBEROS_AES_ONLY`` (one explicit-etype AS-REQ).
        A2 — ``KERBEROS_ETYPE_PROBE``.
        A3 — ``NTLM_AUTHENTICATION``.
        A4 — ``SMB_SIGNING``.

    Concurrency: A1+A2 share the KDC and run sequentially within a
    Kerberos sub-group; A3 (NTLM) and A4 (SMB signing) are independent
    and run alongside. All three sub-flows converge via ``asyncio.gather``
    — no inter-phase dependencies, no sequential second phase.

    Probes whose required credential type is missing are skipped silently
    (``ProbeResult.skipped=True``, no sink call).

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP to probe.
        creds: Credential bundle.
        sink: Posture sink that receives every emitted signal.
        on_progress: Optional callback fired twice per physical probe.
        timeout_per_probe: Per-probe wall-clock cap, seconds.
        force: When ``True``, ignore existing fresh HIGH posture and re-run.
        posture: Optional pre-loaded ``DomainPosture`` used for skip logic.

    Returns:
        Four ``ProbeResult`` entries, one per physical probe, in the
        order ``[A1, A2, A3, A4]``.
    """
    has_password = creds.password is not None
    has_password_or_hash = has_password or (creds.nt_hash is not None)
    has_smb_credential = (
        has_password or (creds.nt_hash is not None) or (creds.ccache_path is not None)
    )

    async def _kerberos_group() -> tuple[ProbeResult, ProbeResult]:
        # A1
        if has_password:

            async def _a1() -> ProbeResult:
                return await _probe_kerberos_rc4(
                    domain=domain,
                    dc_ip=dc_ip,
                    creds=creds,
                    sink=sink,
                    posture=posture,
                    force=force,
                    timeout=timeout_per_probe,
                )

            a1 = await _run_with_lifecycle(
                category=ConstraintCategory.KERBEROS_RC4,
                runner=_a1,
                on_progress=on_progress,
                posture=posture,
                force=force,
            )
        else:
            skipped = _make_skipped(
                ConstraintCategory.KERBEROS_RC4,
                reason="Skipped: explicit-etype AS-REQ requires plaintext password",
            )
            _safe_progress(on_progress, ConstraintCategory.KERBEROS_RC4, None)
            _safe_progress(on_progress, ConstraintCategory.KERBEROS_RC4, skipped)
            a1 = skipped

        # A2 — sequential after A1.
        if has_password:

            async def _a2() -> ProbeResult:
                return await _probe_kerberos_etype(
                    domain=domain,
                    dc_ip=dc_ip,
                    creds=creds,
                    sink=sink,
                    timeout=timeout_per_probe,
                )

            a2 = await _run_with_lifecycle(
                category=ConstraintCategory.KERBEROS_ETYPE_PROBE,
                runner=_a2,
                on_progress=on_progress,
                posture=posture,
                force=force,
            )
        else:
            skipped = _make_skipped(
                ConstraintCategory.KERBEROS_ETYPE_PROBE,
                reason="Skipped: ETYPE-INFO2 probe requires plaintext password",
            )
            _safe_progress(on_progress, ConstraintCategory.KERBEROS_ETYPE_PROBE, None)
            _safe_progress(
                on_progress, ConstraintCategory.KERBEROS_ETYPE_PROBE, skipped
            )
            a2 = skipped
        return a1, a2

    async def _ntlm_probe() -> ProbeResult:
        if not has_password_or_hash:
            skipped = _make_skipped(
                ConstraintCategory.NTLM_AUTHENTICATION,
                reason="Skipped: NTLM probe requires password or NT hash",
            )
            _safe_progress(on_progress, ConstraintCategory.NTLM_AUTHENTICATION, None)
            _safe_progress(on_progress, ConstraintCategory.NTLM_AUTHENTICATION, skipped)
            return skipped

        async def _runner() -> ProbeResult:
            return await _probe_ntlm_authentication(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
            )

        return await _run_with_lifecycle(
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            runner=_runner,
            on_progress=on_progress,
            posture=posture,
            force=force,
        )

    async def _smb_probe() -> ProbeResult:
        if not has_smb_credential:
            skipped = _make_skipped(
                ConstraintCategory.SMB_SIGNING,
                reason="Skipped: SMB probe requires password, NT hash, or ccache",
            )
            _safe_progress(on_progress, ConstraintCategory.SMB_SIGNING, None)
            _safe_progress(on_progress, ConstraintCategory.SMB_SIGNING, skipped)
            return skipped

        async def _runner() -> ProbeResult:
            return await _probe_smb_signing(
                domain=domain,
                dc_ip=dc_ip,
                creds=creds,
                sink=sink,
                timeout=timeout_per_probe,
            )

        return await _run_with_lifecycle(
            category=ConstraintCategory.SMB_SIGNING,
            runner=_runner,
            on_progress=on_progress,
            posture=posture,
            force=force,
        )

    async def _independent_group() -> tuple[ProbeResult, ProbeResult]:
        a3, a4 = await asyncio.gather(_ntlm_probe(), _smb_probe())
        return a3, a4

    (a1, a2), (a3, a4) = await asyncio.gather(
        _kerberos_group(), _independent_group()
    )
    return [a1, a2, a3, a4]


# --------------------------------------------------------------------------- #
# Password policy probe
# --------------------------------------------------------------------------- #


def _filetime_to_days(ft: object) -> "Optional[int]":
    """Thin wrapper over the canonical AD-duration -> days converter.

    Kept as a private name for the existing call-sites in this module and the
    ``__all__`` export. The single source of truth lives in
    ``password_policy_compliance.ad_duration_to_days`` so the live policy API
    and the posture probe share one conversion.
    """
    from adscan_internal.services.password_policy_compliance import (  # noqa: PLC0415
        ad_duration_to_days,
    )

    return ad_duration_to_days(ft)


def _filetime_to_minutes(ft: object) -> "Optional[int]":
    """Thin wrapper over the canonical AD-duration -> minutes converter.

    Single source of truth: ``password_policy_compliance.ad_duration_to_minutes``.
    """
    from adscan_internal.services.password_policy_compliance import (  # noqa: PLC0415
        ad_duration_to_minutes,
    )

    return ad_duration_to_minutes(ft)


async def probe_password_policy(
    *,
    domain: str,
    dc_ip: str,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    timeout: float = 10.0,
) -> "Optional[Any]":
    """Read the default domain password policy from AD via LDAP.

    Queries the domain object (naming-context root) for:
      - ``minPwdLength``  (integer)
      - ``pwdProperties`` (bitmask; bit 0 = complexity required)
      - ``maxPwdAge``     (FILETIME negative integer; 0 = never expires)

    Uses ``async_connect_with_ldap_fallback`` per CLAUDE.md: LDAPS -> LDAP
    fallback is mandatory; never use ``LDAPConnectionFactory`` directly.

    Args:
        domain: Target Kerberos realm / AD domain (e.g. ``north.sevenkingdoms.local``).
        dc_ip: DC IP for the target domain.
        username: LDAP bind username. ``None`` for anonymous bind.
        password: Plaintext password. ``None`` for anonymous / hash bind.
        nt_hash: NT hash (hex string). Used when no plaintext password is
            available and Kerberos is not requested.
        ccache_path: Explicit ccache path for Kerberos ccache bind.
        use_kerberos: When ``True``, builds a Kerberos URL; Kerberos auth is
            skipped silently when no ccache / password is available.
        timeout: Per-attempt wall-clock cap, seconds.

    Returns:
        A :class:`~adscan_internal.services.domain_posture.PasswordPolicySnapshot`
        on success, or ``None`` when the query fails or the domain object is
        absent. The caller always falls back to conservative defaults — this
        probe never aborts a scan.
    """
    from datetime import datetime, timezone

    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.domain_posture import PasswordPolicySnapshot
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cfg = ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        use_ldaps=True,
        use_kerberos=use_kerberos,
        username=username,
        password=password,
        ccache_path=ccache_path,
    )
    if password is None and nt_hash is not None and not use_kerberos:
        # Pass NT hash via the password slot (badldap auto-detects via
        # _is_nt_hash in _build_ldap_connection_url).
        cfg.password = nt_hash

    try:
        conn, _ = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg), timeout=timeout
        )

        base_dn = cfg.domain_dn  # e.g. "DC=north,DC=sevenkingdoms,DC=local"
        results: list[dict] = []
        async for item, err in conn.pagedsearch(
            "(objectClass=domainDNS)",
            [
                "minPwdLength",
                "pwdProperties",
                "maxPwdAge",
                "lockoutThreshold",
                "lockoutObservationWindow",
                "lockoutDuration",
            ],
            tree=base_dn,
            search_scope=0,  # BASE
            raw=True,
        ):
            if err is not None:
                raise err
            results.append(item)

        # Best-effort disconnect.
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)

        if not results:
            print_info_debug(
                f"[posture] Password policy probe: no domainDNS entry returned "
                f"for base_dn={base_dn}"
            )
            return None

        attrs = results[0].get("attributes") or {}

        def _first_int(key: str, default: int) -> int:
            raw = attrs.get(key)
            if isinstance(raw, (list, tuple)):
                raw = raw[0] if raw else None
            try:
                return int(raw) if raw is not None else default
            except (ValueError, TypeError):
                return default

        min_pwd_len = _first_int("minPwdLength", 7)
        pwd_props = _first_int("pwdProperties", 0)
        require_complexity = bool(pwd_props & 0x01)  # DOMAIN_PASSWORD_COMPLEX

        raw_max_age = attrs.get("maxPwdAge")
        if isinstance(raw_max_age, (list, tuple)):
            raw_max_age = raw_max_age[0] if raw_max_age else None
        max_age_days = _filetime_to_days(raw_max_age)

        # Lockout attributes — same domain object, same round-trip. Critical for
        # spraying decisions (stale lockoutThreshold can lock real accounts).
        lockout_threshold = _first_int("lockoutThreshold", 0)

        raw_lockout_window = attrs.get("lockoutObservationWindow")
        if isinstance(raw_lockout_window, (list, tuple)):
            raw_lockout_window = raw_lockout_window[0] if raw_lockout_window else None
        lockout_window_minutes = _filetime_to_minutes(raw_lockout_window)

        raw_lockout_duration = attrs.get("lockoutDuration")
        if isinstance(raw_lockout_duration, (list, tuple)):
            raw_lockout_duration = raw_lockout_duration[0] if raw_lockout_duration else None
        lockout_duration_minutes = _filetime_to_minutes(raw_lockout_duration)

        snapshot = PasswordPolicySnapshot(
            min_length=min_pwd_len,
            require_complexity=require_complexity,
            max_age_days=max_age_days,
            source="ad_default_domain_policy",
            detected_at=datetime.now(timezone.utc),
            lockout_threshold=lockout_threshold,
            lockout_window_minutes=lockout_window_minutes,
            lockout_duration_minutes=lockout_duration_minutes,
        )
        print_info_debug(
            f"[posture] Password policy detected: domain={domain} "
            f"min_length={min_pwd_len} require_complexity={require_complexity} "
            f"max_age_days={max_age_days} lockout_threshold={lockout_threshold} "
            f"lockout_window_minutes={lockout_window_minutes}"
        )
        return snapshot

    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] Password policy probe timed out after {timeout}s "
            f"for domain={domain}"
        )
        return None
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] Password policy probe failed: "
            f"{type(exc).__name__}: {exc}"
        )
        return None


# Re-exported for typing convenience at call-sites.
__all__ = [
    "ProbeCredentials",
    "ProbePhase",
    "ProbeProgressCallback",
    "ProbeResult",
    "probe_auth",
    "probe_password_policy",
    "probe_unauth",
    "get_password_policy",
    "resolve_resultant_password_policy",
    "clear_resultant_policy_cache",
    "_filetime_to_days",
    "_filetime_to_minutes",
]


async def get_password_policy(
    *,
    domain: str,
    dc_ip: str,
    domains_data: "Optional[dict[str, Any]]" = None,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    timeout: float = 10.0,
    force_fresh: bool = False,
) -> "Optional[Any]":
    """Return the current :class:`PasswordPolicySnapshot` for ``domain``.

    Two modes:

    * ``force_fresh=False`` (default — used by scoring): consults the cached
      snapshot in ``domains_data`` first. When the cache is fresh (within
      :data:`domain_posture._PASSWORD_POLICY_TTL`, currently 60 s) it is
      returned without an LDAP round-trip. When stale or absent, a fresh
      probe is issued and the cache is updated.
    * ``force_fresh=True`` (REQUIRED for spraying): always issues a fresh
      LDAP query, ignoring any cached value. ``lockoutThreshold`` and
      ``lockoutObservationWindow`` can change reactively mid-engagement —
      a stale lockout value can lock real customer accounts. Spray code
      paths must use this mode before each batch.

    Args:
        domain: Target AD domain (e.g. ``ais.local``).
        dc_ip: Domain controller IP address for the LDAP connection.
        domains_data: Workspace ``domains_data`` mapping. When provided the
            cache is read and updated through it; when ``None``, behaves as
            if cache were always empty.
        username, password, nt_hash, ccache_path, use_kerberos: credentials
            forwarded to :func:`probe_password_policy`.
        timeout: LDAP probe timeout in seconds.
        force_fresh: When ``True`` bypasses the cache entirely. See above.

    Returns:
        A :class:`PasswordPolicySnapshot` or ``None`` when the probe fails.
    """
    # Deferred imports keep this module light; ``domain_posture`` carries the
    # snapshot dataclass and the persistence helpers.
    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
        get_posture,
        persist_password_policy,
    )

    if not force_fresh and domains_data is not None:
        cached = getattr(
            get_posture(domains_data, domain=domain),
            "password_policy",
            None,
        )
        if cached is not None and not cached.is_stale():
            return cached

    snapshot = await probe_password_policy(
        domain=domain,
        dc_ip=dc_ip,
        username=username,
        password=password,
        nt_hash=nt_hash,
        ccache_path=ccache_path,
        use_kerberos=use_kerberos,
        timeout=timeout,
    )
    if snapshot is not None and domains_data is not None:
        persist_password_policy(domains_data, domain=domain, snapshot=snapshot)
    return snapshot


# Touch ``IntelligenceFinding`` so static analyzers don't flag the import as
# unused — sinks may return it but the engine only forwards the call.
_ = IntelligenceFinding


# --------------------------------------------------------------------------- #
# Resultant password policy (live-first PSO-aware resolution)
# --------------------------------------------------------------------------- #

# In-session, in-memory cache for the per-user PSO leg keyed by
# ``(domain.lower(), target_user_or_None)``. PSO assignment does not change
# mid-engagement so a session-lifetime cache is safe; ``force_refresh=True``
# busts it. The domain-default leg reuses the ``domains_data``-backed cache via
# ``get_password_policy`` (see below) so this dict only memoises PSO results.
_RESULTANT_POLICY_CACHE: "dict[tuple[str, Optional[str]], Any]" = {}

# AD complexity rule: a password must contain characters from at least 3 of the
# 5 classes (lower, upper, digit, symbol, unicode) when complexity is enabled.
_AD_COMPLEXITY_REQUIRED_CLASSES = 3

# Strong safe default — aligns with the collector's weak-policy bar
# (_WEAK_PWD_POLICY_MIN_LENGTH = 14 in audit_analyzer.py).
_SAFE_DEFAULT_MIN_LENGTH = 14


def _resultant_cache_key(domain: str, target_user: "Optional[str]") -> "tuple[str, Optional[str]]":
    return (str(domain or "").lower(), str(target_user).lower() if target_user else None)


def _snapshot_to_resultant(snapshot: Any, *, source: str) -> Any:
    """Promote a ``PasswordPolicySnapshot`` to a ``ResultantPasswordPolicy``."""
    from datetime import datetime, timezone

    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    return ResultantPasswordPolicy(
        min_length=snapshot.min_length,
        require_complexity=snapshot.require_complexity,
        required_classes=(
            _AD_COMPLEXITY_REQUIRED_CLASSES if snapshot.require_complexity else 0
        ),
        source=source,
        detected_at=getattr(snapshot, "detected_at", datetime.now(timezone.utc)),
        max_pwd_age_days=getattr(snapshot, "max_age_days", None),
        lockout_threshold=getattr(snapshot, "lockout_threshold", 0),
        lockout_window_minutes=getattr(snapshot, "lockout_window_minutes", None),
        lockout_duration_minutes=getattr(snapshot, "lockout_duration_minutes", None),
    )


def _safe_default_policy() -> Any:
    """Return the strong safe default policy (source=``default_assumed``)."""
    from datetime import datetime, timezone

    from adscan_internal.services.domain_posture import ResultantPasswordPolicy

    return ResultantPasswordPolicy(
        min_length=_SAFE_DEFAULT_MIN_LENGTH,
        require_complexity=True,
        required_classes=_AD_COMPLEXITY_REQUIRED_CLASSES,
        source="default_assumed",
        detected_at=datetime.now(timezone.utc),
    )


def _coerce_bool_attr(raw: object) -> "Optional[bool]":
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    s = str(raw).strip().upper()
    if s in {"TRUE", "1"}:
        return True
    if s in {"FALSE", "0"}:
        return False
    return None


def _first_attr(attrs: dict, key: str) -> object:
    raw = attrs.get(key)
    if isinstance(raw, (list, tuple)):
        return raw[0] if raw else None
    return raw


def _values_attr(attrs: dict, key: str) -> "list[Any]":
    raw = attrs.get(key)
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return [raw]


async def _resolve_pso_policy(
    conn: Any,
    *,
    domain_dn: str,
    target_user: str,
    domain_default: Any,
    timeout: float,
) -> "Optional[Any]":
    """Resolve a PSO-derived ``ResultantPasswordPolicy`` for ``target_user``.

    Two-step, mirrors the offline ``_select_pso_for_user`` algorithm:

    1. Resolve ``sAMAccountName``/UPN -> user DN, then BASE-read
       ``msDS-ResultantPSO`` (authoritative DC-computed attribute). If present,
       BASE-read that PSO for its attributes.
    2. Fallback: SUBTREE the Password Settings Container, resolve the user's
       group DNs, and pick the covering PSO with the lowest precedence via the
       shared :func:`select_winning_pso_dn` helper.

    Returns ``None`` (caller uses the domain default) when no PSO governs the
    user or the reads fail.
    """
    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.password_policy_compliance import (
        ad_duration_to_days,
        ad_duration_to_minutes,
        select_winning_pso_dn,
    )

    # --- Step 0: resolve the user DN + group membership in one search. ---
    user_dn = ""
    resultant_pso_dn: "Optional[str]" = None
    group_dns: list[str] = []
    user_filter = (
        f"(sAMAccountName={target_user})"
        if "@" not in target_user
        else f"(userPrincipalName={target_user})"
    )
    try:
        async for item, err in conn.pagedsearch(
            user_filter,
            ["distinguishedName", "msDS-ResultantPSO", "memberOf"],
            tree=domain_dn,
            search_scope=2,  # SUBTREE
            raw=True,
        ):
            if err is not None:
                raise err
            attrs = item.get("attributes") or {}
            dn_val = _first_attr(attrs, "distinguishedName")
            if dn_val:
                user_dn = str(dn_val)
            rp = _first_attr(attrs, "msDS-ResultantPSO")
            if rp:
                resultant_pso_dn = str(rp)
            group_dns = [str(g) for g in _values_attr(attrs, "memberOf") if g]
            break  # first match wins
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] PSO user lookup failed for target_user: "
            f"{type(exc).__name__}: {exc}"
        )
        return None

    if not user_dn:
        print_info_debug("[posture] PSO resolution: target user not found")
        return None

    pso_attr_names = [
        "distinguishedName",
        "msDS-PasswordSettingsPrecedence",
        "msDS-MinimumPasswordLength",
        "msDS-MaximumPasswordAge",
        "msDS-MinimumPasswordAge",
        "msDS-LockoutThreshold",
        "msDS-LockoutObservationWindow",
        "msDS-LockoutDuration",
        "msDS-PasswordHistoryLength",
        "msDS-PasswordComplexityEnabled",
        "msDS-PasswordReversibleEncryptionEnabled",
        "msDS-PSOAppliesTo",
    ]

    def _build_policy(attrs: dict, pso_dn: str) -> Any:
        from datetime import datetime, timezone

        from adscan_internal.services.domain_posture import ResultantPasswordPolicy

        complexity = _coerce_bool_attr(_first_attr(attrs, "msDS-PasswordComplexityEnabled"))
        require_complexity = bool(complexity) if complexity is not None else True
        min_len_raw = _first_attr(attrs, "msDS-MinimumPasswordLength")
        try:
            min_len = int(min_len_raw) if min_len_raw is not None else domain_default.min_length
        except (ValueError, TypeError):
            min_len = domain_default.min_length
        hist_raw = _first_attr(attrs, "msDS-PasswordHistoryLength")
        try:
            history_length = int(hist_raw) if hist_raw is not None else None
        except (ValueError, TypeError):
            history_length = None
        lockout_raw = _first_attr(attrs, "msDS-LockoutThreshold")
        try:
            lockout_threshold = int(lockout_raw) if lockout_raw is not None else 0
        except (ValueError, TypeError):
            lockout_threshold = 0
        return ResultantPasswordPolicy(
            min_length=min_len,
            require_complexity=require_complexity,
            required_classes=(
                _AD_COMPLEXITY_REQUIRED_CLASSES if require_complexity else 0
            ),
            source="live_pso",
            detected_at=datetime.now(timezone.utc),
            history_length=history_length,
            min_pwd_age_days=ad_duration_to_days(_first_attr(attrs, "msDS-MinimumPasswordAge")),
            max_pwd_age_days=ad_duration_to_days(_first_attr(attrs, "msDS-MaximumPasswordAge")),
            lockout_threshold=lockout_threshold,
            lockout_window_minutes=ad_duration_to_minutes(
                _first_attr(attrs, "msDS-LockoutObservationWindow")
            ),
            lockout_duration_minutes=ad_duration_to_minutes(
                _first_attr(attrs, "msDS-LockoutDuration")
            ),
            pso_dn=pso_dn,
        )

    # --- Step 1: authoritative msDS-ResultantPSO BASE read. ---
    if resultant_pso_dn:
        try:
            async for item, err in conn.pagedsearch(
                "(objectClass=msDS-PasswordSettings)",
                pso_attr_names,
                tree=resultant_pso_dn,
                search_scope=0,  # BASE
                raw=True,
            ):
                if err is not None:
                    raise err
                attrs = item.get("attributes") or {}
                print_info_debug(
                    "[posture] PSO resolved via msDS-ResultantPSO (authoritative)"
                )
                return _build_policy(attrs, resultant_pso_dn)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[posture] msDS-ResultantPSO BASE read failed, falling back to "
                f"precedence computation: {type(exc).__name__}: {exc}"
            )

    # --- Step 2: precedence fallback over the PSO container. ---
    pso_container = f"CN=Password Settings Container,CN=System,{domain_dn}"
    candidate_psos: list[tuple[str, tuple[str, ...], "Optional[int]"]] = []
    pso_attrs_by_dn: dict[str, dict] = {}
    try:
        async for item, err in conn.pagedsearch(
            "(objectClass=msDS-PasswordSettings)",
            pso_attr_names,
            tree=pso_container,
            search_scope=2,  # SUBTREE
            raw=True,
        ):
            if err is not None:
                raise err
            attrs = item.get("attributes") or {}
            dn_val = _first_attr(attrs, "distinguishedName")
            if not dn_val:
                continue
            dn = str(dn_val)
            applies_to = tuple(str(v) for v in _values_attr(attrs, "msDS-PSOAppliesTo") if v)
            prec_raw = _first_attr(attrs, "msDS-PasswordSettingsPrecedence")
            try:
                precedence = int(prec_raw) if prec_raw is not None else None
            except (ValueError, TypeError):
                precedence = None
            candidate_psos.append((dn, applies_to, precedence))
            pso_attrs_by_dn[dn.upper()] = attrs
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[posture] PSO container read failed: {type(exc).__name__}: {exc}"
        )
        return None

    winning_dn = select_winning_pso_dn(
        resultant_pso_dn=resultant_pso_dn,
        user_dn=user_dn,
        principal_dns=tuple(group_dns),
        candidate_psos=candidate_psos,
    )
    if winning_dn is None:
        return None
    attrs = pso_attrs_by_dn.get(winning_dn.upper())
    if attrs is None:
        return None
    print_info_debug("[posture] PSO resolved via precedence fallback")
    return _build_policy(attrs, winning_dn)


async def resolve_resultant_password_policy(
    *,
    domain: str,
    dc_ip: str,
    target_user: "Optional[str]" = None,
    username: "Optional[str]" = None,
    password: "Optional[str]" = None,
    nt_hash: "Optional[str]" = None,
    ccache_path: "Optional[str]" = None,
    use_kerberos: bool = False,
    domains_data: "Optional[dict[str, Any]]" = None,
    force_refresh: bool = False,
    timeout: float = 10.0,
) -> Any:
    """Resolve the resultant password policy effective for a principal.

    Live-first resolution (never primarily trusts a stale collector artifact):

    1. **Live LDAP read** — domain default via :func:`probe_password_policy`
       (reused through :func:`get_password_policy`); when ``target_user`` is
       given, the per-user PSO via :func:`_resolve_pso_policy`
       (authoritative ``msDS-ResultantPSO`` BASE read, precedence fallback).
    2. **In-session cache** keyed by ``(domain, target_user_or_None)`` so a
       300-attempt spray reads the policy once. ``force_refresh=True`` busts it.
    3. **Collector / persisted** as last resort (best-effort; the JSON
       reverse-loader is deferred to a later phase — see note below).
    4. **Strong safe default** (``min_length=14``, complexity required,
       ``source="default_assumed"``) when everything else is unavailable.

    Connection handling reuses the mandatory ADscan LDAPS->LDAP fallback
    (``async_connect_with_ldap_fallback`` via ``ADscanLDAPConfig``); this
    function never imports ``LDAPConnectionFactory`` directly.

    Args:
        domain: Target Kerberos realm / AD domain.
        dc_ip: DC IP for the target domain.
        target_user: sAMAccountName or UPN to resolve a PSO for. ``None`` =
            domain default only.
        username, password, nt_hash, ccache_path, use_kerberos: bind creds.
        domains_data: Workspace mapping for the domain-default cache leg.
        force_refresh: Bypass both caches and re-read live.
        timeout: Per-LDAP-operation wall-clock cap, seconds.

    Returns:
        A :class:`~adscan_internal.services.domain_posture.ResultantPasswordPolicy`.
        Always returns a usable policy — never ``None`` (worst case the strong
        safe default).
    """
    from adscan_core import telemetry
    from adscan_core.rich_output import print_info_debug
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cache_key = _resultant_cache_key(domain, target_user)
    if not force_refresh and cache_key in _RESULTANT_POLICY_CACHE:
        return _RESULTANT_POLICY_CACHE[cache_key]

    # --- Leg 1: live domain default (reuses the domains_data-backed cache). ---
    domain_default: "Optional[Any]" = None
    snapshot = await get_password_policy(
        domain=domain,
        dc_ip=dc_ip,
        domains_data=domains_data,
        username=username,
        password=password,
        nt_hash=nt_hash,
        ccache_path=ccache_path,
        use_kerberos=use_kerberos,
        timeout=timeout,
        force_fresh=force_refresh,
    )
    if snapshot is not None:
        domain_default = _snapshot_to_resultant(snapshot, source="live_default_domain")

    # --- Leg 1b: live PSO read when a target user is supplied. ---
    if target_user and domain_default is not None:
        cfg = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            use_ldaps=True,
            use_kerberos=use_kerberos,
            username=username,
            password=password,
            ccache_path=ccache_path,
        )
        if password is None and nt_hash is not None and not use_kerberos:
            cfg.password = nt_hash
        try:
            conn, _used_ldaps = await asyncio.wait_for(
                async_connect_with_ldap_fallback(cfg), timeout=timeout
            )
            try:
                pso_policy = await _resolve_pso_policy(
                    conn,
                    domain_dn=cfg.domain_dn,
                    target_user=target_user,
                    domain_default=domain_default,
                    timeout=timeout,
                )
            finally:
                try:
                    disc = getattr(conn, "disconnect", None)
                    if disc is not None:
                        res = disc()
                        if asyncio.iscoroutine(res):
                            await res
                except Exception as disc_exc:  # noqa: BLE001
                    telemetry.capture_exception(disc_exc)
            if pso_policy is not None:
                _RESULTANT_POLICY_CACHE[cache_key] = pso_policy
                return pso_policy
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[posture] PSO resolution failed; using domain default: "
                f"{type(exc).__name__}: {exc}"
            )

    if domain_default is not None:
        _RESULTANT_POLICY_CACHE[cache_key] = domain_default
        return domain_default

    # --- Leg 3: collector / persisted last resort (best-effort). ---
    # NOTE: the JSON reverse-loader from the persisted ``domain_policy.json`` /
    # ``psos.json`` collector artifacts into model objects is deferred; until a
    # caller threads a parsed ``CollectionResult`` through, this leg degrades
    # straight to the strong safe default. Documented in the Phase-1 spec.

    # --- Leg 4: strong safe default. ---
    fallback = _safe_default_policy()
    _RESULTANT_POLICY_CACHE[cache_key] = fallback
    return fallback


def clear_resultant_policy_cache() -> None:
    """Clear the in-session PSO cache. Test/diagnostic helper."""
    _RESULTANT_POLICY_CACHE.clear()
