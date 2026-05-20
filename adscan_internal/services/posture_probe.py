"""Proactive posture probe engine.

Runs lightweight, single-purpose probes against a Domain Controller to elicit
posture signals BEFORE the first real scan operation pays for the discovery.
Each probe targets exactly one ``ConstraintCategory``. All probes are
READ-ONLY and target only the DC the operator already pointed ADscan at —
same network scope as a regular ``start_unauth`` / ``start_auth`` phase.

Concurrency:
    - Kerberos probes share the KDC connection — sequential.
    - LDAP and SMB probes are independent — ``asyncio.gather``.
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

    A probe is skipped when ``force`` is False, the posture already records
    a non-UNKNOWN HIGH-confidence value for the category, and the constraint
    is not stale.
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
    """Best-effort emission of one ``PostureSignal`` through ``sink``."""
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
    """Probe U1 — anonymous LDAPS bind to detect LDAPS reachability."""
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
        is_ldaps_transport_failure,
    )

    cat = ConstraintCategory.LDAPS_AVAILABLE
    started = _now_ms()
    cfg = ADscanLDAPConfig(
        domain=domain, dc_ip=dc_ip, use_ldaps=True, use_kerberos=False
    )
    try:
        conn, used_ldaps = await asyncio.wait_for(
            async_connect_with_ldap_fallback(cfg), timeout=timeout
        )
        # Best-effort disconnect.
        try:
            disc = getattr(conn, "disconnect", None)
            if disc is not None:
                res = disc()
                if asyncio.iscoroutine(res):
                    await res
        except Exception as disc_exc:  # noqa: BLE001
            telemetry.capture_exception(disc_exc)

        if used_ldaps:
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAPS_BIND_OK",
                message="LDAPS bind on port 636 succeeded",
                protocol="ldaps",
            )
            return ProbeResult(
                category=cat,
                state=TriState.ENABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAPS_BIND_OK",
                message="LDAPS bind on port 636 succeeded",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        # Fell back to plain LDAP successfully — LDAPS unavailable.
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TRANSPORT_FAILURE",
            message="LDAPS port 636 unreachable or TLS handshake failed",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_TRANSPORT_FAILURE",
            message="LDAPS port 636 unreachable or TLS handshake failed",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except asyncio.TimeoutError as exc:
        # TCP timeout on port 636 = port filtered = LDAPS not available.
        # Treat the same as a TLS transport failure: emit LDAPS_AVAILABLE=DISABLED
        # so the posture system and auth_plan skip LDAPS on all subsequent connections.
        telemetry.capture_exception(exc)
        _emit(
            sink,
            domain=domain,
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_FILTERED",
            message=f"LDAPS port 636 timed out after {timeout}s — port filtered or unreachable",
            protocol="ldaps",
        )
        return ProbeResult(
            category=cat,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_PORT_FILTERED",
            message=f"LDAPS port 636 timed out after {timeout}s — port filtered or unreachable",
            duration_ms=_now_ms() - started,
            succeeded=True,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        if is_ldaps_transport_failure(exc):
            _emit(
                sink,
                domain=domain,
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAPS_TRANSPORT_FAILURE",
                message="LDAPS port 636 unreachable or TLS handshake failed",
                protocol="ldaps",
            )
            return ProbeResult(
                category=cat,
                state=TriState.DISABLED,
                confidence=SignalConfidence.HIGH,
                signal_code="LDAPS_TRANSPORT_FAILURE",
                message="LDAPS port 636 unreachable or TLS handshake failed",
                duration_ms=_now_ms() - started,
                succeeded=True,
            )
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"LDAPS probe failed: {type(exc).__name__}",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )


async def _probe_ldap_signing(
    *,
    domain: str,
    dc_ip: str,
    sink: PostureSink,
    timeout: float,
) -> ProbeResult:
    """Probe U2 — anonymous plain-LDAP bind to detect LDAP-signing enforcement."""
    from adscan_internal.services.ldap_transport_service import (
        ADscanLDAPConfig,
        async_connect_with_ldap_fallback,
    )

    cat = ConstraintCategory.LDAP_SIGNING
    started = _now_ms()
    cfg = ADscanLDAPConfig(
        domain=domain, dc_ip=dc_ip, use_ldaps=False, use_kerberos=False
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
        # Anonymous bind succeeded — inconclusive about signing requirement.
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="LDAP_ANON_BIND_INCONCLUSIVE",
            message="Anonymous LDAP bind succeeded — signing requirement undetermined",
            duration_ms=_now_ms() - started,
            succeeded=False,
        )
    except asyncio.TimeoutError as exc:
        telemetry.capture_exception(exc)
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
        text = _chain_text(exc)
        if "strongerauthrequired" in text or "ldap_strong_auth_required" in text:
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
        return ProbeResult(
            category=cat,
            state=TriState.UNKNOWN,
            confidence=SignalConfidence.LOW,
            signal_code="PROBE_FAILED",
            message=f"LDAP signing probe failed: {type(exc).__name__}",
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
        U2 — ``LDAP_SIGNING`` (anonymous plain-LDAP bind).

    The two probes run concurrently. ``timeout_per_probe`` is enforced per
    probe; one hung probe must not hang the other.

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
        One ``ProbeResult`` per physical probe, in the order ``[U1, U2]``.
    """

    async def _u1() -> ProbeResult:
        return await _probe_ldaps_available(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    async def _u2() -> ProbeResult:
        return await _probe_ldap_signing(
            domain=domain, dc_ip=dc_ip, sink=sink, timeout=timeout_per_probe
        )

    u1_task = _run_with_lifecycle(
        category=ConstraintCategory.LDAPS_AVAILABLE,
        runner=_u1,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )
    u2_task = _run_with_lifecycle(
        category=ConstraintCategory.LDAP_SIGNING,
        runner=_u2,
        on_progress=on_progress,
        posture=posture,
        force=force,
    )
    results = await asyncio.gather(u1_task, u2_task)
    return list(results)


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
    """Run the auth probe set against the DC.

    Probes (4 physical, 5 distinct posture signals):
        A1 — ``KERBEROS_RC4`` + ``KERBEROS_AES_ONLY`` (one explicit-etype AS-REQ).
        A2 — ``KERBEROS_ETYPE_PROBE``.
        A3 — ``NTLM_AUTHENTICATION``.
        A4 — ``SMB_SIGNING``.

    Concurrency: A1 and A2 share the KDC and run sequentially; A3 and A4 are
    independent and run in parallel; the two groups run in parallel via
    ``asyncio.gather``.

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
        Four ``ProbeResult`` entries, one per physical probe, in the order
        ``[A1, A2, A3, A4]``.
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

    (a1, a2), (a3, a4) = await asyncio.gather(_kerberos_group(), _independent_group())
    return [a1, a2, a3, a4]


# --------------------------------------------------------------------------- #
# Password policy probe
# --------------------------------------------------------------------------- #


def _filetime_to_days(ft: object) -> "Optional[int]":
    """Convert AD FILETIME (negative 100-ns intervals) to days.

    AD stores ``maxPwdAge`` as a negative FILETIME integer (100-nanosecond
    intervals). Zero (or the minimum int64 sentinel) means *never expires*.

    Args:
        ft: Raw value from the LDAP attribute. May be an int, a string
            representation of an int, or ``None``.

    Returns:
        Number of whole days the policy enforces, or ``None`` when the value
        is absent, zero, unparseable, or represents *never expires*.
    """
    try:
        ft_int = int(ft) if ft is not None else None
    except (ValueError, TypeError):
        return None
    if ft_int is None or ft_int == 0:
        return None  # never expires
    # AD FILETIME for password age is stored as a negative value.
    # -(2**63) is the never-expires sentinel used by some DCs.
    if ft_int <= -(2**63) + 1:
        return None
    seconds = abs(ft_int) / 10_000_000
    days = int(seconds // 86400)
    return days if days > 0 else None


def _filetime_to_minutes(ft: object) -> "Optional[int]":
    """Convert AD FILETIME (negative 100-ns intervals) to whole minutes.

    Used for ``lockoutObservationWindow`` and ``lockoutDuration`` which are
    stored in the same FILETIME format as ``maxPwdAge`` but typically in the
    sub-day range. ``0`` for ``lockoutDuration`` means *admin-unlock-only*
    and is reported as ``None``.

    Args:
        ft: Raw value from the LDAP attribute. May be an int, a string,
            or ``None``.

    Returns:
        Number of whole minutes, or ``None`` when the value is absent, zero,
        unparseable, or represents the never-expires sentinel.
    """
    try:
        ft_int = int(ft) if ft is not None else None
    except (ValueError, TypeError):
        return None
    if ft_int is None or ft_int == 0:
        return None
    if ft_int <= -(2**63) + 1:
        return None
    seconds = abs(ft_int) / 10_000_000
    minutes = int(seconds // 60)
    return minutes if minutes > 0 else None


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
