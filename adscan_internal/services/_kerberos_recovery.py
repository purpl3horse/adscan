"""Centralised Kerberos error recovery for the entire native stack.

Importing this module monkey-patches ``kerbad.aioclient.AIOKerberosClient.with_clock_skew``
so that **every** kerbad-driven flow — kerberos_transport, badauth (LDAP / SMB / RPC),
badldap, aiosmb — transparently recovers from:

* ``KRB_AP_ERR_SKEW``        — clock drift (already covered by kerbad upstream)
* ``KRB_AP_ERR_TKT_EXPIRED`` — TGT/ticket lifetime exhausted mid-run
* ``KRB_AP_ERR_TKT_NYV``     — ticket not yet valid (boundary skew variant)
* ``KDC_ERR_TGT_REVOKED``    — TGT revoked / forced renewal

When the wrapped function is anything other than ``get_TGT`` itself and the
client's ``KerberosCredential`` carries a renewable secret (password, NT hash,
AES key, certificate / PKINIT material), the patched wrapper re-issues an
AS-REQ via ``client.get_TGT(...)`` and retries the original call **once**.
Cred-only-via-CCACHE situations propagate the original error untouched —
without the secret, no fresh TGT is possible from this layer.

Single source of truth: every callsite that uses ``client.with_clock_skew(...)``
inherits the recovery transparently, including the badauth path that performs
``self.kc.with_clock_skew(self.kc.get_TGS, spn)`` after a stale CCACHE TGT.

This module is import-once, idempotent, and never imports anything from
``adscan_internal`` to keep the dependency direction clean.

Patch A — global realm skew cache + ``AIOKerberosClient.__init__`` pre-seeding
    ``_REALM_SKEW_CACHE`` (keyed by uppercase realm) is populated whenever
    kerbad's ``with_clock_skew`` wrapper successfully learns a skew (from a
    KRB-ERROR stime).  ``kerbad.aioclient.AIOKerberosClient.__init__`` is
    patched to read the cache at construction time so every fresh ``kc``
    created for the same realm starts with the correct offset.
"""

from __future__ import annotations

import datetime
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


_PATCH_MARKER = "_adscan_recovery_patched"

# ---------------------------------------------------------------------------
# Patch A — module-level realm skew cache
# ---------------------------------------------------------------------------
# Plain dict: asyncio is single-threaded within an event loop so no lock
# is needed for dict reads and writes in coroutines.  Background threads are
# not expected to write here.
_REALM_SKEW_CACHE: dict[str, datetime.timedelta] = {}


def _credential_can_refresh_tgt(credential: Any) -> bool:
    """Return True when the credential carries a secret usable for a fresh AS-REQ."""
    if credential is None:
        return False
    secret_attrs = (
        "password",
        "nt_hash",
        "kerberos_key_aes_256",
        "kerberos_key_aes_128",
        "kerberos_key_rc4",
        "kerberos_key_des3",
        "kerberos_key_des",
        "certificate",
    )
    for attr in secret_attrs:
        if getattr(credential, attr, None):
            return True
    return False


def _is_recoverable_ticket_error(exc: BaseException, error_code_cls: Any) -> bool:
    """True if ``exc`` is a Kerberos ticket-expired/revoked/not-yet-valid error."""
    code = getattr(exc, "errorcode", None)
    if code is None:
        return False
    candidates = []
    for name in ("KRB_AP_ERR_TKT_EXPIRED", "KRB_AP_ERR_TKT_NYV", "KDC_ERR_TGT_REVOKED"):
        value = getattr(error_code_cls, name, None)
        if value is not None:
            candidates.append(value)
    return code in candidates


def install() -> None:
    """Install all recovery patches.  Idempotent: re-imports do not stack patches."""
    _install_kerbad_with_clock_skew()
    _install_patch_a_init()


# ---------------------------------------------------------------------------
# Existing patch — kerbad with_clock_skew + ticket-expired recovery
# ---------------------------------------------------------------------------


def _install_kerbad_with_clock_skew() -> None:
    try:
        from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
        from kerbad.protocol.errors import KerberosError, KerberosErrorCode  # noqa: PLC0415
    except ImportError:
        return

    if getattr(AIOKerberosClient.with_clock_skew, _PATCH_MARKER, False):
        return

    original_with_clock_skew = AIOKerberosClient.with_clock_skew

    async def _refresh_tgt(client: AIOKerberosClient) -> None:
        """Re-issue an AS-REQ in place using the credential's renewable secret."""
        override_etypes = (
            list(getattr(client.credential, "override_etypes", []) or []) or None
        )
        # Use the original, un-patched ``with_clock_skew`` so a refresh does not
        # recurse into our patched wrapper while it is itself recovering.
        await original_with_clock_skew(
            client, client.get_TGT, override_etype=override_etypes
        )

    async def with_clock_skew_recovery(
        self: AIOKerberosClient,
        func: Callable[..., Any],
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        try:
            result = await original_with_clock_skew(self, func, *args, **kwargs)
            # Patch A: persist any skew kerbad just learned to the realm cache.
            # kerbad sets self.clock_skew when it detects KRB_AP_ERR_SKEW;
            # we mirror it to _REALM_SKEW_CACHE so fresh kc instances
            # start with the correct offset.
            _sync_skew_to_cache(self)
            return result
        except KerberosError as exc:
            # Mirror skew even on failure (kerbad may have set it before re-raising).
            _sync_skew_to_cache(self)
            if not _is_recoverable_ticket_error(exc, KerberosErrorCode):
                raise
            # Avoid recursion: if we were already inside get_TGT, a fresh TGT
            # won't fix anything (the AS-REQ itself returned the error).
            if getattr(func, "__name__", "") == "get_TGT":
                raise
            if not _credential_can_refresh_tgt(getattr(self, "credential", None)):
                logger.debug(
                    "Kerberos ticket expired but credential has no renewable "
                    "secret (ccache-only); propagating."
                )
                raise
            # Apply clock_skew from the KRB_ERROR's stime before refreshing.
            # TKT_EXPIRED is server-side, but if the local clock has drifted
            # since the original TGT was issued, the refresh AS-REQ would
            # otherwise carry skewed timestamps and fail with KRB_AP_ERR_SKEW
            # on the very next call. Cost is zero — stime is already in the
            # error message we just received.
            try:
                server_time = exc.krb_err_msg["stime"]
                local_time = datetime.datetime.now(datetime.timezone.utc)
                self.clock_skew = server_time - local_time
                _sync_skew_to_cache(self)
            except Exception:  # noqa: BLE001 — best-effort sync, never fatal
                pass
            logger.warning(
                "Kerberos ticket expired (%s); refreshing TGT and retrying %s.",
                getattr(exc, "errorcode", "?"),
                getattr(func, "__name__", repr(func)),
            )
            await _refresh_tgt(self)
            result = await original_with_clock_skew(self, func, *args, **kwargs)
            _sync_skew_to_cache(self)
            return result

    setattr(with_clock_skew_recovery, _PATCH_MARKER, True)
    AIOKerberosClient.with_clock_skew = with_clock_skew_recovery

    # Auto-route every Kerberos primitive through with_clock_skew so callers
    # cannot bypass clock-skew + ticket-expired recovery by accident. Any future
    # `await client.S4U2self(...)` style call inherits the same recovery as
    # explicit `client.with_clock_skew(client.S4U2self, ...)`. Idempotent.
    _AUTO_WRAP_METHODS = (
        "get_TGT",
        "get_TGS",
        "S4U2self",
        "S4U2proxy",
        "getST",
        "U2U",
        "get_referral_ticket",
    )
    for _method_name in _AUTO_WRAP_METHODS:
        original = getattr(AIOKerberosClient, _method_name, None)
        if original is None or getattr(original, _PATCH_MARKER, False):
            continue

        def _make_wrapper(method_name: str, original_func: Callable[..., Any]):
            async def _auto_clock_skew_wrapper(self, *args: Any, **kwargs: Any) -> Any:
                return await self.with_clock_skew(original_func, self, *args, **kwargs)

            setattr(_auto_clock_skew_wrapper, _PATCH_MARKER, True)
            _auto_clock_skew_wrapper.__name__ = method_name
            _auto_clock_skew_wrapper.__qualname__ = f"AIOKerberosClient.{method_name}"
            return _auto_clock_skew_wrapper

        setattr(AIOKerberosClient, _method_name, _make_wrapper(_method_name, original))


def _sync_skew_to_cache(client: Any) -> None:
    """Write *client*.clock_skew into _REALM_SKEW_CACHE if non-None."""
    skew = getattr(client, "clock_skew", None)
    if skew is None:
        return
    try:
        realm = client.credential.domain.upper()
        if realm:
            _REALM_SKEW_CACHE[realm] = skew
            logger.debug("Realm skew cache updated: %s → %s", realm, skew)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# Patch A — kerbad AIOKerberosClient.__init__ pre-seeding from realm cache
# ---------------------------------------------------------------------------


def _install_patch_a_init() -> None:
    """Patch kerbad AIOKerberosClient.__init__ to pre-seed clock_skew from cache."""
    try:
        from kerbad.aioclient import AIOKerberosClient  # noqa: PLC0415
    except ImportError:
        return

    if getattr(AIOKerberosClient.__init__, _PATCH_MARKER, False):
        return

    original_init = AIOKerberosClient.__init__

    def patched_init(self, *args: Any, **kwargs: Any) -> None:
        original_init(self, *args, **kwargs)
        # If we already know the clock skew for this realm, pre-seed it so
        # the very first Kerberos request uses the correct timestamp without
        # needing a KRB-ERROR round-trip.
        try:
            realm = (getattr(self.credential, "domain", None) or "").upper()
            if realm and realm in _REALM_SKEW_CACHE:
                self.clock_skew = _REALM_SKEW_CACHE[realm]
                logger.debug(
                    "Pre-seeded clock_skew=%s for realm %s from cache",
                    self.clock_skew,
                    realm,
                )
        except Exception:  # noqa: BLE001
            pass

    setattr(patched_init, _PATCH_MARKER, True)
    AIOKerberosClient.__init__ = patched_init


install()
