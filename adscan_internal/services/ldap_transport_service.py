"""Shared LDAP transport helpers with LDAPS->LDAP fallback.

This module centralizes the transport policy for LDAP-backed domain collectors.
ADscan still relies heavily on CLI tooling, but for the smaller set of
domain-scope collectors implemented in Python we want a single place that
decides:

- how CertiHound-style LDAP connections are opened
- when an LDAPS failure should trigger an LDAP retry
- how those retries are logged consistently
"""

from __future__ import annotations

import asyncio
import os
import re
import urllib.parse
from collections.abc import Callable, Mapping
from datetime import datetime, timezone
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    log_exception_debug,
    mark_sensitive,
    print_info_debug,
    print_warning_debug,
)
from adscan_internal.services.domain_posture import (
    ConstraintCategory,
    DomainPosture,
    SignalConfidence,
    TriState,
    PostureSignal,
)
from adscan_internal.services.posture_sink import (  # noqa: F401  (re-exported)
    PostureSink,
    make_workspace_posture_sink,
)

# Activate centralised Kerberos recovery (TKT_EXPIRED/NYV/TGT_REVOKED → auto
# refresh TGT & retry). See _kerberos_recovery for details.
from adscan_internal.services import _kerberos_recovery  # noqa: F401
from adscan_internal.services.auth_error_classification import (
    exception_chain_text,
)


SD_FLAGS_DACL_CONTROL: str = "sd_flags_dacl"
"""Sentinel passed to ADscanLDAPConnection.search(controls=...) to request nTSecurityDescriptor."""

SD_FLAGS_OWNER_CONTROL: str = "sd_flags_owner"
"""Sentinel passed to ADscanLDAPConnection.search/modify to request owner nTSecurityDescriptor."""

SD_FLAGS_ALL_CONTROL: str = "sd_flags_all"
"""Sentinel requesting OWNER+GROUP+DACL (flags=7) so AD computes allowedAttributesEffective."""

_SD_FLAGS_DACL_CONTROL_VALUE: int = 0x04  # DACL only
_SD_FLAGS_OWNER_CONTROL_VALUE: int = 0x01  # Owner only
_SD_FLAGS_ALL_CONTROL_VALUE: int = 0x07  # OWNER + GROUP + DACL


@dataclass
class _LDAPAttrProxy:
    """Minimal attribute proxy exposing .value for ldap3-compatible callsites."""

    value: Any
    raw_value: bytes | None = None


@dataclass
class LDAPEntry:
    """Backend-agnostic LDAP entry returned by ADscanLDAPConnection.search().

    Exposes three access patterns used across ADscan services:
    - entry_attributes_as_dict  → dict[str, list[Any]] (decoded strings or raw bytes)
    - entry_raw_attributes       → dict[str, list[bytes]]
    - entry["attrName"].value    → first decoded value (ldap3-compatible)
    """

    dn: str
    _raw_attrs: dict[str, list[Any]] = field(default_factory=dict)

    @property
    def entry_attributes_as_dict(self) -> dict[str, list[Any]]:
        result: dict[str, list[Any]] = {}
        for name, raw_list in self._raw_attrs.items():
            decoded: list[Any] = []
            for val in raw_list:
                if not isinstance(val, bytes):
                    decoded.append(val)
                    continue
                try:
                    decoded.append(val.decode("utf-8"))
                except (UnicodeDecodeError, AttributeError):
                    decoded.append(val)
            result[name] = decoded
        return result

    @property
    def entry_raw_attributes(self) -> dict[str, list[bytes]]:
        return self._raw_attrs

    def __getitem__(self, attr_name: str) -> _LDAPAttrProxy:
        raw_list = self._raw_attrs.get(attr_name, [])
        if not raw_list:
            return _LDAPAttrProxy(value=None, raw_value=None)
        raw = raw_list[0]
        if not isinstance(raw, bytes):
            return _LDAPAttrProxy(value=raw, raw_value=None)
        try:
            return _LDAPAttrProxy(value=raw.decode("utf-8"), raw_value=raw)
        except UnicodeDecodeError:
            return _LDAPAttrProxy(value=None, raw_value=raw)


@dataclass
class ADscanLDAPConfig:
    """LDAP connection config for ADscanLDAPConnection.

    For cross-domain scenarios (e.g. ping.htb creds → pong.htb LDAP):
    - ``domain`` / ``dc_ip`` describe the *target* domain and DC
    - ``auth_domain`` / ``auth_kdc`` describe the *credentials* domain and its KDC

    Without ``auth_domain``/``auth_kdc``, Kerberos AS-REQ is sent to the target DC,
    which fails when the user account lives in a different domain.

    Restrictive-AD fields (all optional, default to safe no-op values):
    - ``aes_key``: AES-128 (32 hex chars) or AES-256 (64 hex chars) Kerberos session key.
      Used in AES-only domains where RC4 is blocked by GPO. When set, ``use_kerberos``
      must also be True. The URL scheme becomes ``kerberos-aes``.
    - ``etypes``: explicit Kerberos encryption type list (e.g. [18, 17] for AES-256/128 only).
      Passed to badldap via ``etype`` URL query params. Requires ``use_kerberos=True``.
    - ``channel_binding``: request LDAPS channel binding tokens (CBT). Required in
      environments with ``LdapEnforceChannelBinding=2`` GPO. badldap ≥0.7.5 negotiates
      CBT automatically on LDAPS; this field is reserved for explicit opt-in once
      badldap exposes a URL param for it.
    - ``sign``: request LDAP signing (integrity protection). Required when the
      ``LDAPServerIntegrity`` GPO is set to 2. badldap exposes ``_disable_signing``
      on ``MSLDAPClient``; this field wires the inverse.
    - ``encrypt``: request LDAP encryption (confidentiality). Only valid for plain
      LDAP (not LDAPS). badldap exposes this via ``encrypt`` URL query param.
    - ``tls_sni``: explicit TLS SNI hostname for LDAPS connections. When set,
      used as the URL host instead of ``dc_ip``, so the TLS handshake presents the
      correct hostname for certificate validation. Prevents LDAPS failures in
      environments with strict hostname-verifying certs.
    - ``ccache_path``: explicit ccache file path for ``kerberos-ccache`` auth. Takes
      priority over the ``KRB5CCNAME`` environment variable. Use this for programmatic
      flows where the ccache was minted by ``KerberosTicketService`` at a known path.
    - ``paged_size``: LDAP paged-search page size passed to badldap via the
      ``pagesize`` URL param. Max 1000 (badldap enforces this). Default 1000.
    """

    domain: str
    dc_ip: str
    use_ldaps: bool
    use_kerberos: bool
    username: str | None = None
    password: str | None = None
    kerberos_target_hostname: str | None = None
    auth_domain: str | None = None
    auth_kdc: str | None = None
    # Restrictive-AD fields — all optional, safe defaults
    aes_key: str | None = None
    etypes: list[int] | None = None
    channel_binding: bool = False
    sign: bool = False
    encrypt: bool = False
    tls_sni: str | None = None
    ccache_path: str | None = None
    paged_size: int = 1000
    use_simple_bind: bool = False
    """Force RFC 4513 SIMPLE bind. Anonymous SIMPLE (empty creds) yields
    the ``ldap+simple://`` URL form which leaves the connection in RUNNING
    state after bind — required for ``pagedsearch`` against hardened DCs."""

    credential_context: Any = None
    """Optional :class:`CredentialContext` driving PAC-freshness refresh.

    When set, ``async_connect_with_ldap_fallback`` calls
    ``await credential_context.refresh_if_stale(registry)`` immediately before
    each connect attempt.  If the registry has invalidated the bound principal
    since the last bind (e.g. an AddMember step ran), the context re-issues
    the TGT through ``KerberosTicketService`` and the bind uses the fresh
    ccache — fixing the classic ``insufficientAccessRights`` after a
    successful privilege grant.  When ``None``, the legacy ``ccache_path`` /
    ``KRB5CCNAME`` path is used unchanged (no refresh)."""

    posture_sink: "PostureSink | None" = None
    """Optional callable invoked when this transport observes a domain-wide
    LDAP posture signal (LDAPS unreachable, LDAP signing required, channel
    binding required, NTLM rejected via LDAP, etc.). Receives one
    :class:`PostureSignal` and may return an :class:`IntelligenceFinding`
    for the caller to surface to the user. When ``None`` (default), posture
    signals are silently dropped — the transport remains a pure protocol
    module with no workspace coupling. See PR2 (``KerberosConfig.posture_sink``)
    for the matching pattern in the Kerberos transport."""

    posture_snapshot: "DomainPosture | None" = None
    """Optional immutable snapshot of the domain's posture at config-construction
    time. When set, the LDAP fallback uses
    :func:`adscan_internal.services.auth_plan.build_ldap_auth_plan` to drive a
    posture-aware attempt sequence. When ``None`` (default), the conservative
    full retry chain is used — byte-identical to the legacy speculative loop."""

    def __post_init__(self) -> None:
        # Promote short Kerberos target hostnames to FQDN. Centralised here so
        # every call site is fixed at once — see services/_kerberos_spn.py.
        from adscan_internal.services._kerberos_spn import (
            is_ip_address,
            normalize_kerberos_target_hostname,
        )

        if self.use_kerberos and not self.kerberos_target_hostname and self.dc_ip:
            dc_candidate = str(self.dc_ip or "").strip()
            if dc_candidate and not is_ip_address(dc_candidate):
                self.kerberos_target_hostname = dc_candidate
        self.kerberos_target_hostname = normalize_kerberos_target_hostname(
            self.kerberos_target_hostname, self.domain
        )

        # Promote bare KDC addresses to FQDN so Kerberos realm detection
        # works correctly.  IPs pass through unchanged; FQDNs pass through
        # unchanged; bare labels like "dc01" → "dc01.garfield.htb".
        # Without this, callers that read pdc_hostname instead of resolve_dc_ip
        # silently get KDC_ERR_WRONG_REALM.
        self.dc_ip = (
            normalize_kerberos_target_hostname(self.dc_ip, self.domain)
            or self.dc_ip
        )
        if self.auth_kdc:
            # auth_kdc belongs to the auth domain; use auth_domain when set,
            # fall back to target domain for single-realm environments.
            auth_realm = str(self.auth_domain or self.domain or "").strip()
            self.auth_kdc = (
                normalize_kerberos_target_hostname(self.auth_kdc, auth_realm)
                or self.auth_kdc
            )

        # Note: ADscanLDAPConfig intentionally does NOT have a separate
        # ``nt_hash`` field. Pass-the-hash via LDAP works by placing the hash
        # in ``password`` and letting ``_build_ldap_connection_url`` detect
        # the format with ``_is_nt_hash`` and emit the
        # ``ldap+kerberos-rc4://`` (or ``ldap+ntlm-nt://``) URL scheme. Do
        # NOT clear the password here — it would silently break LDAP PtH.

    @property
    def domain_dn(self) -> str:
        labels = [p.strip() for p in str(self.domain or "").split(".") if p.strip()]
        return ",".join(f"DC={label}" for label in labels)

    @property
    def config_dn(self) -> str:
        return f"CN=Configuration,{self.domain_dn}"


_LDAP_SCOPE_MAP: dict[Any, int] = {
    "BASE": 0,
    "ONELEVEL": 1,
    "SUBTREE": 2,
    0: 0,
    1: 1,
    2: 2,
}


def _load_badldap_modules() -> dict[str, Any]:
    """Load badldap modules from installed runtime dependencies.

    Only badldap is supported. The msldap fallback was removed because msldap
    is not installed in the runtime image (only badldap==0.7.5 is present) and
    the silent fallback masked real import errors. If badldap fails to import,
    the exception propagates with a clear RuntimeError.
    """
    try:
        from badldap.client import MSLDAPClient
        from badldap.commons.factory import LDAPConnectionFactory
        from badldap.protocol.constants import BASE, LEVEL
        from badldap.wintypes.asn1.sdflagsrequest import (
            SDFlagsRequest,
            SDFlagsRequestValue,
        )

        return {
            "backend": "badldap",
            "MSLDAPClient": MSLDAPClient,
            "LDAPConnectionFactory": LDAPConnectionFactory,
            "BASE": BASE,
            "LEVEL": LEVEL,
            "SDFlagsRequest": SDFlagsRequest,
            "SDFlagsRequestValue": SDFlagsRequestValue,
        }
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Failed to import badldap backend. "
            f"Ensure badldap>=0.7.5 is installed in the runtime venv. "
            f"Cause: {type(exc).__name__}: {exc}"
        ) from exc


def _build_sd_flags_control(flags: int) -> list[Any]:
    """Return an SD_FLAGS control tuple list compatible with badldap."""
    modules = _load_badldap_modules()
    request_value = modules["SDFlagsRequestValue"]({"Flags": flags})
    return [("1.2.840.113556.1.4.801", True, request_value.dump())]


def _resolve_sd_flags_control(controls: Any) -> Any:
    """Translate ADscan SD flag sentinels to badldap control tuples."""
    if controls == SD_FLAGS_DACL_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_DACL_CONTROL_VALUE)
    if controls == SD_FLAGS_OWNER_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_OWNER_CONTROL_VALUE)
    if controls == SD_FLAGS_ALL_CONTROL:
        return _build_sd_flags_control(_SD_FLAGS_ALL_CONTROL_VALUE)
    return controls


def _resolve_modify_controls(controls: Any) -> Any:
    """Translate ADscan controls to badldap modify control dictionaries."""
    resolved = _resolve_sd_flags_control(controls)
    if isinstance(resolved, list):
        converted = []
        for control in resolved:
            if isinstance(control, tuple) and len(control) == 3:
                converted.append(
                    {
                        "controlType": str(control[0]).encode(),
                        "criticality": control[1],
                        "controlValue": control[2],
                    }
                )
            else:
                converted.append(control)
        return converted
    return resolved


def _quote_url_component(value: str) -> str:
    """URL-encode one LDAP URL component."""
    return urllib.parse.quote(str(value or ""), safe="")


def _is_nt_hash(value: str) -> bool:
    """Return True if value looks like a 32-hex NT hash."""
    return len(value) == 32 and all(c in "0123456789abcdef" for c in value.lower())


def _build_ldap_connection_url(config: "ADscanLDAPConfig") -> tuple[str, bool]:
    """Build a badldap connection URL for one ADscan config.

    URL scheme reference (from badldap/commons/factory.py help_epilog):
        ldap+ntlm-password://DOMAIN\\user:password@host
        ldap+ntlm-nt://DOMAIN\\user:<nthash>@host
        ldap+kerberos-password://DOMAIN\\user:password@host/?dc=<kdc_ip>
        ldap+kerberos-rc4://DOMAIN\\user:<nthash>@host/?dc=<kdc_ip>   ← NT hash Kerberos
        ldap+kerberos-aes://DOMAIN\\user:<aeskey>@host/?dc=<kdc_ip>   ← AES key Kerberos
        ldap+kerberos-ccache://DOMAIN\\user:<ccache_path>@host/?dc=<kdc_ip>  ← ccache
        ldap://host  (anonymous)

    The URL transport prefix (ldap vs ldaps) is controlled by config.use_ldaps.
    The host used for the URL (and therefore TLS SNI on LDAPS) is config.tls_sni
    when set, otherwise config.kerberos_target_hostname or config.dc_ip.

    Returns:
        Tuple of (url, requires_cross_target). requires_cross_target is True when
        auth_domain differs from target domain — caller must use get_client_newtarget.
    """
    transport = "ldaps" if config.use_ldaps else "ldap"

    # For LDAPS TLS: prefer tls_sni (explicit hostname) → kerberos_target_hostname → dc_ip.
    # Using dc_ip as the URL host causes TLS SNI to present an IP address which
    # will fail certificate validation in strict environments.
    if config.use_kerberos:
        from adscan_internal.services._kerberos_spn import (
            require_kerberos_target_hostname,
        )

        url_host = require_kerberos_target_hostname(
            config.tls_sni or config.kerberos_target_hostname,
            protocol="LDAP",
        )
    else:
        url_host = str(
            config.tls_sni or config.kerberos_target_hostname or config.dc_ip or ""
        ).strip()
    if not url_host:
        raise ValueError("LDAP connection requires a DC address or target hostname.")

    auth_domain = str(config.auth_domain or config.domain or "").strip()
    username = str(config.username or "").strip()
    password = str(config.password or "")

    # ---- Kerberos branch ----
    if config.use_kerberos:
        params: list[str] = []

        # dc= is mandatory for Kerberos in badldap — the KDC address.
        kdc_host = str(config.auth_kdc or config.dc_ip or "").strip()
        # Defensive: __post_init__ should have promoted bare hostnames already.
        if kdc_host and "." not in kdc_host:
            from adscan_internal.services._kerberos_spn import is_ip_address
            if not is_ip_address(kdc_host):
                print_info_debug(
                    f"[ldap_transport] bare hostname {kdc_host!r} reached URL builder as KDC — "
                    "expected FQDN or IP (was ADscanLDAPConfig.__post_init__ bypassed?); "
                    f"domain={config.domain!r}"
                )
        if kdc_host:
            params.append(f"dc={_quote_url_component(kdc_host)}")

        # pagesize URL param (badldap enforces max 1000).
        if config.paged_size and config.paged_size != 1000:
            params.append(f"pagesize={min(int(config.paged_size), 1000)}")

        # etypes → repeated etype= params (badldap parses via int_list).
        if config.etypes:
            for etype in config.etypes:
                params.append(f"etype={int(etype)}")

        # encrypt= URL param — only valid for plain LDAP, not LDAPS.
        if config.encrypt and not config.use_ldaps:
            params.append("encrypt=true")

        username_part = (
            f"{_quote_url_component(auth_domain)}\\{_quote_url_component(username)}"
            if username
            else ""
        )

        # Determine auth scheme and secret component. Priority chain
        # — explicit caller intent ALWAYS beats ambient process state:
        #
        #   1. config.ccache_path → kerberos-ccache; secret = ccache path.
        #      Caller explicitly opted into ccache-based auth.
        #   2. config.aes_key → kerberos-aes; secret = AES hex key.
        #      Caller has the AES key material.
        #   3. NT hash (32 hex chars) → kerberos-rc4; secret = NT hash.
        #      Caller has the NT hash (overpass-the-hash).
        #   4. plaintext password → kerberos-password; fresh AS-REQ.
        #      Caller has the cleartext password.
        #   5. KRB5CCNAME env var (LAST resort) → kerberos-ccache.
        #      No explicit credential material at all — only then fall
        #      back to the global Kerberos state.
        #
        # *** Why KRB5CCNAME comes LAST, not first as it used to ***
        #
        # The previous order put ``KRB5CCNAME`` in slot #1 (it was OR'd
        # with ``config.ccache_path`` into a single ``ccache_value``).
        # When a caller passed an explicit ``username + password`` for a
        # FRESH AS-REQ as a specific user but did NOT pass an explicit
        # ``ccache_path``, the LDAP transport silently used whatever TGT
        # was sitting in ``KRB5CCNAME`` from a prior operation. The bind
        # succeeded as the WRONG principal (the one in the env ccache)
        # and the password the caller had explicitly provided was
        # ignored. Symptoms: read succeeds, write fails with
        # ``insufficientAccessRights`` because the principal in the
        # ambient ccache lacks the rights the caller's principal has.
        #
        # Real-world incident (2026-05-21, HTB Puppy): post-spraying
        # ``enable_user`` ran with ``username='ant.edwards'``,
        # ``password='Antman2025!'``, ``ccache=None``. ``KRB5CCNAME``
        # still pointed at LEVI.JAMES's ccache from the initial bind.
        # The LDAP modify was performed as LEVI.JAMES — who does not
        # have GenericAll over adam.silver — and the DC rejected it.
        # bloodyAD invoked with the same explicit creds worked because
        # it uses ``ldap+ntlm-pw://`` and never consults ``KRB5CCNAME``.
        #
        # The new order honours caller intent: if you passed creds, we
        # use those creds. KRB5CCNAME only acts when nothing else is
        # available — preserving legacy behaviour for callers that
        # really do rely on the global Kerberos state.

        explicit_ccache = str(config.ccache_path or "").strip()

        if explicit_ccache:
            # Slot 1: caller explicitly passed ccache_path.
            auth_kind = "kerberos-ccache"
            secret_part = _quote_url_component(explicit_ccache)
        elif config.aes_key:
            # Slot 2: AES key (AS-REQ with AES session key).
            auth_kind = "kerberos-aes"
            secret_part = _quote_url_component(config.aes_key.strip())
        elif password and _is_nt_hash(password):
            # Slot 3: NT hash (overpass-the-hash). badauth maps
            # asyauthSecret.NT → asyauthSecret.RC4 internally.
            auth_kind = "kerberos-rc4"
            secret_part = _quote_url_component(password)
        elif password:
            # Slot 4: plaintext password → fresh AS-REQ.
            auth_kind = "kerberos-password"
            secret_part = _quote_url_component(password)
        else:
            # Slot 5: legacy KRB5CCNAME fallback (no explicit creds).
            env_ccache = str(os.environ.get("KRB5CCNAME") or "").strip()
            if env_ccache:
                print_info_debug(
                    "[kerberos-auth] no explicit credentials in config; "
                    f"falling back to KRB5CCNAME ccache "
                    f"{mark_sensitive(env_ccache, 'path')!r}. Callers that "
                    "want a specific principal must pass ccache_path or "
                    "username+password explicitly."
                )
                auth_kind = "kerberos-ccache"
                secret_part = _quote_url_component(env_ccache)
            else:
                # Truly no credential material — emit an empty-password
                # AS-REQ so the bind surfaces a clear KRB5KDC_ERR_PREAUTH
                # rather than a silent connection error.
                auth_kind = "kerberos-password"
                secret_part = ""

        print_info_debug(
            f"[kerberos-auth] selected auth_kind={auth_kind!r} for "
            f"user={mark_sensitive(str(username or ''), 'user')} "
            f"realm={mark_sensitive(str(auth_domain or ''), 'domain')}"
        )

        credential_part = ""
        if username:
            credential_part = f"{username_part}:{secret_part}@"
        elif auth_kind == "kerberos-ccache" and auth_domain:
            # No explicit username but we have domain + ccache.
            # badldap requires at least a domain in the URL to set the Kerberos realm;
            # username will be resolved from the ccache ticket itself.
            credential_part = f"{_quote_url_component(auth_domain)}\\:{secret_part}@"

        query = f"/?{'&'.join(params)}" if params else "/"
        url = f"{transport}+{auth_kind}://{credential_part}{url_host}{query}"

        requires_cross_target = bool(
            auth_domain
            and auth_domain.casefold() != str(config.domain or "").strip().casefold()
        )

        # Cross-realm: add dcc= (auth KDC) + realmc= (auth realm) so badldap can
        # request a cross-realm referral TGS before binding to the target DC.
        # Mirrors bloodyAD's `params += f"&dcc={cnf.kdcc}&realmc={cnf.realmc}"`.
        if requires_cross_target:
            cross_kdc = str(config.auth_kdc or kdc_host or "").strip()
            if cross_kdc:
                params.append(f"dcc={_quote_url_component(cross_kdc)}")
            params.append(f"realmc={_quote_url_component(auth_domain)}")
            query = f"/?{'&'.join(params)}" if params else "/"
            url = f"{transport}+{auth_kind}://{credential_part}{url_host}{query}"

        return url, requires_cross_target

    # ---- SIMPLE bind branch ----
    # ``use_simple_bind`` selects RFC 4513 SIMPLE bind regardless of other
    # auth state. With empty creds it yields ``ldap+simple://@host``, the
    # canonical anonymous SIMPLE bind that puts the post-bind connection in
    # RUNNING state (required for paged search). With creds it yields the
    # plaintext-over-LDAPS form ``ldap+simple://user:pwd@host``.
    if config.use_simple_bind:
        if username and password is not None:
            principal = f"{auth_domain}\\{username}" if auth_domain else username
            cred_part = (
                f"{_quote_url_component(principal)}:{_quote_url_component(password)}@"
            )
        else:
            # Anonymous SIMPLE bind requires the literal ``@`` separator so
            # badldap recognises empty credentials rather than treating the
            # URL as authenticated.
            cred_part = "@"
        return f"{transport}+simple://{cred_part}{url_host}", False

    # ---- Anonymous branch ----
    if not username and not password:
        return f"{transport}://{url_host}", False

    # ---- NTLM branch ----
    auth_kind = "ntlm-nt" if _is_nt_hash(password) else "ntlm-password"
    principal = username
    if auth_domain:
        principal = f"{auth_domain}\\{username}"

    params_ntlm: list[str] = []
    if config.paged_size and config.paged_size != 1000:
        params_ntlm.append(f"pagesize={min(int(config.paged_size), 1000)}")
    if config.encrypt and not config.use_ldaps:
        params_ntlm.append("encrypt=true")

    query_ntlm = f"/?{'&'.join(params_ntlm)}" if params_ntlm else ""
    url = (
        f"{transport}+{auth_kind}://{_quote_url_component(principal)}:"
        f"{_quote_url_component(password)}@{url_host}{query_ntlm}"
    )
    return url, False


class ADscanLDAPConnection:
    """badldap-backed LDAP context manager for ADscan collectors."""

    def __init__(self, config: ADscanLDAPConfig) -> None:
        self.config = config
        self._conn: Any | None = None
        self._factory: Any | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._entries: list[LDAPEntry] = []
        self._server_info: dict[str, Any] = {}
        # Last write-style operation exception (modify/add/delete).  Exposed so
        # the auth-aware retry layer can detect insufficientAccessRights even
        # though the wrapper methods themselves swallow and return False.
        self.last_error: Exception | None = None

    def __enter__(self) -> "ADscanLDAPConnection":
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        self._conn, _used_ldaps = self._loop.run_until_complete(
            async_connect_with_ldap_fallback(self.config)
        )
        self._server_info = dict(getattr(self._conn, "_serverinfo", {}) or {})
        return self

    def __exit__(self, *_args: Any) -> None:
        if self._conn is not None and self._loop is not None:
            try:
                self._loop.run_until_complete(self._conn.disconnect())
            except Exception:  # noqa: BLE001
                pass
        if self._loop is not None:
            try:
                self._loop.close()
            except Exception:  # noqa: BLE001
                pass
        self._conn = None
        self._factory = None
        self._loop = None
        self._entries = []
        self._server_info = {}

    def _run_coroutine(self, awaitable: Any) -> Any:
        """Run one coroutine on the private connection loop."""
        if self._loop is None:
            raise RuntimeError(
                "ADscanLDAPConnection: connection loop is not initialized"
            )
        return self._loop.run_until_complete(awaitable)

    def _coerce_raw_attribute_values(self, raw_value: Any) -> list[bytes]:
        """Normalize one backend attribute value into a list of raw bytes."""
        values = raw_value if isinstance(raw_value, (list, tuple, set)) else [raw_value]
        normalized: list[bytes] = []
        for value in values:
            if value is None:
                continue
            if isinstance(value, bytes):
                normalized.append(value)
                continue
            normalized.append(str(value).encode("utf-8", errors="surrogatepass"))
        return normalized

    def _build_rootdse_entry(self, attributes: list[str] | None = None) -> LDAPEntry:
        """Synthesize a rootDSE entry from server info returned during connect."""
        requested = list(attributes or [])
        raw_attrs: dict[str, list[bytes]] = {}
        for key, value in self._server_info.items():
            if requested and "*" not in requested and key not in requested:
                continue
            raw_attrs[key] = self._coerce_raw_attribute_values(value)
        return LDAPEntry(dn="", _raw_attrs=raw_attrs)

    def _scope_value(self, search_scope: Any) -> int:
        """Translate ADscan scope values into backend search scope integers."""
        scope_key = (
            str(search_scope).upper() if isinstance(search_scope, str) else search_scope
        )
        scope_int = _LDAP_SCOPE_MAP.get(scope_key, None)
        if scope_int is None:
            print_warning_debug(
                f"[ldap] Unknown search_scope {search_scope!r}; defaulting to SUBTREE"
            )
            return 2
        return scope_int

    @property
    def entries(self) -> list[LDAPEntry]:
        return self._entries

    @property
    def domain_dn(self) -> str:
        return self.config.domain_dn

    @property
    def config_dn(self) -> str:
        return self.config.config_dn

    def search(
        self,
        search_base: str,
        search_filter: str,
        attributes: list[str] | None = None,
        search_scope: Any = "SUBTREE",
        paged_size: int = 1000,
        controls: Any = None,
    ) -> None:
        """Execute an LDAP search and populate ``self.entries``.

        Args:
            search_base: LDAP search base DN.
            search_filter: LDAP filter string.
            attributes: List of attributes to retrieve; defaults to all ("*").
            search_scope: "BASE", "ONELEVEL", "SUBTREE", or integer 0/1/2.
            paged_size: Page size for paged search. Honored via badldap pagedsearch;
                also wired into the connection URL at construction time via
                ``ADscanLDAPConfig.paged_size``. Max 1000.
            controls: Pass ``SD_FLAGS_DACL_CONTROL`` to request nTSecurityDescriptor DACL.
        """
        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: search called outside context manager"
            )

        effective_attrs = list(attributes or ["*"])
        scope_int = self._scope_value(search_scope)
        self._entries = []
        if search_base == "" and self._server_info and scope_int == 0:
            self._entries = [self._build_rootdse_entry(effective_attrs)]
            return

        # paged_size is honored at the connection URL level (pagesize= param).
        # The pagedsearch call does not accept an explicit page size argument;
        # badldap uses the value from MSLDAPTarget.ldap_query_page_size.
        _ = paged_size

        async def _collect_entries() -> list[LDAPEntry]:
            collected: list[LDAPEntry] = []
            async for item, err in self._conn.pagedsearch(  # type: ignore[union-attr]
                search_filter,
                effective_attrs,
                controls=_resolve_sd_flags_control(controls),
                tree=search_base or None,
                search_scope=scope_int,
                raw=True,
            ):
                if err is not None:
                    raise err
                raw_attrs = {
                    str(attr_name): self._coerce_raw_attribute_values(attr_value)
                    for attr_name, attr_value in dict(
                        item.get("attributes", {}) or {}
                    ).items()
                }
                dn = str(item.get("objectName", "") or "")
                collected.append(LDAPEntry(dn=dn, _raw_attrs=raw_attrs))
            return collected

        self._entries = list(self._run_coroutine(_collect_entries()) or [])

    def add(self, dn: str, object_class: list[str], attributes: dict[str, Any]) -> bool:
        """Add a new LDAP object.

        Args:
            dn: Distinguished name of the new object.
            object_class: List of objectClass values (e.g. ["top", "organizationalUnit"]).
            attributes: Dictionary of attribute names to values. ``objectClass`` is
                merged from the ``object_class`` parameter.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: add called outside context manager"
            )

        merged: dict[str, Any] = dict(attributes)
        merged["objectClass"] = object_class

        async def _do_add() -> bool:
            ok, err = await self._conn.add(dn, merged)  # type: ignore[union-attr]
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_add())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] add failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def modify(
        self,
        dn: str,
        changes: dict[str, Any],
        encode: bool = True,
        controls: Any = None,
    ) -> bool:
        """Modify attributes on an existing LDAP object.

        Args:
            dn: Distinguished name of the object to modify.
            changes: badldap-style changes dict:
                ``{'attribute': [('MODIFY_REPLACE', [value])]}``
                Change operation keys follow ldap3/badldap conventions:
                MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE.
            encode: When True (default), badldap encodes str/int values.
                Set to False when passing raw bytes (e.g. nTSecurityDescriptor,
                msDS-KeyCredentialLink) to avoid double-encoding.
            controls: Optional LDAP controls. Pass ``SD_FLAGS_DACL_CONTROL`` when
                replacing ``nTSecurityDescriptor`` DACL bytes.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: modify called outside context manager"
            )

        async def _do_modify() -> bool:
            effective_controls = _resolve_modify_controls(controls)
            ok, err = await self._conn.modify(  # type: ignore[union-attr]
                dn, changes, controls=effective_controls, encode=encode
            )
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_modify())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] modify failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def delete(self, dn: str) -> bool:
        """Delete an LDAP object.

        Args:
            dn: Distinguished name of the object to delete.

        Returns:
            True on success, False on failure.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: delete called outside context manager"
            )

        async def _do_delete() -> bool:
            ok, err = await self._conn.delete(dn)  # type: ignore[union-attr]
            if err is not None:
                raise err
            return bool(ok)

        try:
            result = self._run_coroutine(_do_delete())
            self.last_error = None
            return result
        except Exception as exc:  # noqa: BLE001
            self.last_error = exc
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] delete failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False

    def modify_dn(
        self,
        dn: str,
        new_rdn: str,
        new_superior: str | None = None,
    ) -> bool:
        """Rename or move an LDAP object (modifyDN / modifyRDN).

        badldap does not expose a dedicated modifyDN method on MSLDAPClient.
        This is implemented via the underlying MSLDAPClientConnection.modify_dn
        if available, otherwise raises NotImplementedError.

        Args:
            dn: Current distinguished name.
            new_rdn: New relative distinguished name (e.g. "CN=newname").
            new_superior: New parent DN for move operations; None for rename-only.

        Returns:
            True on success, False on failure.

        Raises:
            NotImplementedError: If badldap does not expose modifyDN at the
                connection level. Upgrade badldap or use a raw connection.
        """
        from adscan_internal import telemetry

        if self._conn is None:
            raise RuntimeError(
                "ADscanLDAPConnection: modify_dn called outside context manager"
            )

        # badldap MSLDAPClient does not have a modify_dn wrapper — fall through
        # to the underlying _con (MSLDAPClientConnection) if it exposes one.
        underlying = getattr(self._conn, "_con", None)
        if underlying is None or not hasattr(underlying, "modify_dn"):
            raise NotImplementedError(
                "modify_dn is not exposed by the current badldap MSLDAPClient. "
                "Use the underlying MSLDAPClientConnection directly or upgrade badldap."
            )

        async def _do_modify_dn() -> bool:
            ok, err = await underlying.modify_dn(
                dn, new_rdn, deleteoldrdn=True, newSuperior=new_superior
            )
            if err is not None:
                raise err
            return bool(ok)

        try:
            return self._run_coroutine(_do_modify_dn())
        except NotImplementedError:
            raise
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] modify_dn failed for dn={mark_sensitive(dn, 'path')}: {exc}"
            )
            return False


class LDAPTransportValidationError(RuntimeError):
    """Raised when an LDAP connection opens but is not usable for queries."""


@dataclass(frozen=True)
class LDAPTargetEndpoints:
    """Resolved LDAP transport and Kerberos target endpoints for one domain."""

    dc_address: str | None
    kerberos_target_hostname: str | None
    dc_ip: str | None
    dc_fqdn: str | None


def _format_gssapi_ccache_name(ccache_name: str) -> str:
    """Return a Kerberos ccache name suitable for python-gssapi."""
    value = str(ccache_name or "").strip()
    if not value:
        return value
    if re.match(r"^[A-Za-z][A-Za-z0-9_+-]*:", value):
        return value
    return f"FILE:{value}"


def _set_gssapi_default_ccache_from_environment() -> bool:
    """Bind python-gssapi's default ccache to ``KRB5CCNAME`` for LDAP SASL.

    ldap3's GSSAPI path ultimately calls GSS-API with ``GSS_C_NO_CREDENTIAL``.
    On some runtimes the GSS layer keeps using the UID default cache even after
    ``KRB5CCNAME`` was updated in Python. Setting python-gssapi's krb5 ccache
    name explicitly makes the workspace ticket authoritative for the thread.

    Returns:
        True when a ccache was explicitly applied.
    """
    ccache_env = str(os.environ.get("KRB5CCNAME") or "").strip()
    if not ccache_env:
        return False

    ccache_name = _format_gssapi_ccache_name(ccache_env)
    try:
        from gssapi.raw.ext_krb5 import krb5_ccache_name  # pylint: disable=no-name-in-module

        krb5_ccache_name(ccache_name.encode("utf-8"))
        print_info_debug(
            "[ldap] Bound python-gssapi default credential cache to "
            f"{mark_sensitive(ccache_name, 'path')}"
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log_exception_debug(
            "Failed to bind python-gssapi default credential cache",
            exception=exc,
            context={"krb5ccname": mark_sensitive(ccache_name, "path")},
        )
        print_warning_debug(
            "[ldap] Failed to bind python-gssapi default credential cache from "
            f"KRB5CCNAME={mark_sensitive(ccache_name, 'path')}. "
            f"Cause: {_format_exception_chain_summary(exc)}"
        )
        return False


def bind_workspace_ticket_for_user(
    *,
    domains_data: Mapping[str, Any] | None,
    domain: str,
    username: str,
    realm: str | None = None,
) -> bool:
    """Activate the workspace TGT for *username* in the current process.

    This is the fast-path counterpart to :func:`prepare_kerberos_ldap_environment`
    used by hot LDAP query helpers (``query_shell_ldap_attribute_values``).
    It avoids the full ticket-refresh dance and instead:

    1. Looks up the ccache registered under
       ``domains_data[domain]["kerberos_tickets"][username]``.
    2. Verifies via :func:`validate_tgt_for_user` that the file actually
       contains a TGT for *username* — defending against the historical bug
       where any non-empty ``kerberos_tickets`` entry was treated as "Kerberos
       is ready", regardless of which user was active.
    3. Sets ``KRB5CCNAME`` and binds python-gssapi's default credential cache
       so subsequent badldap / aiosmb Kerberos calls honour the workspace
       ticket without falling back to the UID default cache.

    Returns:
        ``True`` when the workspace ticket was bound; ``False`` when no
        usable TGT for *username* is registered.  Callers should fall back to
        :func:`prepare_kerberos_ldap_environment` (which can refresh) or skip
        Kerberos altogether on ``False``.
    """
    from adscan_internal.services.kerberos_ccache_inspector import (  # noqa: PLC0415
        validate_tgt_for_user,
    )

    if not isinstance(domains_data, Mapping):
        return False
    domain_data = domains_data.get(domain, {}) if isinstance(domains_data, Mapping) else {}
    if not isinstance(domain_data, Mapping):
        return False

    tickets = domain_data.get("kerberos_tickets", {})
    if not isinstance(tickets, Mapping):
        return False

    user_key = str(username or "").strip()
    if not user_key:
        return False
    ticket_path = tickets.get(user_key)
    if not ticket_path:
        # Try a case-insensitive lookup for tolerance with mixed-case names.
        for stored_user, stored_path in tickets.items():
            if isinstance(stored_user, str) and stored_user.casefold() == user_key.casefold():
                ticket_path = stored_path
                break
    ticket_path = str(ticket_path or "").strip()
    if not ticket_path or not os.path.exists(ticket_path):
        return False

    effective_realm = (realm or domain or "").strip().upper() or None
    result = validate_tgt_for_user(
        ticket_path, username=user_key, realm=effective_realm
    )
    if not result.ok:
        print_info_debug(
            f"[ldap] workspace ticket for {mark_sensitive(user_key, 'user')}@"
            f"{mark_sensitive(effective_realm or '?', 'domain')} rejected: {result.reason}"
        )
        return False

    os.environ["KRB5CCNAME"] = ticket_path
    _set_gssapi_default_ccache_from_environment()
    print_info_debug(
        f"[ldap] bound workspace ticket {mark_sensitive(ticket_path, 'path')} "
        f"for {mark_sensitive(user_key, 'user')}@{mark_sensitive(effective_realm or '?', 'domain')}"
    )
    return True


def resolve_ldap_target_endpoints(
    *,
    target_domain: str,
    domain_data: Mapping[str, Any] | None,
    kerberos_ready: bool,
    ip_hostname_inventory: dict | None = None,
) -> LDAPTargetEndpoints:
    """Resolve transport and Kerberos target endpoints for one domain.

    Delegates FQDN selection to :func:`resolve_dc_fqdn` so the canonical
    fallback chain (incl. workspace inventory) is honoured here too.

    Args:
        target_domain: DNS domain name.
        domain_data: Domain metadata loaded in the shell workspace.
        kerberos_ready: Whether the caller intends to authenticate with Kerberos.
        ip_hostname_inventory: Optional ``{ip: [hostname, …]}`` map from the
            workspace reachability scan. When provided, used as a last-resort
            FQDN source when no hostname field is populated.

    Returns:
        Resolved transport target plus the FQDN that Kerberos should use for the
        service principal name.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn  # noqa: PLC0415

    domain_data_dict = dict(domain_data) if isinstance(domain_data, Mapping) else {}
    dc_fqdn = resolve_dc_fqdn(
        domain_data_dict,
        target_domain=target_domain,
        ip_hostname_inventory=ip_hostname_inventory,
    )
    dc_ip = str(domain_data_dict.get("pdc") or "").strip() or None
    kerberos_target_hostname = dc_fqdn or None
    _ = kerberos_ready  # preserved for callers that may inspect signature
    dc_address = dc_ip or dc_fqdn
    return LDAPTargetEndpoints(
        dc_address=dc_address,
        kerberos_target_hostname=kerberos_target_hostname,
        dc_ip=dc_ip,
        dc_fqdn=dc_fqdn,
    )


def build_ldap_config_for_domain(
    domains_data: Mapping[str, Any],
    domain: str,
    *,
    username: str,
    password: str | None = None,
    nt_hash: str | None = None,
    ccache_path: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    use_ldaps: bool = True,
    use_kerberos: bool | None = None,
    ip_hostname_inventory: dict | None = None,
    posture_sink: Any = None,
    posture_snapshot: Any = None,
) -> ADscanLDAPConfig:
    """Build an ``ADscanLDAPConfig`` from ``domains_data`` with FQDN resolution.

    Single canonical entry point for any caller that wants an LDAP transport
    config derived from the workspace ``domains_data`` map. Walks the FQDN
    fallback chain via ``resolve_dc_fqdn`` so Kerberos-aware callers never
    end up with ``kerberos_target_hostname=None`` while ``dc_ip`` is an IP —
    the exact bug class the dataclass guard exists to surface.

    Args:
        domains_data: ``shell.domains_data`` map (``{domain: {…}}``).
        domain: Target domain key to look up.
        username: Account name for authentication.
        password: Plaintext password (ignored when nt_hash or ccache_path is set).
        nt_hash: NT hash for pass-the-hash Kerberos.
        ccache_path: Explicit ccache file path for ``kerberos-ccache`` auth.
        auth_domain: Cross-domain auth override for the credential's home domain.
        auth_kdc: KDC IP override for cross-domain authentication.
        use_ldaps: Prefer LDAPS (port 636). Defaults to True; the transport
            layer falls back to LDAP automatically when LDAPS is unavailable.
        use_kerberos: When None, inferred from ``ccache_path`` presence.
        ip_hostname_inventory: Optional pre-loaded inventory for IP → FQDN
            fallback. Pass ``load_workspace_ip_hostname_inventory(...)`` from
            the call site that has workspace paths.
        posture_sink: Forwarded to the dataclass for posture signal emission.
        posture_snapshot: Forwarded to the dataclass for auth-plan pruning.

    Returns:
        Fully-formed ``ADscanLDAPConfig`` with ``kerberos_target_hostname``
        resolved from the FQDN fallback chain whenever possible.

    Raises:
        KeyError: ``domain`` is not in ``domains_data``.
        ValueError: No DC IP could be resolved from the ``domains_data`` entry.
    """
    from adscan_internal.models.domain import resolve_dc_fqdn, resolve_dc_ip  # noqa: PLC0415

    if domain not in domains_data:
        raise KeyError(domain)

    domain_data = domains_data[domain] or {}
    dc_ip = resolve_dc_ip(domain_data)
    if not dc_ip:
        raise ValueError(
            f"DC IP could not be resolved for domain {domain!r} from domains_data; "
            "ensure the domain entry has a 'pdc' / 'dc_ip' / 'dcs' field."
        )

    kerberos_active = bool(ccache_path) if use_kerberos is None else bool(use_kerberos)
    kerberos_target_hostname = resolve_dc_fqdn(
        domain_data,
        target_domain=domain,
        ip_hostname_inventory=ip_hostname_inventory,
    )

    return ADscanLDAPConfig(
        domain=domain,
        dc_ip=dc_ip,
        kerberos_target_hostname=kerberos_target_hostname,
        use_ldaps=use_ldaps,
        use_kerberos=kerberos_active,
        username=username,
        password=None if (nt_hash or ccache_path) else password,
        ccache_path=ccache_path,
        auth_domain=auth_domain,
        auth_kdc=auth_kdc,
        posture_sink=posture_sink,
        posture_snapshot=posture_snapshot,
    )


def prepare_kerberos_ldap_environment(
    *,
    operation_name: str,
    target_domain: str,
    workspace_dir: str,
    username: str,
    user_domain: str,
    credential: str | None = None,
    dc_ip: str | None = None,
    domains_data: Mapping[str, Any] | None = None,
    sync_clock: Callable[[str], Any] | None = None,
    force_ticket_refresh: bool = False,
) -> bool:
    """Prepare Kerberos env vars and clock sync for LDAP-backed collectors.

    This is the canonical preflight for any Python LDAP workflow that wants to
    authenticate with Kerberos against a domain controller. It validates the
    workspace ccache, refreshes it when missing/expired and credentials are
    available, then explicitly binds python-gssapi to the chosen ccache.

    Returns:
        ``True`` when a usable workspace Kerberos ticket was configured.
    """
    from adscan_internal import telemetry
    from adscan_internal.services import KerberosTicketService

    domain_key = str(target_domain or "").strip()
    workspace_root = str(workspace_dir or "").strip()
    user_name = str(username or "").strip()
    auth_domain = str(user_domain or domain_key).strip() or domain_key
    credential_value = str(credential or "").strip()
    marked_operation = mark_sensitive(operation_name, "path")
    marked_user = mark_sensitive(user_name, "user")
    marked_auth_domain = mark_sensitive(auth_domain, "domain")

    if not domain_key or not workspace_root:
        print_info_debug(
            f"[ldap] {marked_operation} missing workspace/domain context; Kerberos LDAP env setup skipped."
        )
        return False

    if sync_clock is not None:
        try:
            sync_clock(domain_key)
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[ldap] Kerberos clock sync failed before {marked_operation} for "
                f"{mark_sensitive(domain_key, 'domain')}: {exc}"
            )

    service = KerberosTicketService()

    def _setup_environment() -> tuple[bool, bool, str | None, str | None]:
        return service.setup_environment_for_domain(
            workspace_dir=workspace_root,
            domain=domain_key,
            user_domain=auth_domain,
            username=user_name or None,
            domains_data=domains_data,
        )

    try:
        krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path = (
            _setup_environment()
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(
            f"[ldap] Failed to prepare Kerberos LDAP environment for "
            f"{mark_sensitive(domain_key, 'domain')}: {exc}"
        )
        return False

    ticket_valid = None
    if kerberos_ticket_set and ticket_path and os.path.exists(ticket_path):
        try:
            ticket_valid = service.is_ticket_valid(ticket_path=ticket_path)
            print_info_debug(
                f"[ldap] Workspace Kerberos ticket state for {marked_operation}: "
                f"user={marked_user}@{marked_auth_domain} "
                f"ccache={mark_sensitive(ticket_path, 'path')} valid={ticket_valid!r}"
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[ldap] Kerberos ticket validation failed for {marked_user}@"
                f"{marked_auth_domain} during {marked_operation}: {exc}"
            )

    should_refresh_ticket = bool(
        credential_value
        and user_name
        and (
            force_ticket_refresh
            or not kerberos_ticket_set
            or not ticket_path
            or not os.path.exists(ticket_path)
            or ticket_valid is False
        )
    )
    if should_refresh_ticket:
        refresh_reason = (
            "forced"
            if force_ticket_refresh
            else "missing"
            if not kerberos_ticket_set
            or not ticket_path
            or not os.path.exists(ticket_path)
            else "invalid"
        )
        print_info_debug(
            f"[ldap] Refreshing Kerberos ticket for {marked_operation}: "
            f"user={marked_user}@{marked_auth_domain} reason={refresh_reason}"
        )
        try:
            auth_domain_data = (
                domains_data.get(auth_domain, {})
                if isinstance(domains_data, Mapping)
                else {}
            )
            refresh_dc_ip = (
                str(
                    dc_ip
                    or (
                        auth_domain_data.get("pdc")
                        if isinstance(auth_domain_data, Mapping)
                        else ""
                    )
                    or ""
                ).strip()
                or None
            )
            result = service.auto_generate_tgt(
                username=user_name,
                credential=credential_value,
                domain=auth_domain,
                workspace_dir=workspace_root,
                dc_ip=refresh_dc_ip,
            )
            if not result.success:
                print_warning_debug(
                    f"[ldap] Kerberos ticket refresh failed for {marked_operation}: "
                    f"user={marked_user}@{marked_auth_domain} error={result.error_message!r}"
                )
            krb5_config_set, kerberos_ticket_set, krb5_config_path, ticket_path = (
                _setup_environment()
            )
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_debug(
                f"[ldap] Kerberos ticket refresh raised during {marked_operation}: "
                f"Cause: {_format_exception_chain_summary(exc)}"
            )

    if krb5_config_set and krb5_config_path:
        print_info_debug(
            f"[ldap] Using workspace krb5.conf for {marked_operation}: "
            f"{mark_sensitive(krb5_config_path, 'path')}"
        )
    else:
        workspace_conf = Path(workspace_root).expanduser().resolve() / "krb5.conf"
        print_info_debug(
            f"[ldap] No workspace krb5.conf available for {marked_operation} at "
            f"{mark_sensitive(str(workspace_conf), 'path')}"
        )

    if kerberos_ticket_set and ticket_path and os.path.exists(ticket_path):
        _set_gssapi_default_ccache_from_environment()
        print_info_debug(
            f"[ldap] Using workspace Kerberos ticket for {marked_operation}: "
            f"{mark_sensitive(ticket_path, 'path')}"
        )
        return True

    print_info_debug(
        f"[ldap] No workspace Kerberos ticket available for "
        f"{mark_sensitive(user_name, 'username')}@{mark_sensitive(auth_domain, 'domain')} "
        f"during {marked_operation}; falling back to password-backed LDAP bind."
    )
    return False


def _walk_exception_chain(exc: BaseException) -> list[BaseException]:
    """Return the exception with its ``__cause__`` / ``__context__`` chain."""
    seen: set[int] = set()
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        chain.append(current)
        current = current.__cause__ or current.__context__
    return chain


def _format_exception_chain_summary(exc: BaseException, *, max_items: int = 3) -> str:
    """Return a compact exception chain summary for debug messages."""
    parts: list[str] = []
    for candidate in _walk_exception_chain(exc)[:max_items]:
        class_name = type(candidate).__name__.strip() or "Exception"
        message = str(candidate or "").strip()
        parts.append(f"{class_name}: {message}" if message else class_name)
    if not parts:
        return type(exc).__name__
    return " <- ".join(parts)


def is_ldaps_transport_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like an LDAPS transport/TLS failure.

    Includes timeout-class exceptions: when LDAPS:636 is filtered the TCP
    connect never completes and asyncio raises TimeoutError / CancelledError.
    These are always connectivity failures (never auth failures) at connect time,
    so they should trigger the LDAPS→LDAP fallback just like TLS errors.
    """
    # Timeout exceptions — port 636 filtered → TCP never connects → timeout.
    for candidate in _walk_exception_chain(exc):
        if isinstance(candidate, (TimeoutError, asyncio.TimeoutError,
                                   asyncio.CancelledError)):
            return True

    indicators = (
        "socket ssl wrapping error",
        "socket is not open",
        "ldapsocketopenerror",
        "ssl handshake error",
        "connection reset by peer",
        "unable to send message",
        "tls",
        "ldaps",
        "ldaptransportvalidationerror",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(
            indicator in haystack for haystack in haystacks for indicator in indicators
        ):
            return True
    return False


def is_kerberos_auth_failure(exc: BaseException) -> bool:
    """Return whether one exception looks like a Kerberos/GSSAPI auth failure."""

    indicators = (
        "server not found in kerberos database",
        "ticket expired",
        "krb_ap_err",
        "kerberos",
        "gssapi",
        "gsserror",
        "preauthentication failed",
        "no credentials were supplied",
        "cannot find kdc",
        "client not found in kerberos database",
    )
    for candidate in _walk_exception_chain(exc):
        class_name = type(candidate).__name__.strip().lower()
        message = str(candidate or "").strip().lower()
        haystacks = (class_name, message)
        if any(
            indicator in haystack for haystack in haystacks for indicator in indicators
        ):
            return True
    return False


# ---------------------------------------------------------------------------
# Posture signal emission (PR3)
# ---------------------------------------------------------------------------


def _emit_posture_signal(
    config: "ADscanLDAPConfig",
    *,
    category: ConstraintCategory,
    state: TriState,
    confidence: SignalConfidence,
    signal_code: str,
    message: str,
    protocol: str = "ldap",
) -> None:
    """Emit an LDAP posture signal to the configured sink, if any.

    Pure best-effort: any exception in the sink is captured via telemetry and
    never propagates — posture telemetry must never break an LDAP bind.
    """
    sink = getattr(config, "posture_sink", None)
    if sink is None:
        return
    try:
        signal = PostureSignal(
            domain=config.domain,
            category=category,
            state=state,
            confidence=confidence,
            source="ldap_transport",
            signal_code=signal_code,
            message=message,
            protocol=protocol,
            observed_at=datetime.now(timezone.utc),
        )
        sink(signal)
    except Exception as sink_exc:
        telemetry.capture_exception(sink_exc)
        print_info_debug(
            f"[ldap_transport] posture sink raised: "
            f"{type(sink_exc).__name__}: {sink_exc}"
        )


def _emit_ldap_failure_posture(
    config: "ADscanLDAPConfig",
    *,
    exc: BaseException,
    used_kerberos_auth: bool,
    transport_was_ldaps: bool,
) -> None:
    """Classify one LDAP bind failure and emit any matching posture signals.

    A single failure may match multiple rules — each emits a separate signal
    (the posture module deduplicates downstream). ``transport_was_ldaps``
    represents the user's transport intent (LDAPS vs plain LDAP) and is used
    to gate channel-binding detection (only meaningful on LDAPS).
    """
    chain_text = " ".join(
        f"{type(c).__name__}: {c}".lower() for c in _walk_exception_chain(exc)
    )
    # Rule 1 — LDAP signing required.
    if (
        "strongerauthrequired" in chain_text
        or "ldap_strong_auth_required" in chain_text
        or "ldap signing" in chain_text
    ):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAP_SIGNING,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_STRONG_AUTH_REQUIRED",
            message="DC requires LDAP signing for unencrypted binds",
        )
    # Rule 2 — LDAP channel binding required (only meaningful on LDAPS).
    if transport_was_ldaps and "channel binding" in chain_text:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAP_CHANNEL_BINDING,
            state=TriState.REQUIRED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAP_CHANNEL_BINDING_REQUIRED",
            message="DC enforces LDAP channel binding for LDAPS binds",
        )
    # Rule 3 — NTLM rejected via LDAP while a Kerberos TGT was valid.
    if (
        used_kerberos_auth
        and "invalidcredentials" in chain_text
        and "sec_e_logon_denied" in chain_text
    ):
        _emit_posture_signal(
            config,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.DISABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="NTLM_REJECTED_VIA_LDAP",
            message=(
                "DC rejected NTLM bind with SEC_E_LOGON_DENIED while a "
                "Kerberos TGT was valid — NTLM appears disabled by policy"
            ),
        )


def _emit_ldap_success_posture(
    config: "ADscanLDAPConfig",
    *,
    used_kerberos_auth: bool,
    used_ldaps: bool,
) -> None:
    """Emit posture signals for a successful LDAP bind.

    LDAPS success → ``LDAPS_AVAILABLE = ENABLED`` (HIGH).
    NTLM (password) success → ``NTLM_AUTHENTICATION = ENABLED`` (MEDIUM).
    Kerberos success is intentionally not emitted: Kerberos is the default
    auth mechanism and its success carries no hardening signal.
    """
    if used_ldaps:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.LDAPS_AVAILABLE,
            state=TriState.ENABLED,
            confidence=SignalConfidence.HIGH,
            signal_code="LDAPS_BIND_OK",
            message="LDAPS bind succeeded on port 636",
        )
    if not used_kerberos_auth:
        _emit_posture_signal(
            config,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
            state=TriState.ENABLED,
            confidence=SignalConfidence.MEDIUM,
            signal_code="NTLM_BIND_OK",
            message="NTLM bind via LDAP succeeded",
        )


def _validate_rootdse_query(connection: Any) -> None:
    """Ensure one LDAP connection can execute a minimal rootDSE query."""
    attempts = (
        ["namingContexts"],
        ["defaultNamingContext"],
        ["*"],
    )
    last_exc: BaseException | None = None
    for attributes in attempts:
        try:
            search_result = connection.search(
                search_base="",
                search_filter="(objectClass=*)",
                attributes=attributes,
                search_scope="BASE",
            )
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            continue

        # Support ADscanLDAPConnection (.entries), ldap3 connections
        # (.connection.entries), and connections that return results directly from search().
        entries = getattr(connection, "entries", None)
        if entries is None:
            entries = getattr(getattr(connection, "connection", None), "entries", None)
        if isinstance(entries, list) and entries:
            return
        if isinstance(search_result, list) and search_result:
            return

    if last_exc is not None:
        raise LDAPTransportValidationError(
            "LDAP transport validation failed during rootDSE query"
        ) from last_exc
    raise LDAPTransportValidationError(
        "LDAP transport validation failed: rootDSE query returned no entries"
    )


def _diag_dump_ccache(ccache_path: str | Path | None) -> None:
    """Diagnostic: log TGT timestamps and clock skew to debug SEC_E_LOGON_DENIED."""
    import time

    try:
        path = Path(ccache_path) if ccache_path else None
        if not path or not path.exists():
            print_info_debug(f"[ldap_transport][diag] ccache missing: {ccache_path}")
            return

        from kerbad.common.ccache import CCACHE  # type: ignore

        ccache = CCACHE.from_file(str(path))
        now = time.time()
        now_iso = datetime.fromtimestamp(now, tz=timezone.utc).isoformat()
        creds = list(getattr(ccache, "credentials", []) or [])
        print_info_debug(
            f"[ldap_transport][diag] ccache={path} now={now_iso} creds={len(creds)}"
        )
        for idx, cred in enumerate(creds):
            try:
                times = getattr(cred, "time", None)
                authtime = getattr(times, "authtime", None)
                starttime = getattr(times, "starttime", None)
                endtime = getattr(times, "endtime", None)
                renew_till = getattr(times, "renew_till", None)
                server = getattr(cred, "server", None)
                spn = (
                    "/".join([c.to_string() for c in server.components])
                    if server is not None and getattr(server, "components", None)
                    else repr(server)
                )
                skew = (
                    f"{int(now - starttime)}s past starttime"
                    if isinstance(starttime, (int, float))
                    else "n/a"
                )
                expired = isinstance(endtime, (int, float)) and now > endtime
                print_info_debug(
                    f"[ldap_transport][diag] cred[{idx}] spn={spn} "
                    f"authtime={authtime} starttime={starttime} endtime={endtime} "
                    f"renew_till={renew_till} expired={expired} {skew}"
                )
            except Exception as exc:  # noqa: BLE001
                print_info_debug(
                    f"[ldap_transport][diag] cred[{idx}] dump failed: "
                    f"{type(exc).__name__}: {exc}"
                )
    except Exception as exc:  # noqa: BLE001
        print_info_debug(
            f"[ldap_transport][diag] ccache dump raised {type(exc).__name__}: {exc}"
        )


def _diag_dump_bind_exception(exc: BaseException) -> None:
    """Diagnostic: walk exception chain to surface Kerberos error under SEC_E_LOGON_DENIED."""
    try:
        chain = _walk_exception_chain(exc)
        for idx, e in enumerate(chain):
            print_info_debug(
                f"[ldap_transport][diag] exc[{idx}] type={type(e).__name__} repr={e!r}"
            )
            for attr in (
                "error_code",
                "errorCode",
                "result_code",
                "kerberos_error",
                "native_errno",
            ):
                val = getattr(e, attr, None)
                if val is not None:
                    print_info_debug(
                        f"[ldap_transport][diag] exc[{idx}].{attr}={val!r}"
                    )
    except Exception as inner:  # noqa: BLE001
        print_info_debug(
            f"[ldap_transport][diag] bind exception dump failed: "
            f"{type(inner).__name__}: {inner}"
        )


async def async_connect_with_ldap_fallback(
    config: "ADscanLDAPConfig",
) -> tuple[Any, bool]:
    """Async LDAPS→LDAP fallback for native badldap consumers.

    Preferred over direct ``LDAPConnectionFactory.from_url()`` calls because it:
    - Tries LDAPS (port 636) first
    - Detects TLS transport failures via :func:`is_ldaps_transport_failure`
    - Retries transparently on plain LDAP (port 389)
    - Handles cross-domain referrals when ``config.auth_domain``/``config.auth_kdc`` are set

    Args:
        config: LDAP connection config. Set ``config.use_ldaps = True`` (the default);
            the fallback will downgrade to ``False`` automatically if LDAPS is unavailable.

    Returns:
        ``(connected_client, used_ldaps)`` where *connected_client* is a live
        ``MSLDAPClient`` and *used_ldaps* records which transport succeeded.

    Raises:
        Exception: last connection error when both LDAPS and plain LDAP fail.
    """
    modules = _load_badldap_modules()
    LDAPConnectionFactory = modules["LDAPConnectionFactory"]

    configs_to_try: list[tuple["ADscanLDAPConfig", bool]] = []
    if config.use_ldaps:
        configs_to_try.append((config, True))
        import dataclasses as _dc

        plain_config = _dc.replace(config, use_ldaps=False)
        configs_to_try.append((plain_config, False))
    else:
        configs_to_try.append((config, False))

    # ---- PR6b: posture-driven plan pruning ---------------------------------
    # When the caller threaded a ``posture_snapshot`` into the config, consult
    # ``auth_plan.build_ldap_auth_plan`` and prune the speculative chain to
    # only the transport+auth combinations the posture says are viable. When
    # ``posture_snapshot`` is ``None`` the conservative chain above is used
    # unchanged (byte-identical with pre-PR6b behaviour).
    if getattr(config, "posture_snapshot", None) is not None:
        from adscan_internal.services.auth_plan import (
            LDAPTransport as _PlanTransport,
            NoViableLDAPAuthError,
            build_ldap_auth_plan,
        )
        import dataclasses as _dc_plan

        plan = build_ldap_auth_plan(config=config, posture=config.posture_snapshot)
        if plan.is_empty:
            note = plan.notes[0] if plan.notes else "no viable LDAP auth combinations"
            raise NoViableLDAPAuthError(note)

        plan_transports = {att.transport for att in plan.attempts}
        # Field overrides from the plan (CBT on LDAPS, signing on LDAP) are
        # taken from the first attempt of each transport, since the planner
        # only ever produces one attempt per transport per primary scheme in
        # PR6b's LDAP-only scope.
        ldaps_overrides = next(
            (a for a in plan.attempts if a.transport is _PlanTransport.LDAPS), None
        )
        ldap_overrides = next(
            (a for a in plan.attempts if a.transport is _PlanTransport.LDAP), None
        )

        pruned: list[tuple["ADscanLDAPConfig", bool]] = []
        for cfg, is_ldaps in configs_to_try:
            transport_key = _PlanTransport.LDAPS if is_ldaps else _PlanTransport.LDAP
            if transport_key not in plan_transports:
                continue
            override = ldaps_overrides if is_ldaps else ldap_overrides
            if override is not None and (
                override.channel_binding != cfg.channel_binding
                or override.sign != cfg.sign
            ):
                cfg = _dc_plan.replace(
                    cfg,
                    channel_binding=override.channel_binding,
                    sign=override.sign,
                )
            pruned.append((cfg, is_ldaps))
        configs_to_try = pruned
        if not configs_to_try:
            raise NoViableLDAPAuthError(
                "Posture pruning produced no viable LDAP transport"
            )
    # ------------------------------------------------------------------------

    # Refresh stale Kerberos ticket once before the LDAPS/LDAP attempts.  The
    # refresh result applies to every fallback attempt below — both transports
    # use the same ccache.  Errors are swallowed by ``refresh_if_stale`` itself,
    # so the bind can still surface the canonical auth error if the refresh
    # could not run.
    cred_ctx = getattr(config, "credential_context", None)
    if cred_ctx is not None:
        try:
            refreshed = await cred_ctx.refresh_if_stale()
            if refreshed:
                # Propagate the new ccache path into every prepared config.
                refreshed_path = getattr(cred_ctx, "ccache_path", None)
                if refreshed_path:
                    import dataclasses as _dc_refresh

                    configs_to_try = [
                        (_dc_refresh.replace(c, ccache_path=refreshed_path), is_l)
                        for (c, is_l) in configs_to_try
                    ]
        except Exception as exc:  # noqa: BLE001
            print_info_debug(
                f"[ldap_transport] credential refresh raised {type(exc).__name__}: {exc}"
            )
    elif config.use_kerberos and config.ccache_path:
        # Legacy call site — flag once so we can migrate it later.
        print_info_debug(
            "[ldap_transport] kerberos bind without CredentialContext; "
            "PAC freshness not guaranteed (legacy ccache path)"
        )
        _diag_dump_ccache(config.ccache_path)

    last_exc: Exception | None = None
    last_attempt_was_ldaps: bool = False
    ldaps_disabled_emitted: bool = False
    for cfg, is_ldaps in configs_to_try:
        transport_label = "LDAPS" if is_ldaps else "LDAP"
        last_attempt_was_ldaps = is_ldaps
        try:
            url, requires_cross_target = _build_ldap_connection_url(cfg)
            if cfg.use_kerberos:
                _host_for_spn = str(
                    cfg.tls_sni or cfg.kerberos_target_hostname or cfg.dc_ip or ""
                ).strip()
                _is_ip_spn = bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", _host_for_spn))
                print_info_debug(
                    f"[ldap_transport][diag] kerberos SPN host={_host_for_spn!r} "
                    f"is_ip={_is_ip_spn} kerberos_target_hostname="
                    f"{cfg.kerberos_target_hostname!r} tls_sni={cfg.tls_sni!r} "
                    f"dc_ip={cfg.dc_ip!r}"
                )
            factory = LDAPConnectionFactory.from_url(url)

            if cfg.use_kerberos:
                target_host = str(
                    cfg.tls_sni or cfg.kerberos_target_hostname or ""
                ).strip()
                conn = factory.get_client_newtarget(
                    hostname_or_ip=target_host,
                    ip=cfg.dc_ip,
                    new_domain=cfg.domain if requires_cross_target else None,
                    old_target_ip=str(cfg.auth_kdc or cfg.dc_ip or "").strip() or None,
                )
            elif requires_cross_target:
                target_host = str(
                    cfg.kerberos_target_hostname or cfg.dc_ip or ""
                ).strip()
                conn = factory.get_client_newtarget(
                    hostname_or_ip=target_host,
                    ip=cfg.dc_ip,
                    new_domain=cfg.domain,
                    old_target_ip=str(cfg.auth_kdc or cfg.dc_ip or "").strip() or None,
                )
            else:
                conn = factory.get_client()

            if hasattr(conn, "_disable_signing"):
                conn._disable_signing = not cfg.sign
            if hasattr(conn, "_disable_channel_binding"):
                conn._disable_channel_binding = not cfg.channel_binding

            ok, err = await conn.connect()
            if not ok:
                raise err or RuntimeError(
                    f"{transport_label} connect returned ok=False"
                )

            print_info_debug(
                f"[ldap_transport] async connect: {transport_label} on {cfg.dc_ip}"
            )
            _emit_ldap_success_posture(
                config,
                used_kerberos_auth=cfg.use_kerberos,
                used_ldaps=is_ldaps,
            )
            return conn, is_ldaps

        except Exception as exc:
            last_exc = exc
            _diag_dump_bind_exception(exc)
            if is_ldaps and is_ldaps_transport_failure(exc):
                if not ldaps_disabled_emitted:
                    _emit_posture_signal(
                        config,
                        category=ConstraintCategory.LDAPS_AVAILABLE,
                        state=TriState.DISABLED,
                        confidence=SignalConfidence.HIGH,
                        signal_code="LDAPS_TRANSPORT_FAILURE",
                        message=(
                            "LDAPS port unreachable or TLS handshake failed — "
                            "domain does not expose LDAPS"
                        ),
                    )
                    ldaps_disabled_emitted = True
                print_info_debug(
                    f"[ldap_transport] LDAPS unavailable on {config.dc_ip}, retrying on plain LDAP"
                )
                continue
            if last_exc is not None:
                _emit_ldap_failure_posture(
                    config,
                    exc=last_exc,
                    used_kerberos_auth=config.use_kerberos,
                    transport_was_ldaps=last_attempt_was_ldaps,
                )
            raise

    if last_exc is not None:
        _emit_ldap_failure_posture(
            config,
            exc=last_exc,
            used_kerberos_auth=config.use_kerberos,
            transport_was_ldaps=last_attempt_was_ldaps,
        )
    raise last_exc or RuntimeError(
        "Both LDAPS and plain LDAP connection attempts failed"
    )


def execute_with_ldap_fallback(
    *,
    operation_name: str,
    target_domain: str,
    dc_address: str,
    callback: Callable[[Any], Any],
    config_cls: type[Any] | None = None,
    connection_cls: type[Any] | None = None,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    prefer_ldaps: bool = True,
    validate_connection: Callable[[Any], None] | None = None,
    config_overrides: Mapping[str, Any] | None = None,
    kerberos_target_hostname: str | None = None,
    allow_password_fallback_on_kerberos_failure: bool = False,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
    posture_sink: "PostureSink | None" = None,
) -> tuple[Any, bool]:
    """Execute one LDAP-backed callback with centralized LDAPS->LDAP fallback.

    When ``config_cls`` and ``connection_cls`` are None (the default), the
    ADscan-native badldap-backed classes are used.

    Args:
        posture_sink: Optional :data:`PostureSink` propagated into every
            ``ADscanLDAPConfig`` built by this helper. Lets callers receive
            posture signals (LDAPS unavailable, signing required, NTLM
            disabled, etc.) emitted by the underlying transport. ``None`` is
            a no-op.

    Returns:
        Tuple ``(result, used_ldaps)``.

    Raises:
        Exception: Re-raises the terminal connection/operation error.
    """
    effective_config_cls = config_cls if config_cls is not None else ADscanLDAPConfig
    effective_connection_cls = (
        connection_cls if connection_cls is not None else ADscanLDAPConnection
    )

    attempts = [prefer_ldaps]
    if prefer_ldaps:
        attempts.append(False)

    marked_operation = mark_sensitive(operation_name, "path")
    marked_domain = mark_sensitive(target_domain, "domain")
    marked_dc = mark_sensitive(dc_address, "host")
    marked_kerberos_target = mark_sensitive(
        str(kerberos_target_hostname or "").strip() or "n/a",
        "hostname",
    )
    last_exc: Exception | None = None

    auth_attempts: list[bool] = [use_kerberos]
    can_retry_with_password = (
        use_kerberos
        and allow_password_fallback_on_kerberos_failure
        and bool(str(username or "").strip())
        and bool(str(password or "").strip())
    )
    if can_retry_with_password:
        auth_attempts.append(False)

    for use_kerberos_auth in auth_attempts:
        retry_with_password = False
        for use_ldaps in attempts:
            transport = "LDAPS" if use_ldaps else "LDAP"
            auth_mode = "Kerberos" if use_kerberos_auth else "password"
            print_info_debug(
                f"[ldap] Attempting {marked_operation} over {transport} for "
                f"{marked_domain} via {marked_dc} using {auth_mode} auth"
            )
            config_kwargs: dict[str, Any] = {
                "domain": target_domain,
                "dc_ip": dc_address,
                "use_ldaps": use_ldaps,
                "use_kerberos": use_kerberos_auth,
            }
            if posture_sink is not None:
                config_kwargs["posture_sink"] = posture_sink
            if isinstance(config_overrides, Mapping):
                config_kwargs.update(dict(config_overrides))
            if use_kerberos_auth and str(kerberos_target_hostname or "").strip():
                config_kwargs["kerberos_target_hostname"] = str(
                    kerberos_target_hostname
                ).strip()
            if use_kerberos_auth and str(auth_domain or "").strip():
                config_kwargs["auth_domain"] = str(auth_domain).strip()
            if use_kerberos_auth and str(auth_kdc or "").strip():
                config_kwargs["auth_kdc"] = str(auth_kdc).strip()
            if str(username or "").strip():
                config_kwargs["username"] = str(username).strip()
            if password:
                config_kwargs["password"] = password
            if not use_kerberos_auth and (not str(username or "").strip() or not password):
                raise ValueError(
                    f"{operation_name} with password auth requires username and password."
                )

            try:
                config = effective_config_cls(**config_kwargs)
                with effective_connection_cls(config) as connection:
                    validator = validate_connection or _validate_rootdse_query
                    validator(connection)
                    result = callback(connection)
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                if use_ldaps and prefer_ldaps and is_ldaps_transport_failure(exc):
                    log_exception_debug(
                        f"LDAP transport retry for {marked_operation}",
                        exception=exc,
                        context={
                            "domain": marked_domain,
                            "dc": marked_dc,
                            "transport": transport,
                            "auth_mode": auth_mode,
                            "kerberos_target_hostname": marked_kerberos_target,
                        },
                    )
                    print_warning_debug(
                        f"[ldap] {marked_operation} failed over LDAPS for {marked_domain}; "
                        "retrying over LDAP. "
                        f"Cause: {_format_exception_chain_summary(exc)}"
                    )
                    continue
                if (
                    use_kerberos_auth
                    and can_retry_with_password
                    and is_kerberos_auth_failure(exc)
                ):
                    # When the TGT has expired, try to renew it before falling
                    # back to password bind.  Renewal preserves Kerberos auth
                    # (more secure, matches what the DC expects) and avoids
                    # downgrading to plaintext credentials.
                    _exc_text = exception_chain_text(exc).upper()
                    _tgt_expired = "TKT_EXPIRED" in _exc_text or "TICKET HAS EXPIRED" in _exc_text
                    if _tgt_expired:
                        _ccache = str(
                            (config_overrides or {}).get("ccache_path", "") or ""
                        ).strip()
                        if _ccache:
                            try:
                                from adscan_internal.services.kerberos_ticket_service import (
                                    KerberosTicketService,
                                )
                                _renewed = KerberosTicketService().try_renew_tgt(
                                    ticket_path=_ccache
                                )
                                if _renewed:
                                    print_info_debug(
                                        f"[ldap] Kerberos TGT renewed for {marked_operation} — "
                                        f"retrying Kerberos auth instead of password fallback"
                                    )
                                    continue  # retry this transport with fresh TGT
                            except Exception as _renew_exc:  # noqa: BLE001
                                print_info_debug(
                                    f"[ldap] TGT renewal failed for {marked_operation}: "
                                    f"{type(_renew_exc).__name__}: {_renew_exc}"
                                )
                    # For TKT_EXPIRED specifically: this is expected when a
                    # session runs longer than the TGT's validity window and
                    # renewal wasn't possible.  Log without the full traceback
                    # to keep the operator's debug output clean.
                    if _tgt_expired:
                        print_info_debug(
                            f"[ldap] {marked_operation} Kerberos TGT expired for "
                            f"{marked_domain} via {marked_dc} — falling back to "
                            f"password bind (renewal not available or failed)"
                        )
                    else:
                        log_exception_debug(
                            f"LDAP Kerberos auth retry for {marked_operation}",
                            exception=exc,
                            context={
                                "domain": marked_domain,
                                "dc": marked_dc,
                                "transport": transport,
                                "auth_mode": auth_mode,
                                "kerberos_target_hostname": marked_kerberos_target,
                            },
                        )
                        print_warning_debug(
                            f"[ldap] {marked_operation} Kerberos auth failed for {marked_domain} "
                            f"via {marked_dc}; retrying with password bind. "
                            f"Cause: {_format_exception_chain_summary(exc)}"
                        )
                    retry_with_password = True
                    break
                raise

            if not use_ldaps:
                print_info_debug(
                    f"[ldap] LDAP fallback succeeded for {marked_operation} on {marked_domain}"
                )
            if not use_kerberos_auth and use_kerberos:
                print_info_debug(
                    f"[ldap] Password bind fallback succeeded for {marked_operation} on "
                    f"{marked_domain}"
                )
            return result, bool(use_ldaps)

        if retry_with_password:
            continue

    if last_exc is not None:
        if posture_sink is not None:
            # Synthesize a minimal config purely to carry the sink + domain so
            # the failure classifier can emit. The posture signals only need
            # ``domain`` and ``posture_sink`` to be set.
            try:
                _emit_ldap_failure_posture(
                    ADscanLDAPConfig(
                        domain=target_domain,
                        dc_ip=dc_address,
                        use_ldaps=bool(prefer_ldaps),
                        use_kerberos=bool(use_kerberos),
                        posture_sink=posture_sink,
                    ),
                    exc=last_exc,
                    used_kerberos_auth=bool(use_kerberos),
                    transport_was_ldaps=bool(prefer_ldaps),
                )
            except Exception as _emit_exc:  # noqa: BLE001
                telemetry.capture_exception(_emit_exc)
        raise last_exc
    raise RuntimeError(f"{operation_name} failed without executing any LDAP attempt")
