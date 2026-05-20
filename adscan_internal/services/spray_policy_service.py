"""Native LDAP-based password policy and BadPwdCount fetch for spraying.

Replaces NetExec subprocess calls for:
- Domain default password policy (lockoutThreshold, lockoutDuration)
- Per-user badPwdCount (all enabled user accounts)
- Fine-grained PSO lockout threshold per user (msDS-ResultantPSO)

All functions return gracefully on failure so callers can fall back to
NetExec without user-visible errors.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any

from adscan_core.rich_output import print_info_debug, print_warning_debug
from adscan_internal import telemetry
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    async_connect_with_ldap_fallback,
)

# Attributes to fetch per user for spray eligibility
_USER_SPRAY_ATTRS = [
    "sAMAccountName",
    "badPwdCount",
    "userAccountControl",
    "msDS-ResultantPSO",
]

# Attributes to fetch from domain root for default password policy
_DOMAIN_POLICY_ATTRS = [
    "lockoutThreshold",
    "lockoutDuration",
    "lockoutObservationWindow",
    "minPwdLength",
    "maxPwdAge",
]

# Attributes to fetch from PSO objects
_PSO_ATTRS = [
    "name",
    "distinguishedName",
    "msDS-LockoutThreshold",
    "msDS-LockoutDuration",
    "msDS-LockoutObservationWindow",
    "msDS-PSOAppliesTo",
    "msDS-PasswordSettingsPrecedence",
]

# sAMAccountType for normal user accounts (excludes computers by default)
_USER_ONLY_FILTER = "(&(sAMAccountType=805306368)(!(isDeleted=TRUE))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

# Filter to locate PSO container
_PSO_FILTER = "(objectClass=msDS-PasswordSettings)"


@dataclass(slots=True)
class DomainPasswordPolicy:
    """Default domain password policy lockout settings."""

    lockout_threshold: int | None = None
    lockout_duration_seconds: int | None = None
    observation_window_seconds: int | None = None
    no_lockout_enforced: bool = False


@dataclass(slots=True)
class PSOPolicy:
    """Fine-grained password policy object (PSO)."""

    name: str = ""
    dn: str = ""
    lockout_threshold: int | None = None
    precedence: int = 0


@dataclass(slots=True)
class SprayPolicyResult:
    """Complete spray-safe policy result from native LDAP.

    Attributes:
        default_policy: Domain-level lockout settings.
        pso_by_name: PSO objects keyed by DN (for per-user resolution).
        badpwd_by_user: Lowercase sAMAccountName → badPwdCount.
        pso_dn_by_user: Lowercase sAMAccountName → resultant PSO DN (if any).
        fetch_errors: Non-fatal errors encountered during fetch.
    """

    default_policy: DomainPasswordPolicy = field(default_factory=DomainPasswordPolicy)
    pso_by_dn: dict[str, PSOPolicy] = field(default_factory=dict)
    badpwd_by_user: dict[str, int] = field(default_factory=dict)
    pso_dn_by_user: dict[str, str] = field(default_factory=dict)
    fetch_errors: list[str] = field(default_factory=list)

    def effective_lockout_threshold(self, username_lower: str) -> int | None:
        """Return the effective lockout threshold for a user.

        PSO takes precedence over default domain policy when present.
        """
        pso_dn = self.pso_dn_by_user.get(username_lower)
        if pso_dn:
            pso = self.pso_by_dn.get(pso_dn.lower())
            if pso and pso.lockout_threshold is not None:
                return pso.lockout_threshold
        return self.default_policy.lockout_threshold


def _interval_to_seconds(interval: int | None) -> int | None:
    """Convert a Windows LDAP interval (100-nanosecond units, negative) to seconds."""
    if interval is None:
        return None
    try:
        # AD stores durations as negative 100-ns intervals
        return abs(int(interval)) // 10_000_000
    except (TypeError, ValueError):
        return None


async def _fetch_domain_policy(
    conn: Any,
    domain_nc: str,
) -> DomainPasswordPolicy:
    """Fetch lockout policy from the domain naming context root."""
    policy = DomainPasswordPolicy()
    try:
        async for entry, err in conn.pagedsearch(
            query="(objectClass=domain)",
            attributes=_DOMAIN_POLICY_ATTRS,
            tree=domain_nc,
            search_scope=0,  # BASE scope — domain root only
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] domain policy search error: {err}")
                continue
            attrs = entry.get("attributes", {})
            raw_threshold = attrs.get("lockoutThreshold")
            if raw_threshold is not None:
                try:
                    threshold = int(raw_threshold)
                    policy.lockout_threshold = threshold
                    policy.no_lockout_enforced = threshold == 0
                except (TypeError, ValueError):
                    pass

            policy.lockout_duration_seconds = _interval_to_seconds(
                attrs.get("lockoutDuration")
            )
            policy.observation_window_seconds = _interval_to_seconds(
                attrs.get("lockoutObservationWindow")
            )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(f"[spray_policy] Failed to fetch domain policy: {exc}")
    return policy


async def _fetch_pso_objects(
    conn: Any,
    domain_nc: str,
) -> dict[str, PSOPolicy]:
    """Fetch all PSO objects from the Password Settings Container."""
    pso_container = f"CN=Password Settings Container,CN=System,{domain_nc}"
    pso_by_dn: dict[str, PSOPolicy] = {}
    try:
        async for entry, err in conn.pagedsearch(
            query=_PSO_FILTER,
            attributes=_PSO_ATTRS,
            tree=pso_container,
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] PSO search error: {err}")
                continue
            attrs = entry.get("attributes", {})
            dn = str(entry.get("objectName") or attrs.get("distinguishedName") or "")
            name = str(attrs.get("name") or "")
            threshold_raw = attrs.get("msDS-LockoutThreshold")
            threshold: int | None = None
            if threshold_raw is not None:
                try:
                    threshold = int(threshold_raw)
                except (TypeError, ValueError):
                    pass
            precedence_raw = attrs.get("msDS-PasswordSettingsPrecedence")
            precedence = int(precedence_raw) if precedence_raw is not None else 0
            pso = PSOPolicy(name=name, dn=dn, lockout_threshold=threshold, precedence=precedence)
            pso_by_dn[dn.lower()] = pso
    except Exception as exc:  # noqa: BLE001
        # PSO container may not exist on basic AD — non-fatal
        print_info_debug(f"[spray_policy] PSO fetch skipped or failed: {exc}")
    return pso_by_dn


async def _fetch_user_badpwdcounts(
    conn: Any,
    domain_nc: str,
    *,
    include_pso: bool = True,
) -> tuple[dict[str, int], dict[str, str]]:
    """Fetch badPwdCount and resultant PSO DN for all enabled user accounts.

    Returns:
        (badpwd_by_user, pso_dn_by_user) — both keyed by lowercase sAMAccountName.
    """
    attrs = list(_USER_SPRAY_ATTRS)
    if not include_pso and "msDS-ResultantPSO" in attrs:
        attrs.remove("msDS-ResultantPSO")

    badpwd_by_user: dict[str, int] = {}
    pso_dn_by_user: dict[str, str] = {}

    try:
        async for entry, err in conn.pagedsearch(
            query=_USER_ONLY_FILTER,
            attributes=attrs,
            tree=domain_nc,
        ):
            if err is not None:
                print_warning_debug(f"[spray_policy] user search error: {err}")
                continue
            attrs_data = entry.get("attributes", {})
            sam = str(attrs_data.get("sAMAccountName") or "").strip()
            if not sam:
                continue
            sam_lower = sam.lower()
            bad_raw = attrs_data.get("badPwdCount")
            if bad_raw is not None:
                try:
                    badpwd_by_user[sam_lower] = int(bad_raw)
                except (TypeError, ValueError):
                    pass
            pso_dn_raw = attrs_data.get("msDS-ResultantPSO")
            if pso_dn_raw:
                pso_dn_by_user[sam_lower] = str(pso_dn_raw)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_warning_debug(f"[spray_policy] Failed to fetch user badPwdCounts: {exc}")

    return badpwd_by_user, pso_dn_by_user


async def fetch_spray_policy_native(
    *,
    domain: str,
    dc_ip: str,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    kerberos_target_hostname: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
) -> SprayPolicyResult:
    """Fetch domain password policy + per-user badPwdCount via native LDAP.

    Returns a SprayPolicyResult with all available data. Non-fatal errors
    are collected in result.fetch_errors so callers can decide whether to
    fall back to NetExec.

    Args:
        domain: Target domain (DNS name).
        dc_ip: Domain controller IP.
        username: Authenticating username (or None for anonymous/Kerberos).
        password: Authenticating password.
        use_kerberos: Use Kerberos ticket auth instead of password.
        kerberos_target_hostname: Target DC FQDN for the LDAP service SPN.
        auth_domain: Authenticating domain when different from target.
        auth_kdc: Auth KDC IP for cross-realm scenarios.

    Returns:
        SprayPolicyResult (partial results on error).
    """
    result = SprayPolicyResult()
    try:
        config = ADscanLDAPConfig(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_ldaps=True,
            use_kerberos=use_kerberos,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=auth_domain or domain,
            auth_kdc=auth_kdc,
        )
        conn, _used_ldaps = await async_connect_with_ldap_fallback(config)

        # Derive domain naming context
        server_info = getattr(conn, "_serverinfo", None) or {}
        domain_nc = (
            server_info.get("defaultNamingContext")
            or ",".join(f"DC={part}" for part in domain.split("."))
        )

        # Fetch policy and users concurrently
        policy, pso_by_dn, (badpwd_by_user, pso_dn_by_user) = await asyncio.gather(
            _fetch_domain_policy(conn, domain_nc),
            _fetch_pso_objects(conn, domain_nc),
            _fetch_user_badpwdcounts(conn, domain_nc, include_pso=True),
        )

        result.default_policy = policy
        result.pso_by_dn = pso_by_dn
        result.badpwd_by_user = badpwd_by_user
        result.pso_dn_by_user = pso_dn_by_user

        print_info_debug(
            f"[spray_policy] fetched: threshold={policy.lockout_threshold}, "
            f"pso_count={len(pso_by_dn)}, users={len(badpwd_by_user)}, "
            f"pso_assigned_users={len(pso_dn_by_user)}"
        )

        try:
            if hasattr(conn, "disconnect"):
                await conn.disconnect()
        except Exception:  # noqa: BLE001
            pass

    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        msg = f"Native policy fetch failed: {exc}"
        result.fetch_errors.append(msg)
        print_warning_debug(f"[spray_policy] {msg}")

    return result


def fetch_spray_policy_sync(
    *,
    domain: str,
    dc_ip: str,
    username: str | None = None,
    password: str | None = None,
    use_kerberos: bool = False,
    kerberos_target_hostname: str | None = None,
    auth_domain: str | None = None,
    auth_kdc: str | None = None,
) -> SprayPolicyResult:
    """Synchronous wrapper around fetch_spray_policy_native."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    lambda: asyncio.run(
                        fetch_spray_policy_native(
                            domain=domain,
                            dc_ip=dc_ip,
                            username=username,
                            password=password,
                            use_kerberos=use_kerberos,
                            kerberos_target_hostname=kerberos_target_hostname,
                            auth_domain=auth_domain,
                            auth_kdc=auth_kdc,
                        )
                    )
                )
                return future.result(timeout=30)
    except RuntimeError:
        pass

    return asyncio.run(
        fetch_spray_policy_native(
            domain=domain,
            dc_ip=dc_ip,
            username=username,
            password=password,
            use_kerberos=use_kerberos,
            kerberos_target_hostname=kerberos_target_hostname,
            auth_domain=auth_domain,
            auth_kdc=auth_kdc,
        )
    )
