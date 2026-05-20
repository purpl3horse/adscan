"""AD servicePrincipalName write primitives.

Adds or removes SPNs on AD accounts via LDAP modify on the
servicePrincipalName attribute. Reusable for:
  - ESC8 Kerberos relay (register http/relay-host SPN on CA machine account)
  - RBCD setup (future)
  - Any workflow needing SPN manipulation

Uses ADscanLDAPConnection (LDAPS→LDAP fallback).
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import AsyncIterator

from adscan_core import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info_debug,
    print_success,
    print_warning,
)
from adscan_internal.services.ldap_transport_service import (
    ADscanLDAPConfig,
    ADscanLDAPConnection,
)


@dataclass(frozen=True)
class ADSPNConfig:
    """Connection config for SPN write operations."""

    dc_ip: str
    domain: str
    username: str
    password: str


def _ldap_cfg(config: ADSPNConfig) -> ADscanLDAPConfig:
    return ADscanLDAPConfig(
        domain=config.domain,
        dc_ip=config.dc_ip,
        use_ldaps=True,
        use_kerberos=False,
        username=config.username,
        password=config.password,
    )


def _resolve_account_dn(config: ADSPNConfig, samaccountname: str) -> str | None:
    """Return the DN for a sAMAccountName. Raises on connection failure."""
    with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
        conn.search(
            search_base=conn.domain_dn,
            search_filter=f"(sAMAccountName={samaccountname})",
            attributes=["distinguishedName", "servicePrincipalName"],
        )
        if not conn.entries:
            return None
        return str(conn.entries[0].dn)


def _modify_spn_sync(
    config: ADSPNConfig,
    spn: str,
    target_samname: str,
    add: bool,
) -> tuple[bool, str | None]:
    """Add or remove an SPN on target_samname. Returns (ok, error).

    Strategy (in order):
    1. Direct write to servicePrincipalName (requires GenericWrite / WriteSPN).
    2. Fallback: write the hostname portion to msDS-AdditionalDnsHostName
       (requires Validated Write — available to more principals).
       When this attribute is populated, AD auto-registers the corresponding SPNs.
    """
    try:
        with ADscanLDAPConnection(_ldap_cfg(config)) as conn:
            conn.search(
                search_base=conn.domain_dn,
                search_filter=f"(sAMAccountName={target_samname})",
                attributes=["distinguishedName", "servicePrincipalName"],
            )
            if not conn.entries:
                return False, f"account {target_samname!r} not found in LDAP"
            target_dn = str(conn.entries[0].dn)
            op = "add" if add else "delete"

            # Attempt 1: direct servicePrincipalName write
            ok = conn.modify(target_dn, {"servicePrincipalName": [(op, [spn])]})
            if ok:
                action = "added" if add else "removed"
                print_info_debug(
                    f"ADSPN: {action} SPN {spn!r} on {target_samname!r} "
                    f"(via servicePrincipalName)"
                )
                return True, None

            # Attempt 2: msDS-AdditionalDnsHostName (Validated Write)
            # Strip the service class prefix (e.g. "http/host.domain" → "host.domain")
            hostname_part = spn.split("/", 1)[1] if "/" in spn else spn
            ok2 = conn.modify(
                target_dn,
                {"msDS-AdditionalDnsHostName": [(op, [hostname_part])]},
            )
            if ok2:
                action = "added" if add else "removed"
                print_info_debug(
                    f"ADSPN: {action} hostname {hostname_part!r} on {target_samname!r} "
                    f"(via msDS-AdditionalDnsHostName — SPNs auto-registered)"
                )
                return True, None

            return False, f"LDAP modify failed for {target_dn} (tried servicePrincipalName + msDS-AdditionalDnsHostName)"
    except Exception as exc:
        telemetry.capture_exception(exc)
        return False, str(exc)


async def adspn_add(config: ADSPNConfig, spn: str, target_samname: str) -> bool:
    ok, err = await asyncio.to_thread(_modify_spn_sync, config, spn, target_samname, True)
    if not ok:
        print_error(f"ADSPN: failed to add SPN {spn!r} on {target_samname!r}: {err}")
    return ok


async def adspn_remove(config: ADSPNConfig, spn: str, target_samname: str) -> bool:
    ok, err = await asyncio.to_thread(_modify_spn_sync, config, spn, target_samname, False)
    if not ok:
        print_warning(
            f"ADSPN: failed to remove SPN {spn!r} from {target_samname!r} — "
            f"manual cleanup required: {err}"
        )
    return ok


@contextlib.asynccontextmanager
async def adspn_scope(
    config: ADSPNConfig,
    spn: str,
    target_samname: str,
) -> AsyncIterator[str]:
    """RAII context: add SPN on enter, remove on exit (even on exception)."""
    added = await adspn_add(config, spn, target_samname)
    if not added:
        raise RuntimeError(
            f"ADSPN: could not add SPN {spn!r} on {target_samname!r} — "
            "check write permissions (GenericWrite / WriteSPN on the account)"
        )
    print_success(
        f"ADSPN: registered SPN {mark_sensitive(spn, 'text')} "
        f"on {mark_sensitive(target_samname, 'user')}"
    )
    try:
        yield spn
    finally:
        removed = await adspn_remove(config, spn, target_samname)
        if removed:
            print_success(
                f"ADSPN: removed SPN {mark_sensitive(spn, 'text')} "
                f"from {mark_sensitive(target_samname, 'user')}"
            )
        else:
            print_warning(
                f"ADSPN: could not remove SPN {spn!r} from {target_samname!r} — "
                f"manual cleanup: modify servicePrincipalName on account DN"
            )
