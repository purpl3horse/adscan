"""Network discovery helpers for ADscan.

This module centralises small, reusable pieces of network discovery logic that
were previously embedded in the monolithic ``adscan.py`` shell implementation.

The goal is to keep the heavy lifting here so CLI/interactive code can remain
thin wrappers while still preserving legacy behaviour.
"""

from __future__ import annotations

from typing import Protocol
import re
import secrets
import shlex
import socket
import struct
import time

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_exception,
    print_info_debug,
    print_info_verbose,
)
from adscan_internal.services.async_bridge import run_async_sync


class NetworkDiscoveryHost(Protocol):
    """Host interface required by the network discovery helpers."""

    def run_command(self, command: str, **kwargs):  # noqa: ANN001
        ...

    netexec_path: str | None


_BANNER_DOMAIN_PATTERN = re.compile(r"\(domain:(\S+?)\)", flags=re.IGNORECASE)
_BANNER_NAME_PATTERN = re.compile(r"\(name:(\S+?)\)", flags=re.IGNORECASE)


def _infer_domain_from_netexec_banner(
    host: NetworkDiscoveryHost,
    *,
    protocol: str,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
    auth_args: str = "",
) -> tuple[str | None, str | None]:
    """Infer a domain from a NetExec protocol banner.

    Args:
        host: Object providing ``run_command`` and optionally ``netexec_path``.
        protocol: NetExec protocol to probe (for example ``smb`` or ``ldap``).
        target_ip: Target host IP address (DC/DNS candidate).
        timeout_seconds: Max time allowed for the NetExec probe.
        attempts: Number of retries when the probe returns no banner.
        retry_delay_seconds: Delay between retries.
        auth_args: Optional additional CLI arguments for NetExec.

    Returns:
        Tuple of ``(domain_fqdn, hostname)``. Values are ``None`` when inference
        fails.
    """
    try:
        netexec_path = getattr(host, "netexec_path", None)
        if not netexec_path:
            return None, None

        ip_clean = (target_ip or "").strip()
        if not ip_clean:
            return None, None

        auth_suffix = f" {auth_args.strip()}" if auth_args.strip() else ""
        cmd = (
            f"{shlex.quote(netexec_path)} {shlex.quote(protocol)} "
            f"{shlex.quote(ip_clean)}{auth_suffix}"
        )

        last_hostname: str | None = None
        protocol_label = protocol.lower()
        for attempt in range(1, max(attempts, 1) + 1):
            proc = host.run_command(
                cmd,
                timeout=timeout_seconds,
                ignore_errors=True,
                allow_timeout_recovery=False,
            )
            if not proc:
                if attempt < attempts:
                    marked_ip = mark_sensitive(ip_clean, "ip")
                    print_info_debug(
                        f"[{protocol_label}_infer] NetExec returned no result for "
                        f"{marked_ip}; retrying ({attempt}/{attempts})"
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, None

            stdout = (getattr(proc, "stdout", "") or "").strip()
            stderr = (getattr(proc, "stderr", "") or "").strip()
            combined = stdout or stderr
            if not combined:
                if attempt < attempts:
                    print_info_debug(
                        f"[{protocol_label}_infer] Empty {protocol_label.upper()} "
                        f"banner output; retrying ({attempt}/{attempts})"
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, None

            if getattr(proc, "returncode", 0) != 0:
                marked_ip = mark_sensitive(ip_clean, "ip")
                print_info_debug(
                    f"[{protocol_label}_infer] NetExec returned non-zero exit code "
                    f"for {marked_ip}, attempting to parse output anyway."
                )

            domain_matches = _BANNER_DOMAIN_PATTERN.findall(combined)
            name_matches = _BANNER_NAME_PATTERN.findall(combined)
            hostname = name_matches[0].strip().rstrip(".") if name_matches else None
            last_hostname = hostname or last_hostname

            domain = domain_matches[0].strip().rstrip(".") if domain_matches else None
            if not domain:
                if (
                    "first time use detected" in stdout.lower()
                    or "creating home directory structure" in stdout.lower()
                    or "copying default configuration file" in stdout.lower()
                ) and attempt < attempts:
                    print_info_debug(
                        f"[{protocol_label}_infer] NetExec initialization detected; "
                        f"retrying {protocol_label.upper()} banner."
                    )
                    time.sleep(retry_delay_seconds)
                    continue
                return None, hostname

            domain_norm = domain.strip().lower()
            if domain_norm in {"workgroup", "unknown"}:
                return None, hostname

            if "." not in domain_norm:
                return None, hostname

            return domain_norm, hostname

        return None, last_hostname
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_exception(show_locals=False, exception=exc)
        return None, None


def _nc_to_fqdn(nc: str) -> str | None:
    """Convert an LDAP distinguishedName base to a dotted FQDN.

    ``"DC=ais,DC=local"``  →  ``"ais.local"``
    Returns ``None`` when *nc* contains no DC components.
    """
    parts = [
        seg[3:]
        for seg in nc.replace(" ", "").split(",")
        if seg[:3].upper() == "DC=" and seg[3:]
    ]
    return ".".join(parts).lower() if parts else None


async def _infer_domain_from_ldap_native(
    dc_ip: str,
    *,
    timeout: int = 8,
) -> tuple[str | None, str | None]:
    """Infer domain FQDN and hostname from an anonymous LDAP rootDSE read.

    Tries LDAPS (636) first, then plain LDAP (389). Reads ``defaultNamingContext``
    for the domain and ``dnsHostName`` for the hostname — both attributes are
    always returned in the rootDSE from Windows DCs, even with anonymous access.

    Returns ``(domain_fqdn, hostname)`` or ``(None, None)`` on failure.

    This replaces the ``nxc ldap -u '' -p ''`` subprocess call for the common
    case. The nxc path in ``infer_domain_from_ldap_banner`` is retained as a
    fallback for environments where LDAP is firewalled on both 389 and 636.
    """
    try:
        from adscan_internal.services.ldap_transport_service import (
            async_anonymous_ldap_connection,
        )
    except ImportError:
        return None, None

    try:
        # Centralized anonymous SIMPLE-bind with LDAPS->LDAP fallback. badldap
        # fetches the rootDSE attributes during connect, so the bound client's
        # _serverinfo already carries defaultNamingContext + dnsHostName — no
        # explicit search is needed.
        async with async_anonymous_ldap_connection(
            dc_ip, timeout=timeout
        ) as (client, used_ldaps):
            server_info: dict | None = None
            if hasattr(client, "get_server_info"):
                server_info = client.get_server_info()
            if not isinstance(server_info, dict):
                server_info = getattr(client, "_serverinfo", None)
            if not isinstance(server_info, dict):
                return None, None

            # defaultNamingContext → "DC=ais,DC=local" → "ais.local"
            raw_nc = server_info.get("defaultNamingContext")
            if not raw_nc:
                raw_nc = (server_info.get("namingContexts") or [None])[0]
            nc_str = str(raw_nc[0] if isinstance(raw_nc, list) else raw_nc).strip() if raw_nc else ""
            domain = _nc_to_fqdn(nc_str) if nc_str else None

            # dnsHostName → "dc01.ais.local"
            raw_host = server_info.get("dnsHostName")
            hostname: str | None = None
            if raw_host:
                hostname = str(raw_host[0] if isinstance(raw_host, list) else raw_host).strip() or None

            if domain:
                transport = "LDAPS" if used_ldaps else "LDAP"
                print_info_debug(
                    f"[ldap_infer] native rootDSE ({transport} {dc_ip}): "
                    f"domain={mark_sensitive(domain, 'domain')} "
                    f"host={mark_sensitive(hostname or 'N/A', 'hostname')}"
                )
                return domain, hostname
            return None, None
    except Exception as exc:  # noqa: BLE001
        print_info_debug(f"[ldap_infer] native LDAP anonymous probe failed: {exc}")
        return None, None


def infer_domain_from_smb_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) from NetExec SMB banner output against a target IP.

    This is used as a best-effort fallback when DNS (PTR/SRV) is unavailable but
    SMB is reachable and NetExec can fingerprint the remote host.

    Args:
        host: Object providing ``run_command`` and optionally ``netexec_path``.
        target_ip: Target host IP address (DC/DNS candidate).
        timeout_seconds: Max time allowed for the NetExec probe.

    Returns:
        Tuple of (domain_fqdn, hostname). Values are ``None`` when inference fails.
    """
    return _infer_domain_from_netexec_banner(
        host,
        protocol="smb",
        target_ip=target_ip,
        timeout_seconds=timeout_seconds,
        attempts=attempts,
        retry_delay_seconds=retry_delay_seconds,
    )


def infer_domain_from_ldap_banner(
    host: NetworkDiscoveryHost,
    *,
    target_ip: str,
    timeout_seconds: int = 60,
    attempts: int = 3,
    retry_delay_seconds: float = 1.0,
) -> tuple[str | None, str | None]:
    """Infer a domain (FQDN) and DC hostname from a target IP via LDAP.

    Tries an anonymous rootDSE read (native, no subprocess) first — this
    covers >99% of DCs where port 389 or 636 is reachable. Falls back to
    the nxc subprocess path only when the native probe fails (e.g. both LDAP
    ports blocked by firewall, or badldap import unavailable).

    Returns ``(domain_fqdn, hostname)`` or ``(None, None)`` when both paths fail.
    """
    ip_clean = (target_ip or "").strip()
    if not ip_clean:
        return None, None

    # Native path — anonymous LDAP bind → rootDSE (defaultNamingContext + dnsHostName).
    # Uses a short timeout (≤8s) so it fails fast when LDAP is not available.
    native_timeout = min(timeout_seconds, 8)
    try:
        domain, hostname = run_async_sync(
            _infer_domain_from_ldap_native(ip_clean, timeout=native_timeout)
        )
        if domain:
            return domain, hostname
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[ldap_infer] native path raised unexpectedly: {exc}")

    # Subprocess fallback — nxc ldap, used when native probe cannot connect
    # (both 389 and 636 firewalled, or badldap import unavailable in this env).
    print_info_debug(
        f"[ldap_infer] native LDAP probe returned no domain for "
        f"{mark_sensitive(ip_clean, 'ip')}; falling back to nxc"
    )
    return _infer_domain_from_netexec_banner(
        host,
        protocol="ldap",
        target_ip=ip_clean,
        timeout_seconds=timeout_seconds,
        attempts=attempts,
        retry_delay_seconds=retry_delay_seconds,
        auth_args="-u '' -p ''",
    )


def _encode_nbns_name(name: str = "*") -> bytes:
    """Encode a NetBIOS name in the wire format used by NBNS (RFC 1002).

    The wildcard ``*`` is used for NBSTAT (node status) queries: it's padded
    with NULs to 16 bytes and each nibble is encoded as an ASCII letter
    ('A'..'P'), producing a 32-byte label prefixed with 0x20 and terminated
    with 0x00.
    """
    raw = name.encode("ascii")[:16].ljust(16, b"\x00")
    encoded = bytearray()
    for byte in raw:
        encoded.append(0x41 + (byte >> 4))
        encoded.append(0x41 + (byte & 0x0F))
    return bytes([0x20]) + bytes(encoded) + b"\x00"


def _query_netbios_name_native(
    target_ip: str,
    *,
    timeout: float = 3.0,
    retries: int = 2,
) -> str | None:
    """Query the NetBIOS workgroup/domain name of a host via NBSTAT (UDP/137).

    This replaces the legacy ``nmblookup -A`` subprocess with a self-contained
    UDP query. Returns the NetBIOS domain/workgroup name (suffix 0x00 with the
    group bit set), or ``None`` if the host does not respond or no group name
    is reported.
    """
    target = (target_ip or "").strip()
    if not target:
        return None

    txn_id = secrets.randbits(16)
    header = struct.pack(">HHHHHH", txn_id, 0x0000, 1, 0, 0, 0)
    question = _encode_nbns_name("*") + struct.pack(">HH", 0x0021, 0x0001)
    packet = header + question

    last_exc: Exception | None = None
    for _ in range(max(retries, 1)):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.settimeout(timeout)
            sock.sendto(packet, (target, 137))
            data, _ = sock.recvfrom(4096)
        except (socket.timeout, OSError) as exc:
            last_exc = exc
            continue
        finally:
            sock.close()

        # Skip 12-byte header + question (encoded name 34 bytes + qtype 2 + qclass 2)
        offset = 12 + 34 + 4
        # Answer: name (compressed pointer 2B or full 34B), type(2), class(2), ttl(4), rdlength(2)
        if offset >= len(data):
            continue
        if data[offset] & 0xC0:
            offset += 2
        else:
            offset += 34
        offset += 2 + 2 + 4 + 2  # type, class, ttl, rdlength
        if offset >= len(data):
            continue
        num_names = data[offset]
        offset += 1

        for _ in range(num_names):
            if offset + 18 > len(data):
                break
            name_bytes = data[offset:offset + 15].rstrip(b" \x00")
            suffix = data[offset + 15]
            flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
            offset += 18
            # Domain/workgroup: suffix 0x00 with group bit set (0x8000)
            if suffix == 0x00 and (flags & 0x8000):
                try:
                    return name_bytes.decode("ascii", errors="replace").strip()
                except Exception:  # noqa: BLE001
                    return None
        return None

    if last_exc is not None:
        print_info_debug(f"NBSTAT query to {mark_sensitive(target, 'ip')} failed: {last_exc}")
    return None


def extract_netbios(
    host: NetworkDiscoveryHost,
    domain: str,
    *,
    dc_ip: str | None = None,
) -> str | None:
    """Extract the NetBIOS name for a domain using a native NBSTAT (UDP/137) query.

    Resolution order:
    1. Native NBSTAT query against the DC IP (``dc_ip`` argument, or
       ``host.pdc`` / first entry of ``host.dcs`` as fallback).
    2. First label of the FQDN, upper-cased.

    Args:
        host: Object providing host context (``pdc`` / ``dcs`` attributes).
        domain: Domain name from which to derive NetBIOS.
        dc_ip: Optional explicit DC IP to query.

    Returns:
        The extracted or derived NetBIOS name, or ``None`` on unrecoverable error.
    """
    try:
        marked_domain = mark_sensitive(domain, "domain")
        domain_clean = (domain or "").strip()
        if not domain_clean:
            return None

        ip_candidate = (dc_ip or "").strip() or (getattr(host, "pdc", "") or "").strip()
        if not ip_candidate:
            dcs = getattr(host, "dcs", None) or []
            if dcs:
                ip_candidate = (dcs[0] or "").strip()

        if ip_candidate:
            netbios = _query_netbios_name_native(ip_candidate)
            if netbios:
                return netbios
            print_info_debug(
                f"NBSTAT did not return a domain/workgroup name for {mark_sensitive(ip_candidate, 'ip')}."
            )
        else:
            print_info_debug("No DC IP available for NBSTAT query; falling back to FQDN label.")

        netbios_default = domain_clean.split(".")[0].upper()
        marked_netbios_default = mark_sensitive(netbios_default, "domain")
        print_info_verbose(
            f"Could not extract NetBIOS from domain {marked_domain}, using {marked_netbios_default} as default."
        )
        return netbios_default
    except Exception as exc:  # noqa: BLE001 - preserve legacy catch-all semantics
        telemetry.capture_exception(exc)
        print_error("Error extracting NetBIOS.")
        print_exception(show_locals=False, exception=exc)
        return None
