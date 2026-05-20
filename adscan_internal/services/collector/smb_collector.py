"""Native async SMB collector for ADscan.

Collects per-host SMB posture and session/admin relationships via aiosmb:

  * SMB negotiate (unauthenticated) → signing_required, signing_enabled, dialect
  * SRVSVC NetSessEnum            → HasSession edges (Computer → User)
  * SAMR Builtin\\Administrators   → AdminTo edges   (User/Group → Computer)

All Computer nodes in the CollectionResult are processed concurrently up to
``concurrency`` simultaneous connections.  IP resolution is expected to have
already been done by ``dns_resolver.resolve_computer_nodes`` — the collector
falls back to ``dnshostname`` for hosts where no ``ip_address`` was stored.
"""

from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink

from adscan_internal import print_info_debug


# ---------------------------------------------------------------------------
# SMB config for the collector
# ---------------------------------------------------------------------------


@dataclass
class SMBCollectorConfig:
    """Credentials + options for the SMB collection phase."""

    domain: str
    auth_domain: str
    dc_address: str
    username: str | None = None
    password: str | None = None
    nt_hash: str | None = None
    aes_key: str | None = None
    ccache_path: str | None = None
    use_kerberos: bool = False
    kdc_ip: str | None = None
    port: int = 445
    per_host_timeout: int = 15
    concurrency: int = 20
    posture_sink: Optional["PostureSink"] = None
    posture_snapshot: Optional["DomainPosture"] = None


# ---------------------------------------------------------------------------
# Per-host collection helpers
# ---------------------------------------------------------------------------


_SMB1_NEGOTIATE_REQUEST = bytes([
    # NetBIOS Session Service: type=0x00, length=47 (3 bytes big-endian)
    0x00, 0x00, 0x00, 0x2F,
    # SMBv1 header (32 bytes)
    0xFF, 0x53, 0x4D, 0x42,  # Magic: \xFFSMB
    0x72,                    # Command: NEGOTIATE_PROTOCOL
    0x00, 0x00, 0x00, 0x00,  # NT Status: Success
    0x18,                    # Flags: canonical, case-insensitive
    0x01, 0xC8,              # Flags2
    0x00, 0x00,              # PID High
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # Signature (8 bytes)
    0x00, 0x00,              # Reserved
    0xFF, 0xFF,              # Tree ID
    0xFE, 0xFF,              # Process ID
    0x00, 0x00,              # User ID
    0x20, 0x00,              # Multiplex ID
    # Parameter block
    0x00,                    # WordCount = 0
    # Data block
    0x0C, 0x00,              # ByteCount = 12
    # Dialect: "NT LM 0.12\0"
    0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00,
])


async def smb1_probe(ip: str, port: int = 445, timeout: float = 3.0) -> bool:
    """Return True if the host responds positively to a raw SMBv1 negotiate.

    Sends a minimal NT LM 0.12 negotiate packet and checks whether the server
    returns a valid SMBv1 response (\\xFFSMB magic with status 0x00000000).
    This is the same probe NXC uses for its SMBv1 detection.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        try:
            writer.write(_SMB1_NEGOTIATE_REQUEST)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            # Read NetBIOS header (4 bytes) to get body length
            header = await asyncio.wait_for(reader.readexactly(4), timeout=timeout)
            body_len = struct.unpack(">I", header)[0] & 0x00FFFFFF
            if body_len < 4:
                return False
            body = await asyncio.wait_for(
                reader.readexactly(min(body_len, 256)), timeout=timeout
            )
            # SMBv1 success: magic \xFFSMB + NT Status 0x00000000
            return (
                len(body) >= 9
                and body[:4] == b"\xff\x53\x4d\x42"
                and body[5:9] == b"\x00\x00\x00\x00"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception:
        return False


async def negotiate_only(ip: str, port: int, timeout: int) -> dict[str, Any]:
    """Return SMB signing posture via an unauthenticated negotiate exchange."""
    try:
        from aiosmb.commons.connection.factory import SMBConnectionFactory
        from aiosmb.protocol.smb2.commands.negotiate import NegotiateDialects
    except ImportError:
        return {}

    url = f"smb+ntlm-password://WORKGROUP\\guest:@{ip}:{port}"
    try:
        factory = SMBConnectionFactory.from_url(url)
        conn = factory.get_connection()
        # WILDCARD excluded intentionally: when protocol_test=True aiosmb sends
        # only ['NT LM 0.12'] if WILDCARD is present, returning an SMBMessage
        # (v1) that has no DialectRevision and may report incorrect v2 signing.
        # SMBv1 detection is handled by the separate smb1_probe() below.
        dialects = [
            NegotiateDialects.SMB202,
            NegotiateDialects.SMB210,
            NegotiateDialects.SMB300,
            NegotiateDialects.SMB302,
            NegotiateDialects.SMB311,
        ]
        (sign_negotiate, sign_en, sign_req, rply, err), smb_v1 = await asyncio.gather(
            asyncio.wait_for(conn.protocol_test(dialects), timeout=timeout),
            smb1_probe(ip, port, timeout=min(timeout, 5)),
        )
        if err is not None:
            return {}
        dialect_val = None
        try:
            dr = getattr(getattr(rply, "command", None), "DialectRevision", None)
            if dr is not None:
                # NegotiateDialects is an enum — .name gives "SMB311", "SMB202", etc.
                dialect_val = getattr(dr, "name", str(dr))
        except Exception:
            pass
        return {
            "smb_signing_enabled": bool(sign_en),
            "smb_signing_required": bool(sign_req),
            "smb_dialect": dialect_val,
            "smb_v1": smb_v1,
        }
    except Exception:
        return {}


async def collect_sessions(machine: Any) -> list[tuple[str, str]]:
    """Return list of (username, ip_addr) active sessions via SRVSVC."""
    sessions: list[tuple[str, str]] = []
    try:
        async for sess, err in machine.list_sessions(level=10):
            if err is not None:
                break
            if sess is not None:
                uname = str(getattr(sess, "username", "") or "").strip()
                ip = str(getattr(sess, "ip_addr", "") or "").strip()
                if uname and not uname.startswith("\\"):
                    sessions.append((uname, ip))
    except Exception as exc:
        print_info_debug(f"[smb-collector] sessions error: {exc}")
    return sessions


# BUILTIN group RIDs relevant for attack paths
_BUILTIN_GROUPS: dict[int, str] = {
    544: "AdminTo",  # BUILTIN\Administrators
    555: "CanRDP",  # BUILTIN\Remote Desktop Users
    580: "CanPSRemote",  # BUILTIN\Remote Management Users
}


async def collect_builtin_group_members(machine: Any) -> dict[str, list[str]]:
    """Return {relation: [sid, ...]} for all three BUILTIN groups via the consolidated SAMR service."""
    from adscan_internal.services.native_samr_service import enumerate_alias_members_via

    result: dict[str, list[str]] = {rel: [] for rel in _BUILTIN_GROUPS.values()}
    members_by_rid, status, err = await enumerate_alias_members_via(
        machine, builtin_alias_rids=list(_BUILTIN_GROUPS.keys())
    )
    if status != "done":
        print_info_debug(f"[smb-collector] BUILTIN groups: status={status} err={err}")
        # Fall through — partial members per RID may still be present.
    for rid, relation in _BUILTIN_GROUPS.items():
        result[relation] = [m.sid for m in members_by_rid.get(rid, [])]
    return result


# ---------------------------------------------------------------------------
# Domain-level collection helpers
# ---------------------------------------------------------------------------


def resolve_target_ip(node: Any) -> str | None:
    """Return the IP to connect to for a Computer node."""
    ip = str(node.properties.get("ip_address") or "").strip()
    if ip:
        return ip
    dns = str(node.properties.get("dnshostname") or "").strip()
    if dns:
        return dns
    return None


def resolve_target_hostname(node: Any) -> str | None:
    """Return the Kerberos SPN hostname for a Computer node, when known."""
    dns = str(node.properties.get("dnshostname") or "").strip()
    if dns:
        return dns
    name = str(getattr(node, "name", "") or "").strip().rstrip("$")
    domain = str(getattr(node, "domain", "") or "").strip()
    if name and domain and "." not in name:
        return f"{name}.{domain}".lower()
    if name and "." in name:
        return name
    return None


def sid_to_object_id(sid_str: str) -> str:
    """Normalise a SID string to upper-case object ID key."""
    return sid_str.strip().upper()
