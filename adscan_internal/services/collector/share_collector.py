"""Native async share collector for ADscan (Sub-C).

For each Computer node in the CollectionResult, enumerates SMB shares and
their security descriptors.  Creates graph edges:

  ReadShare    (principal → Computer)  — generic or file read/list rights
  WriteShare   (principal → Computer)  — generic or file write/create rights
  FullControlShare (principal → Computer) — generic all or file all access

Three-tier fallback for share SDs (same logic as ShareHound, ported to aiosmb):
  1. SRVSVC NetrShareGetInfo level 502 (requires admin)
  2. Remote Registry: HKLM\\SYSTEM\\...\\LanmanServer\\Shares\\Security\\<name>
  3. Root folder NTFS SD (connect to share, query root dir SD)

SID → graph node mapping uses the already-collected LDAP node set plus the
well-known SIDs injected by well_known_sids.py — no additional LSA RPC needed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional, TYPE_CHECKING

if TYPE_CHECKING:
    from adscan_internal.services.domain_posture import DomainPosture
    from adscan_internal.services.posture_sink import PostureSink

from adscan_internal import print_info_debug
from adscan_internal.services.smb_exclusion_policy import (
    is_globally_excluded_smb_share,
)

# ---------------------------------------------------------------------------
# Share SD access mask constants
# ---------------------------------------------------------------------------

_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_ALL = 0x10000000
_READ_CONTROL = 0x00020000
_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_FILE_READ_EA = 0x00000008
_FILE_WRITE_EA = 0x00000010
_FILE_EXECUTE = 0x00000020
_FILE_READ_ATTRIBUTES = 0x00000080
_FILE_WRITE_ATTRIBUTES = 0x00000100
_FILE_ALL_ACCESS = 0x001F01FF

_FILE_READ_BITS = (
    _READ_CONTROL | _FILE_READ_DATA | _FILE_READ_EA | _FILE_READ_ATTRIBUTES
)
_FILE_WRITE_BITS = (
    _FILE_WRITE_DATA | _FILE_APPEND_DATA | _FILE_WRITE_EA | _FILE_WRITE_ATTRIBUTES
)

# ACCESS_ALLOWED ACE type constant
_ACCESS_ALLOWED_ACE_TYPE = 0x00


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------


@dataclass
class ShareCollectorConfig:
    """Credentials + options for the share collection phase."""

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
    per_host_timeout: int = 20
    concurrency: int = 15
    skip_admin_shares: bool = True
    posture_sink: Optional["PostureSink"] = None
    posture_snapshot: Optional["DomainPosture"] = None


# ---------------------------------------------------------------------------
# SD parsing helper
# ---------------------------------------------------------------------------


def parse_sd_aces(sd_bytes: bytes) -> list[tuple[str, int]]:
    """Parse a raw security descriptor and return (sid_str, mask) for ALLOW ACEs.

    Compatible with the impacket version in the ADscan runtime which exposes
    DACL ACEs via ``dacl.aces`` (list of ACE objects) rather than
    ``dacl["Data"]`` (older impacket API).
    """
    try:
        from impacket.ldap import ldaptypes

        sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
        sd.fromString(sd_bytes)
        dacl = sd["Dacl"]
        if dacl is None:
            return []

        # Runtime impacket: dacl.aces is a list of ACE objects
        ace_list = getattr(dacl, "aces", None)
        if ace_list is None:
            # Older impacket fallback
            ace_list = dacl.get("Data") or []

        result = []
        for ace in ace_list:
            type_name = str(
                ace.fields.get("TypeName") or ace.fields.get("AceType") or ""
            )
            if "ALLOWED" not in type_name.upper() and type_name != "0":
                # Skip non-allow ACEs; also accept raw type 0 (ACCESS_ALLOWED)
                if ace.fields.get("AceType", -1) != _ACCESS_ALLOWED_ACE_TYPE:
                    continue

            try:
                sid_str = ace["Ace"]["Sid"].formatCanonical()
                mask_val = int(ace["Ace"]["Mask"]["Mask"])
            except (KeyError, TypeError, AttributeError):
                continue

            if sid_str and mask_val:
                result.append((sid_str, mask_val))
        return result
    except Exception as exc:
        print_info_debug(f"[share-collector] SD parse error: {exc}")
        return []


def mask_to_edge_kinds(mask: int) -> list[str]:
    """Map a share ACE mask to ADscan edge relation names."""
    kinds = []
    if mask & _GENERIC_ALL or (mask & _FILE_ALL_ACCESS) == _FILE_ALL_ACCESS:
        kinds.append("FullControlShare")
    else:
        if mask & (_GENERIC_READ | _FILE_READ_BITS):
            kinds.append("ReadShare")
        if mask & (
            _GENERIC_WRITE | _GENERIC_EXECUTE | _FILE_WRITE_BITS | _FILE_EXECUTE
        ):
            kinds.append("WriteShare")
    return kinds


# ---------------------------------------------------------------------------
# Share SD retrieval — three-tier fallback
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Per-host share collection — single SRVSVC session
# ---------------------------------------------------------------------------


@dataclass
class _ShareInfo:
    name: str
    share_type: int
    comment: str
    hidden: bool
    aces: list[tuple[str, int]] = field(default_factory=list)
    sd_source: str = "unavailable"


def _sd_object_to_bytes(sd_object: object) -> bytes:
    """Serialize a winacl security descriptor object returned by aiosmb."""
    if sd_object is None:
        return b""
    if isinstance(sd_object, bytes):
        return sd_object
    to_bytes = getattr(sd_object, "to_bytes", None)
    if callable(to_bytes):
        try:
            return bytes(to_bytes())
        except Exception:
            return b""
    return b""


def _build_unc_path(host: str, share: str, path: str = "") -> str:
    """Build a UNC path for aiosmb share-root operations."""
    clean_path = str(path or "").strip("\\")
    if clean_path:
        return f"\\\\{host}\\{share}\\{clean_path}"
    return f"\\\\{host}\\{share}"


async def read_share_root_sd(
    machine: Any,
    target_host: str,
    share_name: str,
) -> tuple[bytes, str]:
    """Read one share/root security descriptor using SMB2 QueryInfo fallbacks."""
    from aiosmb.commons.interfaces.directory import SMBDirectory
    from aiosmb.commons.interfaces.share import SMBShare

    last_error: Exception | None = None
    share = SMBShare(
        name=share_name,
        fullpath=_build_unc_path(target_host, share_name),
    )
    try:
        sd_object, err = await share.get_security_descriptor(machine.connection)
        if err is not None:
            raise err
        sd_bytes = _sd_object_to_bytes(sd_object)
        if sd_bytes:
            return sd_bytes, "smb2_share_root"
    except Exception as exc:
        last_error = exc

    for candidate_path in ("", "\\"):
        try:
            directory = SMBDirectory.from_uncpath(
                _build_unc_path(target_host, share_name, candidate_path)
            )
            sd_object, err = await directory.get_security_descriptor(machine.connection)
            if err is not None:
                raise err
            sd_bytes = _sd_object_to_bytes(sd_object)
            if sd_bytes:
                return sd_bytes, "smb2_path_root"
        except Exception as exc:
            last_error = exc

    if last_error is not None:
        raise last_error
    return b"", "unavailable"


async def fill_missing_share_sds(
    machine: Any,
    target_host: str,
    shares: list[_ShareInfo],
) -> dict[str, int]:
    """Populate missing share ACEs through low-privileged SMB2 root SD reads."""
    stats = {
        "attempted": 0,
        "succeeded": 0,
        "failed": 0,
        "aces": 0,
    }
    for share in shares:
        if share.aces:
            continue
        stats["attempted"] += 1
        try:
            sd_bytes, sd_source = await read_share_root_sd(
                machine, target_host, share.name
            )
        except Exception as exc:
            stats["failed"] += 1
            print_info_debug(
                "[share-collector] SMB2 root SD fallback failed: "
                f"host={target_host} share={share.name} error={exc}"
            )
            continue
        aces = parse_sd_aces(sd_bytes)
        if not aces:
            stats["failed"] += 1
            continue
        share.aces = aces
        share.sd_source = sd_source
        stats["succeeded"] += 1
        stats["aces"] += len(aces)
    return stats


async def collect_shares_for_host(
    machine: Any,
    config: ShareCollectorConfig,
    target_host: str,
) -> list[_ShareInfo]:
    """Enumerate shares and their SDs for a single connected host.

    Strategy: one SRVSVC session, try level 502 first (shares + SDs in one
    round-trip, admin only) then fall back to level 1 (names only, always
    works).  This avoids opening a second RPC pipe over the same connection.
    """
    from aiosmb.dcerpc.v5.interfaces.srvsmgr import srvsrpc_from_smb
    from aiosmb.dcerpc.v5 import srvs

    shares: list[_ShareInfo] = []

    try:
        async with srvsrpc_from_smb(machine.connection) as rpc:
            # ── Try level 502 (admin) — shares + SDs in one call ─────────
            got_502 = False
            try:
                resume = 0
                while True:
                    resp, err = await srvs.hNetrShareEnum(
                        rpc.dce, 502, resumeHandle=resume
                    )
                    if err is not None:
                        # Check if it's MORE_ENTRIES (0x00000105) — keep going
                        ec = getattr(err, "error_code", None)
                        if ec == 0x00000105:
                            resp = err.get_packet()
                        else:
                            raise err

                    container = resp["InfoStruct"]["ShareInfo"]["Level502"]["Buffer"]
                    for entry in container:
                        name = str(entry["shi502_netname"]).rstrip("\x00")
                        if not name:
                            continue
                        if config.skip_admin_shares and is_globally_excluded_smb_share(
                            name
                        ):
                            continue
                        stype = int(entry["shi502_type"] or 0)
                        remark = str(entry["shi502_remark"] or "").rstrip("\x00")
                        sd_raw = entry["shi502_security_descriptor"]
                        raw_bytes = b"".join(sd_raw) if sd_raw else b""
                        aces = parse_sd_aces(raw_bytes) if raw_bytes else []
                        shares.append(
                            _ShareInfo(
                                name=name,
                                share_type=stype,
                                comment=remark,
                                hidden=name.endswith("$"),
                                aces=aces,
                                sd_source="srvsvc502" if raw_bytes else "unavailable",
                            )
                        )

                    resume = resp["ResumeHandle"]
                    if resp["ErrorCode"] != 0x00000105:
                        break

                got_502 = True
            except Exception as exc:
                print_info_debug(
                    f"[share-collector] level 502 failed, falling back to level 1: {exc}"
                )

            # ── Fallback: level 1 (names only, no SDs) ───────────────────
            if not got_502:
                async for name, stype, remark, err in rpc.list_shares(level=1):
                    if err is not None:
                        break
                    if name is None:
                        continue
                    if config.skip_admin_shares and is_globally_excluded_smb_share(
                        name
                    ):
                        continue
                    shares.append(
                        _ShareInfo(
                            name=name,
                            share_type=int(stype or 0),
                            comment=str(remark or ""),
                            hidden=name.endswith("$"),
                        )
                    )

    except Exception as exc:
        print_info_debug(f"[share-collector] list_shares failed: {exc}")

    if shares and any(not share.aces for share in shares):
        stats = await fill_missing_share_sds(machine, target_host, shares)
        if stats["attempted"]:
            print_info_debug(
                "[share-collector] SMB2 root SD fallback: "
                f"host={target_host} attempted={stats['attempted']} "
                f"succeeded={stats['succeeded']} failed={stats['failed']} "
                f"aces={stats['aces']}"
            )

    return shares
