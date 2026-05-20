"""Native SMB share enumeration — replaces ``nxc smb --shares``.

Uses :func:`smb_machine_with_fallback` (posture-aware, auto Kerberos retry)
to drive ``SMBMachine.list_shares()`` and, for each non-IPC share,
``tree_connect()`` to read the per-share ``maximal_access`` bitmask. The
bitmask is the same value the SMB server would compute for a real
file-system access decision, so it gives a faithful READ/WRITE permission
view without any guess-and-probe semantics.

Public surface:

* :class:`NativeShareEntry`  — one share with translated permissions.
* :class:`NativeSharesResult` — list + status + error envelope.
* :func:`enumerate_shares_native` — async entry point.
* :func:`enumerate_shares_native_sync` — convenience for sync callers.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, List, Literal, Optional

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug

from adscan_internal.services.smb_transport import (
    SMBAuthError,
    SMBConfig,
    SMBConnectionError,
    SMBSigningRequiredError,
    smb_machine_with_fallback,
)


NativeSharesStatus = Literal["ok", "denied", "error", "partial"]


# Share type values returned by SRVSVC NetrShareEnum (STYPE_*)
_STYPE_BASE_MASK = 0x0FFFFFFF
_STYPE_NAMES = {
    0: "DISK",
    1: "PRINT",
    2: "DEVICE",
    3: "IPC",
}
_STYPE_SPECIAL = 0x80000000   # admin shares like C$, ADMIN$
_STYPE_TEMPORARY = 0x40000000


def _translate_share_type(stype: Any) -> str:
    """Map an SRVSVC share type bitmask to a short, human label."""
    try:
        raw = int(stype)
    except (TypeError, ValueError):
        return "UNKNOWN"
    base = raw & _STYPE_BASE_MASK
    name = _STYPE_NAMES.get(base, f"TYPE_{base:#x}")
    flags = []
    if raw & _STYPE_SPECIAL:
        flags.append("ADMIN")
    if raw & _STYPE_TEMPORARY:
        flags.append("TEMP")
    if flags:
        return f"{name} ({','.join(flags)})"
    return name


# FileAccessMask bits relevant to share permission display.
_FILE_READ_DATA = 0x00000001
_FILE_WRITE_DATA = 0x00000002
_FILE_APPEND_DATA = 0x00000004
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_WRITE_OWNER = 0x00080000
_GENERIC_ALL = 0x10000000
_GENERIC_EXECUTE = 0x20000000
_GENERIC_WRITE = 0x40000000
_GENERIC_READ = 0x80000000


def _translate_maximal_access(mask: Any) -> List[str]:
    """Translate a ``maximal_access`` bitmask to ADscan permission labels.

    The labels are stable, sorted, deduplicated. ``GENERIC_*`` flags imply
    the corresponding read/write rights so we collapse them.
    """
    try:
        raw = int(mask) if mask is not None else 0
    except (TypeError, ValueError):
        return []

    perms: List[str] = []

    if raw & (_GENERIC_ALL | _GENERIC_READ | _FILE_READ_DATA):
        perms.append("READ")
    if raw & (_GENERIC_ALL | _GENERIC_WRITE | _FILE_WRITE_DATA | _FILE_APPEND_DATA):
        perms.append("WRITE")
    if raw & (_GENERIC_ALL | _WRITE_DAC | _WRITE_OWNER):
        perms.append("WRITE_DAC")
    if raw & _READ_CONTROL:
        perms.append("READ_CONTROL")
    if raw & _GENERIC_EXECUTE:
        perms.append("EXECUTE")

    seen = set()
    return [p for p in perms if not (p in seen or seen.add(p))]


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------


@dataclass
class NativeShareEntry:
    """One discovered SMB share with translated permissions."""

    name: str
    type: str
    remark: str
    permissions: List[str] = field(default_factory=list)
    accessible: bool = True
    probe_error: Optional[str] = None

    @property
    def is_writable(self) -> bool:
        return any(p in {"WRITE", "WRITE_DAC"} for p in self.permissions)

    @property
    def is_readable(self) -> bool:
        return "READ" in self.permissions

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "remark": self.remark,
            "permissions": list(self.permissions),
            "accessible": self.accessible,
            "probe_error": self.probe_error,
        }


@dataclass
class NativeSharesResult:
    """Outcome of one host's share enumeration."""

    host: str
    shares: List[NativeShareEntry] = field(default_factory=list)
    status: NativeSharesStatus = "ok"
    error: Optional[str] = None

    @property
    def readable(self) -> List[NativeShareEntry]:
        return [s for s in self.shares if s.is_readable]

    @property
    def writable(self) -> List[NativeShareEntry]:
        return [s for s in self.shares if s.is_writable]

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "status": self.status,
            "error": self.error,
            "shares": [s.to_dict() for s in self.shares],
            "counts": {
                "total": len(self.shares),
                "readable": len(self.readable),
                "writable": len(self.writable),
            },
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


# Share names for which probing access provides no useful signal (IPC$ is the
# RPC pipe broker; refusing to tree_connect it is normal). Keeping the list
# narrow lets the operator still see READ/WRITE on admin shares like C$.
_SKIP_PROBE_NAMES = {"IPC$"}


async def _probe_share_access(
    machine: Any, share_obj: Any
) -> tuple[List[str], Optional[str]]:
    """Tree-connect to ``share_obj`` and translate ``maximal_access``.

    Returns ``(permissions, error)``. An error here is per-share (one denied
    share does not abort the sweep) and surfaces in :class:`NativeShareEntry`.
    """
    try:
        ok, err = await share_obj.connect(machine.connection)
        if err is not None:
            return [], str(err)
        if not ok:
            return [], "tree_connect returned False"
        return _translate_maximal_access(share_obj.maximal_access), None
    except Exception as exc:  # noqa: BLE001 — boundary; re-emit as soft error
        telemetry.capture_exception(exc)
        return [], str(exc)


def _is_access_denied(exc: BaseException | str | None) -> bool:
    if exc is None:
        return False
    text = str(exc).upper()
    return "ACCESS_DENIED" in text or "STATUS_ACCESS_DENIED" in text


# ---------------------------------------------------------------------------
# Public entry — async
# ---------------------------------------------------------------------------


async def enumerate_shares_native(
    *,
    config: SMBConfig,
    timeout: int = 30,
    probe_access: bool = True,
) -> NativeSharesResult:
    """Enumerate SMB shares on ``config.target_ip`` natively.

    Args:
        config: ``SMBConfig`` describing the connection (credentials, target,
            posture snapshot). Built once at the call site via the standard
            transport layer; never construct aiosmb URLs by hand.
        timeout: Per-operation timeout in seconds.
        probe_access: When True (default), perform a ``tree_connect`` on
            every non-IPC share to read ``maximal_access`` and translate to
            READ/WRITE labels. Set False for fast listing only (e.g. when
            access checks already happened upstream).

    Returns:
        :class:`NativeSharesResult` — never raises. Auth/connection
        failures are translated to ``status=denied|error`` with the cause
        in ``error``.
    """
    host = config.target_hostname or config.target_ip
    result = NativeSharesResult(host=host)

    try:
        async with asyncio.timeout(timeout):
            async with smb_machine_with_fallback(config) as machine:
                listing_failed = False
                async for share_obj, err in machine.list_shares():
                    if err is not None:
                        listing_failed = True
                        result.error = str(err)
                        result.status = "denied" if _is_access_denied(err) else "error"
                        break
                    if share_obj is None:
                        continue

                    name = str(share_obj.name or "")
                    if not name:
                        continue
                    type_label = _translate_share_type(share_obj.type)
                    remark = (share_obj.remark or "").strip()

                    permissions: List[str] = []
                    probe_err: Optional[str] = None
                    accessible = True

                    if probe_access and name not in _SKIP_PROBE_NAMES:
                        permissions, probe_err = await _probe_share_access(
                            machine, share_obj
                        )
                        if probe_err is not None:
                            accessible = False

                    result.shares.append(
                        NativeShareEntry(
                            name=name,
                            type=type_label,
                            remark=remark,
                            permissions=permissions,
                            accessible=accessible,
                            probe_error=probe_err,
                        )
                    )

                if listing_failed and not result.shares:
                    return result
                if listing_failed:
                    result.status = "partial"
                    return result
                result.status = "ok"
                return result

    except SMBAuthError as exc:
        result.status = "denied"
        result.error = str(exc)
    except SMBSigningRequiredError as exc:
        result.status = "error"
        result.error = f"SMB signing required: {exc}"
    except SMBConnectionError as exc:
        result.status = "error"
        result.error = str(exc)
    except asyncio.TimeoutError:
        result.status = "error"
        result.error = f"Share enumeration timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001 — outer boundary
        telemetry.capture_exception(exc)
        result.status = "error"
        result.error = str(exc)
        print_info_debug(f"[native-shares] unexpected error: {exc}")

    return result


# ---------------------------------------------------------------------------
# Public entry — sync convenience
# ---------------------------------------------------------------------------


def enumerate_shares_native_sync(
    *,
    config: SMBConfig,
    timeout: int = 30,
    probe_access: bool = True,
) -> NativeSharesResult:
    """Sync wrapper for callers outside an event loop.

    Uses ``run_smb_operation`` so the transport's existing event-loop
    discipline (no nested loops, posture sink wiring) is preserved.
    """
    from adscan_internal.services.smb_transport import run_smb_operation

    return run_smb_operation(
        enumerate_shares_native(
            config=config, timeout=timeout, probe_access=probe_access
        )
    )


# ---------------------------------------------------------------------------
# Native sessions enumeration — replaces ``nxc smb --sessions``
# ---------------------------------------------------------------------------


@dataclass
class NativeSessionEntry:
    """One active SMB session as reported by ``SrvSvc NetSessionEnum``."""

    username: str
    source_ip: str

    def to_dict(self) -> dict:
        return {"username": self.username, "source_ip": self.source_ip}


@dataclass
class NativeSessionsResult:
    """Outcome of one host's session enumeration."""

    host: str
    sessions: List[NativeSessionEntry] = field(default_factory=list)
    status: NativeSharesStatus = "ok"
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "status": self.status,
            "error": self.error,
            "sessions": [s.to_dict() for s in self.sessions],
            "counts": {"total": len(self.sessions)},
        }


async def enumerate_sessions_native(
    *,
    config: SMBConfig,
    timeout: int = 30,
    level: int = 10,
) -> NativeSessionsResult:
    """Enumerate active SMB sessions on ``config.target_ip``.

    Uses ``SrvSvc NetSessionEnum`` via aiosmb. ``level=10`` returns
    ``(username, ip_addr)`` per session — the same minimum signal NetExec's
    ``--sessions`` shows. Higher levels include connection-time and
    transport, which are not useful for our table.
    """
    host = config.target_hostname or config.target_ip
    result = NativeSessionsResult(host=host)

    try:
        async with asyncio.timeout(timeout):
            async with smb_machine_with_fallback(config) as machine:
                async for session_obj, err in machine.list_sessions(level=level):
                    if err is not None:
                        result.status = "denied" if _is_access_denied(err) else "error"
                        result.error = str(err)
                        return result
                    if session_obj is None:
                        continue
                    username = (getattr(session_obj, "username", "") or "").strip()
                    raw_ip = getattr(session_obj, "ip_addr", "") or ""
                    source_ip = raw_ip.replace("\\", "").strip()
                    if not username and not source_ip:
                        continue
                    result.sessions.append(
                        NativeSessionEntry(username=username, source_ip=source_ip)
                    )
                result.status = "ok"
                return result

    except SMBAuthError as exc:
        result.status = "denied"
        result.error = str(exc)
    except SMBSigningRequiredError as exc:
        result.status = "error"
        result.error = f"SMB signing required: {exc}"
    except SMBConnectionError as exc:
        result.status = "error"
        result.error = str(exc)
    except asyncio.TimeoutError:
        result.status = "error"
        result.error = f"Session enumeration timed out after {timeout}s"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        result.status = "error"
        result.error = str(exc)
        print_info_debug(f"[native-sessions] unexpected error: {exc}")

    return result


def enumerate_sessions_native_sync(
    *,
    config: SMBConfig,
    timeout: int = 30,
    level: int = 10,
) -> NativeSessionsResult:
    from adscan_internal.services.smb_transport import run_smb_operation

    return run_smb_operation(
        enumerate_sessions_native(config=config, timeout=timeout, level=level)
    )


__all__ = [
    "NativeShareEntry",
    "NativeSharesResult",
    "NativeSharesStatus",
    "NativeSessionEntry",
    "NativeSessionsResult",
    "enumerate_shares_native",
    "enumerate_shares_native_sync",
    "enumerate_sessions_native",
    "enumerate_sessions_native_sync",
]
