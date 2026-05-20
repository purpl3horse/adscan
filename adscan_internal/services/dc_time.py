"""Read the wall-clock time of a Domain Controller via multiple channels.

Decouples "where does DC time come from" from "how do we apply it locally".
Reading is pre-auth, no priv, no shell-out for the primary path.

Channel order (best-effort, returns first success):
    1. SMB Negotiate (aiosmb)  — pre-auth, no creds, 445 always open on DC.
                                  Reads SystemTime from NEGOTIATE_PROTOCOL_RESPONSE.
    2. NTP (ntpdate/ntpdig)    — fast in corporate envs; fails in many HTB/lab
                                  scenarios where UDP/123 is filtered or absent.
    3. Samba ``net time``      — legacy RPC fallback (srvsvc.NetRemoteTOD); kept
                                  for environments where SMB Negotiate refuses
                                  before delivering a response (rare). Requires
                                  a *separate* timezone query to convert the
                                  DC's local time back to UTC — see the channel
                                  implementation for the full gymnastics.

The aiosmb path is the primary because:
    - Pre-auth, no creds needed.
    - 445 is always reachable on a working DC.
    - aiosmb is a vendored async library — coherent with the LDAP/Kerberos
      stack and no SO-level binary dependency.
    - ``SystemTime`` is FILETIME with 100ns precision (returned as UTC datetime).

This module ONLY reads DC time. Applying the reading to the local system is
the caller's responsibility (cli/kerberos.py drives that via the host helper
``set_system_time`` op).

Posture detection:
    Time-read failures are NOT a posture signal — they reflect transport
    reachability, not AD hardening. This module does not emit ``PostureSignal``.
    All failures route through ``telemetry.capture_exception`` and verbose
    debug logging only.
"""
from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from adscan_core import telemetry
from adscan_core.rich_output import (
    mark_sensitive,
    print_info_debug,
    print_warning_debug,
)


class DCTimeChannel(str, Enum):
    """Channel used to read the wall-clock time of a DC."""

    SMB_NEGOTIATE = "smb_negotiate"
    NTP = "ntp"
    NET_TIME = "net_time"


@dataclass(frozen=True)
class DCTimeReading:
    """A successful DC time reading.

    Attributes:
        when_utc: Timezone-aware UTC datetime reported by the DC.
        channel: Which channel returned the reading.
        rtt_ms: Roundtrip time of the read in milliseconds (sanity check).
        server_endpoint: The ``ip:port`` (or ``ip``) that responded, for logging.
    """

    when_utc: datetime
    channel: DCTimeChannel
    rtt_ms: int
    server_endpoint: str


class DCTimeChannelError(RuntimeError):
    """Raised when a single channel attempt fails."""


class DCTimeUnavailable(RuntimeError):
    """Raised when every configured channel failed to read DC time."""


# ----- Diagnostics ----------------------------------------------------------


def _describe_exception(exc: Any) -> str:
    """Render an aiosmb exception/error tuple with enough detail to debug.

    aiosmb routinely returns ``err`` objects whose ``__str__`` is empty
    (typed exceptions without an explicit message, or NoneType-style
    wrappers); we surface the type name and a repr to give the operator
    a real diagnostic instead of an empty trailing colon in the log.
    """
    if exc is None:
        return "None"
    type_name = type(exc).__name__
    try:
        text = str(exc).strip()
    except Exception:  # noqa: BLE001 — defensive: __str__ can raise
        text = ""
    if not text:
        try:
            text = repr(exc)
        except Exception:  # noqa: BLE001 — defensive: __repr__ can raise
            text = "<unrepresentable>"
    return f"{type_name}: {text}"


# ----- Channel 1: SMB Negotiate (primary) -----------------------------------


async def _tcp_port_open(ip: str, port: int, timeout: float = 2.0) -> bool:
    """Quick TCP connect check (no SMB protocol).

    Distinguishes "port filtered/closed" from "aiosmb library issue"
    when the higher-level SMB Negotiate fails — useful diagnostic when
    a previous SMB-heavy operation may have left state in a weird place.

    Args:
        ip: IPv4 address of the target.
        port: TCP port to probe (typically 445).
        timeout: Soft timeout in seconds for the connect attempt.

    Returns:
        True if a TCP connection could be established, False otherwise.
        Never raises — this is a best-effort pre-check.
    """
    writer = None
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=timeout
        )
        return True
    except Exception:  # noqa: BLE001 — pre-check must never raise
        return False
    finally:
        if writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:  # noqa: BLE001 — best effort
                pass


async def _do_smb_negotiate_read(
    dc_ip: str, *, port: int = 445, timeout: float = 5.0
) -> DCTimeReading:
    """Single SMB Negotiate read attempt.

    Lives separately from ``get_dc_time_via_smb_negotiate`` so the retry
    wrapper can call it without losing exception context across attempts.

    Raises:
        DCTimeChannelError: On TCP unreachable, SMB connect failure,
            SMB negotiate failure, or missing ``SystemTime``.
    """
    # Import lazily — aiosmb is a heavy dependency we do not want to pay for
    # when the caller only needs the NTP/net-time channels.
    from aiosmb.commons.connection.target import SMBTarget
    from aiosmb.connection import SMBConnection

    # Pre-check: a fast TCP connect tells us whether 445 is reachable at all.
    # If aiosmb later returns an empty error, this gives the operator a real
    # signal that the DC is reachable but the SMB stack is unhappy.
    if not await _tcp_port_open(dc_ip, port, timeout=min(2.0, timeout)):
        raise DCTimeChannelError(
            f"TCP {dc_ip}:{port} unreachable (pre-check failed)"
        )

    target = SMBTarget(ip=dc_ip, port=port, timeout=int(max(1, timeout)))
    conn = SMBConnection(gssapi=None, target=target, preserve_gssapi=False)
    start = time.monotonic()
    try:
        async with conn:
            _, err = await conn.connect()
            if err is not None:
                raise DCTimeChannelError(
                    f"SMB connect failed: {_describe_exception(err)}"
                ) from err
            res, rply, err = await conn.negotiate(protocol_test=True)
            if not res or rply is None or err is not None:
                detail = _describe_exception(err) if err is not None else "no rply"
                raise DCTimeChannelError(f"SMB negotiate failed: {detail}")
            system_time = getattr(getattr(rply, "command", None), "SystemTime", None)
            if system_time is None:
                raise DCTimeChannelError(
                    "SMB negotiate response missing SystemTime"
                )
            # aiosmb parses FILETIME via ``timestamp2datetime`` which returns
            # a naive UTC datetime. Force timezone awareness so callers can
            # compute offsets safely.
            if system_time.tzinfo is None:
                system_time = system_time.replace(tzinfo=timezone.utc)
            rtt_ms = int((time.monotonic() - start) * 1000)
            return DCTimeReading(
                when_utc=system_time,
                channel=DCTimeChannel.SMB_NEGOTIATE,
                rtt_ms=rtt_ms,
                server_endpoint=f"{dc_ip}:{port}",
            )
    except DCTimeChannelError:
        raise
    except Exception as exc:
        raise DCTimeChannelError(
            f"SMB negotiate channel error: {_describe_exception(exc)}"
        ) from exc


async def get_dc_time_via_smb_negotiate(
    dc_ip: str,
    *,
    port: int = 445,
    timeout: float = 5.0,
    max_attempts: int = 3,
) -> DCTimeReading:
    """Read DC system time via SMB2 NEGOTIATE.

    Pre-auth: no credentials, no privilege. The DC's ``SystemTime`` is parsed
    from the NEGOTIATE_PROTOCOL_RESPONSE PDU (FILETIME, 100ns precision).

    Retries up to ``max_attempts`` times with exponential backoff
    (0.5s, 1s, 2s) for transient connection failures — connection pool
    exhaustion from a previous SMB-heavy operation (rclone share spider),
    DC ratelimit, or a brief network blip — all of which usually clear
    within a couple of seconds. Each attempt re-opens a fresh aiosmb
    ``SMBConnection`` so a stuck session cannot poison the retry chain.

    Args:
        dc_ip: IPv4 address of the DC.
        port: SMB port (default 445).
        timeout: Soft socket timeout in seconds.
        max_attempts: Maximum number of attempts (default 3).

    Returns:
        A populated ``DCTimeReading``.

    Raises:
        DCTimeChannelError: When every attempt fails. The message includes
            the last exception type and detail for diagnostics.
    """
    last_exc: Exception | None = None
    backoff = 0.5
    for attempt in range(1, max_attempts + 1):
        try:
            return await _do_smb_negotiate_read(dc_ip, port=port, timeout=timeout)
        except DCTimeChannelError as exc:
            last_exc = exc
            print_info_debug(
                f"[clock-sync] smb_negotiate attempt {attempt}/{max_attempts} "
                f"failed: {_describe_exception(exc)}"
            )
            if attempt < max_attempts:
                await asyncio.sleep(backoff)
                backoff *= 2.0
    assert last_exc is not None  # loop guarantees we set it on the failure path
    raise DCTimeChannelError(
        f"SMB negotiate failed after {max_attempts} attempts: "
        f"{_describe_exception(last_exc)}"
    ) from last_exc


# ----- NTP / net-time output parsers (used by host-helper channels) ---------

# ``ntpdate -q`` sample: ``server 192.168.180.10, stratum 4, offset +0.001234, delay 0.02567``
_NTPDATE_OFFSET_RE = re.compile(
    r"offset\s+([+-]?\d+(?:\.\d+)?)", re.IGNORECASE
)
# ``ntpdig`` sample: ``2026-05-19 19:20:34.123456 (+0000) +0.001234 +/- 0.012345 ...``
_NTPDIG_ISO_RE = re.compile(
    r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s*\(([+-]\d{4})\)"
)
# ``net time -S <ip>`` sample: ``Mon May 19 19:20:34 2026``  or
# ``Time at 192.168.180.10 is Mon May 19 19:20:34 2026``
_NET_TIME_ASCTIME_RE = re.compile(
    r"((?:Sun|Mon|Tue|Wed|Thu|Fri|Sat)\s+"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})"
)
# ``net time zone -S <ip>`` sample: ``-14400`` (seconds east of UTC, EDT = -4h).
# Some Samba builds prefix with a label; tolerate both shapes.
_NET_TIME_ZONE_RE = re.compile(r"(-?\d{1,6})")


def _parse_ntp_query_output(stdout: str | None) -> datetime | None:
    """Parse ``ntpdate -q`` / ``ntpdig`` output into a UTC datetime.

    Strategy: ntpdig emits an ISO timestamp; ntpdate emits an offset relative
    to local time. When only an offset is present, apply it to the host's
    current UTC time — the result is approximate to the offset's precision
    but accurate enough for the ≤5min Kerberos skew tolerance.

    Returns ``None`` when parsing fails.
    """
    if not stdout:
        return None
    iso_match = _NTPDIG_ISO_RE.search(stdout)
    if iso_match:
        ts_str, tz_str = iso_match.group(1), iso_match.group(2)
        ts_str = ts_str.replace(" ", "T")
        try:
            # Normalise +HHMM → +HH:MM for fromisoformat (3.10 tolerates both).
            normalized = f"{ts_str}{tz_str[:3]}:{tz_str[3:]}"
            parsed = datetime.fromisoformat(normalized)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            pass
    offset_match = _NTPDATE_OFFSET_RE.search(stdout)
    if offset_match:
        try:
            offset_s = float(offset_match.group(1))
            now = datetime.now(timezone.utc)
            return now.replace(microsecond=0) + timedelta(seconds=offset_s)
        except ValueError:
            return None
    return None


def _parse_net_time_local_output(stdout: str | None) -> datetime | None:
    """Parse Samba ``net time -S <ip>`` output as a *naive local* datetime.

    CRITICAL: ``net time -S <ip>`` returns the DC's wall-clock in the DC's
    *local* timezone, NOT UTC. Treating the parsed datetime as UTC produces
    a clock offset equal to the DC's timezone offset (e.g. -4h on EDT) —
    which then poisons the host clock for the whole session.

    The returned datetime is intentionally naive: the caller MUST combine
    it with the offset reported by ``net time zone`` to derive UTC.
    """
    if not stdout:
        return None
    match = _NET_TIME_ASCTIME_RE.search(stdout)
    if not match:
        return None
    try:
        return datetime.strptime(match.group(1), "%a %b %d %H:%M:%S %Y")
    except ValueError:
        return None


def _parse_net_time_zone_output(stdout: str | None) -> int | None:
    """Parse Samba ``net time zone -S <ip>`` output → seconds east of UTC.

    Samba prints a single signed integer (e.g. ``-14400`` for EDT, ``+3600``
    for CET). We accept a leading whitespace/label and pluck the integer.

    Returns ``None`` when no integer can be extracted. Sane bound check:
    timezone offsets are within ±14h (50400 seconds).
    """
    if not stdout:
        return None
    text = stdout.strip()
    if not text:
        return None
    match = _NET_TIME_ZONE_RE.search(text)
    if not match:
        return None
    try:
        offset = int(match.group(1))
    except ValueError:
        return None
    # Sanity: real-world TZ offsets are within ±14h. Reject anything larger
    # — parser likely matched a stray number unrelated to the timezone.
    if offset < -50400 or offset > 50400:
        return None
    return offset


# Backwards-compat: keep the old name in case anything external imports it.
# Internal callers MUST use the two new parsers above (one for the local
# time, one for the timezone) so the UTC conversion is explicit.
_parse_net_time_output = _parse_net_time_local_output


# ----- Channel 2: NTP (host-helper) -----------------------------------------


async def get_dc_time_via_ntp(
    dc_ip: str, *, sock_path: str, timeout: float = 10.0
) -> DCTimeReading:
    """Read DC time via the host helper ``ntp_query`` op.

    Args:
        dc_ip: IPv4 address.
        sock_path: Host-helper Unix socket path.
        timeout: Soft timeout for the helper call.

    Raises:
        DCTimeChannelError: When the helper fails or output cannot be parsed.
    """
    from adscan_internal.host_privileged_helper import (
        HostHelperError,
        host_helper_client_request,
    )

    start = time.monotonic()
    try:
        resp = await asyncio.to_thread(
            host_helper_client_request,
            sock_path,
            op="ntp_query",
            payload={"host": dc_ip},
        )
    except (HostHelperError, OSError) as exc:
        raise DCTimeChannelError(
            f"NTP host-helper call failed: {_describe_exception(exc)}"
        ) from exc

    if not getattr(resp, "ok", False):
        raise DCTimeChannelError(
            f"NTP host-helper returned not-ok: rc={getattr(resp, 'returncode', None)} "
            f"msg={getattr(resp, 'message', None)!r}"
        )

    when_utc = _parse_ntp_query_output(getattr(resp, "stdout", None))
    if when_utc is None:
        when_utc = _parse_ntp_query_output(getattr(resp, "stderr", None))
    if when_utc is None:
        raise DCTimeChannelError(
            "NTP host-helper output could not be parsed for a timestamp"
        )

    rtt_ms = int((time.monotonic() - start) * 1000)
    return DCTimeReading(
        when_utc=when_utc,
        channel=DCTimeChannel.NTP,
        rtt_ms=rtt_ms,
        server_endpoint=dc_ip,
    )


# ----- Channel 3: net time (host-helper) ------------------------------------


async def _query_net_time_local(dc_ip: str, sock_path: str) -> str:
    """Run ``net time -S <ip>`` via the host helper and return stdout.

    Raises:
        DCTimeChannelError: When the helper call fails or the response
            indicates a non-zero exit status.
    """
    from adscan_internal.host_privileged_helper import (
        HostHelperError,
        host_helper_client_request,
    )

    try:
        resp = await asyncio.to_thread(
            host_helper_client_request,
            sock_path,
            op="net_time_query",
            payload={"host": dc_ip},
        )
    except (HostHelperError, OSError) as exc:
        raise DCTimeChannelError(
            f"net time host-helper call failed: {_describe_exception(exc)}"
        ) from exc

    if not getattr(resp, "ok", False):
        raise DCTimeChannelError(
            f"net time host-helper returned not-ok: rc={getattr(resp, 'returncode', None)} "
            f"msg={getattr(resp, 'message', None)!r}"
        )
    return getattr(resp, "stdout", "") or getattr(resp, "stderr", "") or ""


async def _query_net_time_zone(dc_ip: str, sock_path: str) -> int:
    """Run ``net time zone -S <ip>`` via the host helper and return the offset.

    The offset is seconds east of UTC — positive for east, negative for west.

    Raises:
        DCTimeChannelError: When the helper call fails, the response is
            non-ok, or the output cannot be parsed for a plausible offset.
            We refuse to apply a "best guess" — a missing timezone read
            means the net_time channel must abort cleanly so the caller
            falls through to the next channel or surfaces the error.
    """
    from adscan_internal.host_privileged_helper import (
        HostHelperError,
        host_helper_client_request,
    )

    try:
        resp = await asyncio.to_thread(
            host_helper_client_request,
            sock_path,
            op="net_time_zone_query",
            payload={"host": dc_ip},
        )
    except (HostHelperError, OSError) as exc:
        raise DCTimeChannelError(
            f"net time zone host-helper call failed: {_describe_exception(exc)}"
        ) from exc

    if not getattr(resp, "ok", False):
        raise DCTimeChannelError(
            f"net time zone host-helper returned not-ok: "
            f"rc={getattr(resp, 'returncode', None)} "
            f"msg={getattr(resp, 'message', None)!r}"
        )

    offset = _parse_net_time_zone_output(getattr(resp, "stdout", None))
    if offset is None:
        offset = _parse_net_time_zone_output(getattr(resp, "stderr", None))
    if offset is None:
        raise DCTimeChannelError(
            "net time zone output could not be parsed for an integer offset"
        )
    return offset


async def get_dc_time_via_net_time(
    dc_ip: str, *, sock_path: str, timeout: float = 30.0
) -> DCTimeReading:
    """Read DC time via the host helper ``net_time_query`` op (Samba ``net time``).

    Why the gymnastics: ``net time -S <ip>`` returns the DC's wall-clock in
    the DC's *local* timezone, not UTC. To recover a true UTC timestamp we
    issue a second helper call (``net_time_zone_query``) which executes
    ``net time zone -S <ip>`` and returns the offset in seconds east of UTC,
    then subtract the offset from the parsed local datetime.

    If the timezone query is unavailable (Samba too old, ``net`` not present,
    helper not running), we **abort the channel** instead of inventing a
    UTC equivalent. A wrong clock is much more dangerous than a missing
    sync — it silently breaks Kerberos and trips downstream auth retries.

    Raises:
        DCTimeChannelError: When either helper call fails, output cannot
            be parsed, or the timezone query is unavailable.
    """
    start = time.monotonic()
    local_raw = await _query_net_time_local(dc_ip, sock_path)
    naive_local = _parse_net_time_local_output(local_raw)
    if naive_local is None:
        raise DCTimeChannelError(
            "net time host-helper output could not be parsed for a timestamp"
        )

    # Second call: timezone offset. If this fails, abort — do not pretend the
    # local time is UTC (that's the bug that put the host clock 4h behind on
    # the Cicada engagement).
    zone_offset_seconds = await _query_net_time_zone(dc_ip, sock_path)

    utc_dt = (naive_local - timedelta(seconds=zone_offset_seconds)).replace(
        tzinfo=timezone.utc
    )

    rtt_ms = int((time.monotonic() - start) * 1000)
    return DCTimeReading(
        when_utc=utc_dt,
        channel=DCTimeChannel.NET_TIME,
        rtt_ms=rtt_ms,
        server_endpoint=dc_ip,
    )


# ----- Channel orchestration ------------------------------------------------


DEFAULT_CHANNELS: tuple[DCTimeChannel, ...] = (
    DCTimeChannel.SMB_NEGOTIATE,
    DCTimeChannel.NTP,
    DCTimeChannel.NET_TIME,
)


async def get_dc_time(
    dc_ip: str,
    *,
    port: int = 445,
    timeout: float = 5.0,
    channels: tuple[DCTimeChannel, ...] = DEFAULT_CHANNELS,
    sock_path: str | None = None,
) -> DCTimeReading:
    """Try channels in order until one succeeds.

    Args:
        dc_ip: IPv4 address of the DC.
        port: SMB port for the SMB_NEGOTIATE channel.
        timeout: Per-channel soft timeout.
        channels: Channel order to attempt.
        sock_path: Host-helper socket path; required for NTP / NET_TIME
            channels when invoked from inside the container. When ``None``
            those channels are skipped (with a debug log).

    Returns:
        The first successful ``DCTimeReading``.

    Raises:
        DCTimeUnavailable: When every channel failed. The exception message
            chains the per-channel failure reasons for diagnostics.
    """
    marked_dc = mark_sensitive(dc_ip, "ip")
    failures: list[str] = []

    for channel in channels:
        print_info_debug(f"[clock-sync] trying channel={channel.value} dc={marked_dc}")
        try:
            if channel is DCTimeChannel.SMB_NEGOTIATE:
                reading = await get_dc_time_via_smb_negotiate(
                    dc_ip, port=port, timeout=timeout
                )
            elif channel is DCTimeChannel.NTP:
                if not sock_path:
                    raise DCTimeChannelError(
                        "NTP channel requires sock_path (host helper socket)"
                    )
                reading = await get_dc_time_via_ntp(
                    dc_ip, sock_path=sock_path, timeout=timeout
                )
            elif channel is DCTimeChannel.NET_TIME:
                if not sock_path:
                    raise DCTimeChannelError(
                        "net_time channel requires sock_path (host helper socket)"
                    )
                reading = await get_dc_time_via_net_time(
                    dc_ip, sock_path=sock_path, timeout=timeout
                )
            else:  # pragma: no cover — defensive
                raise DCTimeChannelError(f"Unknown channel: {channel}")
        except DCTimeChannelError as exc:
            failures.append(f"{channel.value}: {_describe_exception(exc)}")
            print_warning_debug(
                f"[clock-sync] channel={channel.value} failed: {_describe_exception(exc)}"
            )
            continue
        except Exception as exc:  # noqa: BLE001 — surface any unknown failure
            telemetry.capture_exception(exc)
            failures.append(
                f"{channel.value}: unexpected: {_describe_exception(exc)}"
            )
            print_warning_debug(
                f"[clock-sync] channel={channel.value} unexpected error: "
                f"{_describe_exception(exc)}"
            )
            continue

        print_info_debug(
            f"[clock-sync] channel={channel.value} ok rtt={reading.rtt_ms}ms "
            f"when_utc={reading.when_utc.isoformat()}"
        )
        return reading

    raise DCTimeUnavailable(
        "All DC time channels failed: " + " | ".join(failures)
    )


# ----- ISO 8601 validation (for set_system_time payload) --------------------

# Strict ISO 8601: ``YYYY-MM-DDTHH:MM:SS[.ffffff]<+HH:MM|-HH:MM|Z>``.
# Reject sloppy inputs because this string ends up in a privileged shell call.
ISO_8601_STRICT_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?"
    r"(?:Z|[+-]\d{2}:\d{2})$"
)


def is_valid_iso8601(value: str) -> bool:
    """Strict ISO 8601 validation gate for the privileged ``set_system_time`` op.

    The string must include an explicit timezone (``Z`` or ``±HH:MM``). Naive
    timestamps are rejected because applying them to a privileged host clock
    is ambiguous.
    """
    if not isinstance(value, str):
        return False
    if not ISO_8601_STRICT_RE.match(value):
        return False
    try:
        # fromisoformat handles both ``Z`` (3.11+) and ``±HH:MM``.
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


# ----- Sanity gates (caller-side, before applying to host clock) ------------

# Hardcoded bounds — non-configurable on purpose. If we receive a timestamp
# from outside this window something is catastrophically wrong (parser bug,
# DC misconfigured, helper returning junk) and applying it to the host clock
# can break TLS certs, cron, the container's view of "now", etc. Updated when
# we cross calendar boundaries.
_MIN_PLAUSIBLE_YEAR = 2024
_MAX_PLAUSIBLE_YEAR = 2030

# An RTT above this threshold means the channel was lagging during the read
# — the reading is potentially stale by seconds, which is enough to put us
# back across the 5-minute Kerberos skew tolerance after a few syncs.
MAX_PLAUSIBLE_RTT_MS = 10_000


def is_plausible_reading(reading: DCTimeReading) -> tuple[bool, str | None]:
    """Sanity-check a ``DCTimeReading`` before applying it to the host clock.

    Two checks:
        1. Year must be within ``[_MIN_PLAUSIBLE_YEAR, _MAX_PLAUSIBLE_YEAR]``.
           A timestamp from 1601 or 2099 indicates a parser bug or a
           corrupted DC response — applying it would brick the host clock.
        2. RTT must be ≤ ``MAX_PLAUSIBLE_RTT_MS``. A slow read may have
           captured a stale snapshot of the DC clock; better to abort and
           retry than to apply a reading that was already seconds old when
           it left the wire.

    Returns:
        ``(True, None)`` when the reading is safe to apply. Otherwise
        ``(False, reason)`` with a human-readable explanation suitable
        for surfacing to the operator.
    """
    year = reading.when_utc.year
    if year < _MIN_PLAUSIBLE_YEAR or year > _MAX_PLAUSIBLE_YEAR:
        return (
            False,
            f"DC time channel={reading.channel.value} returned implausible "
            f"year {year}; aborting clock sync to avoid corrupting host clock.",
        )
    if reading.rtt_ms > MAX_PLAUSIBLE_RTT_MS:
        return (
            False,
            f"DC time channel={reading.channel.value} took {reading.rtt_ms}ms — "
            f"reading may be stale; aborting clock sync.",
        )
    return (True, None)
