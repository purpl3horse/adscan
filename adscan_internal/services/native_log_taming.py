"""Single source of truth for taming third-party (vendor) logging noise.

ADscan integrates a sizable surface of third-party libraries — the native AD
stack (aiosmb, msldap, kerbad, asysocks, badldap, badauth, minikerberos,
winacl, asyauth, asyldap), credential parsers (pypykatz), and stdlib loggers
that emit benign chatter as a side-effect of how we use them (asyncio).

These libraries pollute the user's terminal through **four distinct channels**,
each with its own remedy. This module is the canonical place for all four —
do not invent parallel mechanisms in other modules.

================================================================================
Channel 1 — stdlib ``logging`` (rogue StreamHandler at import time)
================================================================================
Native-stack libs install their own ``StreamHandler`` and write raw lines like
``2026-05-02 08:07:36,863 aiosmb ERROR ...`` straight to stderr, bypassing
Rich. :func:`tame_native_stack_loggers` strips those handlers, forces
``propagate=True`` so records reach ADscan's root :class:`RichHandler`, and
attaches :class:`BenignNativeNoiseFilter` to drop known-benign post-teardown
chatter (SMB ``CONNECTION_ABORTED``, SPNEGO/NEGOEX cleanup, late callbacks).

================================================================================
Channel 2 — stdlib ``logging`` (handler-less vendor loggers)
================================================================================
Some vendors (``pypykatz``, ``asyncio``) don't add their own handlers — they
just propagate. We don't need to strip anything, only filter benign noise via
the same :class:`BenignNativeNoiseFilter`. Add the logger name to
:data:`_NATIVE_STACK_LOGGER_NAMES` (handler-stripping is a no-op when there
are no handlers to strip) and the substring to
:data:`BENIGN_NATIVE_NOISE_MARKERS`.

================================================================================
Channel 3 — vendor ``log_callback`` mechanism (bypasses logging entirely)
================================================================================
aiosmb and badldap relay servers use a ``log_callback`` parameter that, by
default, calls ``print()`` directly to stdout. :func:`make_relay_log_callback`
produces a replacement callback that filters lifecycle chatter and packet
dumps and routes the rest through ADscan's ``print_info_debug``. Pass it when
constructing ``SMBServerSettings`` / ``LDAPServerSettings``.

================================================================================
Channel 4 — direct ``print()`` / ``traceback.print_exc()`` in vendor source
================================================================================
Some vendor code prints raw bytes / tracebacks directly (asyauth SPNEGO server,
aiosmb relay exception handlers). These bypass everything. Because ``vendor/``
is committed and IS what ships, the fix is to **patch the vendor file
directly** — silence the print, replace the traceback with ``pass``, or route
through the available callback if one exists. See git history for examples in
``vendor/aiosmb/aiosmb/relay/serverconnection.py`` and
``vendor/asyauth/asyauth/protocols/spnego/server/native.py``.

================================================================================
Lifecycle
================================================================================
Call :func:`tame_native_stack_loggers` exactly once at runtime startup, right
after ``init_logging`` has configured the root Rich console handler. The
function is idempotent — subsequent calls are no-ops.
"""

from __future__ import annotations

import logging
import traceback
from collections.abc import Callable


_NATIVE_STACK_LOGGER_NAMES: tuple[str, ...] = (
    # Native AD stack — strip rogue StreamHandler + filter benign noise.
    "aiosmb",
    "msldap",
    "kerbad",
    "minikerberos",
    "asysocks",
    "asysocks.client",
    "asysocks.client.http",
    "asysocks.unicomm",
    "badldap",
    "badauth",
    "badauth.ntlm",
    "badauth.kerberos",
    "badauth.credssp",
    "winacl",
    "asyauth",
    "asyldap",
    # Credential parsers — emit informational warnings as a side-effect of
    # how we call them (e.g. ``hive path not supplied`` when we deliberately
    # pass only SAM/SYSTEM and skip SECURITY/SOFTWARE).
    "pypykatz",
    # stdlib loggers that emit benign noise as a side-effect of our async
    # socket lifecycle (e.g. ``socket.send() raised exception`` after a
    # short-lived SMB session is torn down with pending writes).
    "asyncio",
)


_NATIVE_STACK_LOGGER_PREFIXES: tuple[str, ...] = tuple(
    sorted({name.split(".", 1)[0] for name in _NATIVE_STACK_LOGGER_NAMES})
)


BENIGN_NATIVE_NOISE_MARKERS: tuple[str, ...] = (
    # aiosmb tears down sockets after a normal session and re-raises the
    # terminal status as an exception — its ``except:`` clause then logs the
    # traceback at ERROR even though the foreground operation has succeeded.
    "SMBConnectionTerminated",
    "CONNECTION_ABORTED",
    "CONNECTION_RESET",
    "__handle_smb_in",
    # SPNEGO / NEGOEX teardown chatter from relay listeners and the auth
    # negotiation re-binding when a peer drops the channel cleanly.
    "NEGTOKEN_LOAD_ERROR",
    "[SPNEGOServer]",
    "[SPNEGORelay]",
    "Value [APPLICATION 28] did not match",
    "authenticate_relay_server",
    # Late callbacks fired once the underlying socket has already gone away.
    "object of type 'NoneType' has no len()",
    "SecurityBufferLength = len(self.Buffer)",
    "'NoneType' object has no attribute 'get_session_key'",
    # pypykatz offline_parser — fired every SAM-only dump because we
    # deliberately don't pass SECURITY/SOFTWARE hives.
    "hive path not supplied",
    # asyncio selector_events / proactor_events — fired when a connection is
    # torn down with pending writes (standard pattern for short-lived SMB).
    "socket.send() raised exception",
    "socket.sendto() raised exception",
)


def is_benign_native_noise(
    message: str,
    *,
    extra_markers: tuple[str, ...] = (),
) -> bool:
    """Return ``True`` when a third-party message matches a benign pattern.

    ``extra_markers`` lets callers extend the global list with context-specific
    tokens (e.g. the relay listener path adds ``TimeoutError`` and a few
    ``[DEBUG]`` prints that are only safe to drop in that flow).
    """

    if not message:
        return False
    for marker in BENIGN_NATIVE_NOISE_MARKERS:
        if marker in message:
            return True
    for marker in extra_markers:
        if marker in message:
            return True
    return False


class BenignNativeNoiseFilter(logging.Filter):
    """Drop benign post-teardown chatter from third-party native loggers."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 (stdlib API)
        if not record.name.startswith(_NATIVE_STACK_LOGGER_PREFIXES):
            return True
        message = record.getMessage()
        if record.exc_info:
            exc_type, exc_value, exc_tb = record.exc_info
            message = (
                f"{message}\n"
                f"{''.join(traceback.format_exception(exc_type, exc_value, exc_tb))}"
            )
        return not is_benign_native_noise(message)


_taming_installed = False


# ---------------------------------------------------------------------------
# Relay log_callback factory
# ---------------------------------------------------------------------------

_PACKET_MARKERS: tuple[str, ...] = ("[PACKET]",)


# Lifecycle chatter from aiosmb relay — emitted on every connection accepted
# by the listener. Useless even at debug level: a single coercion run produces
# 8+ connections, each with [INF] Got new connection / Authenticate results /
# Stopping connection (×N). The information is captured upstream by the probe
# result (success/failure + observation) so we drop these unconditionally.
_RELAY_LIFECYCLE_MARKERS: tuple[str, ...] = (
    "[INF] Got new connection",
    "[INF] Authenticate results",
    "[INF] Stopping connection",
    "[INF] Connection end",
    "[INF] Calling authenticate_relay_server",
)


def make_relay_log_callback(context: str) -> Callable:
    """Return an async ``log_callback`` for aiosmb / badldap relay servers.

    Routes messages through ADscan's output system instead of bare ``print()``:

    - Raw packet dumps (``[PACKET]``) are dropped — they are binary noise that
      is never useful to the user.
    - Messages matching :data:`BENIGN_NATIVE_NOISE_MARKERS` are dropped
      silently (SPNEGO teardown, session-key errors, NEGTOKEN chatter, etc.).
    - ``[ERR]`` messages that survive both filters go to ``print_info_debug``
      so they appear in the debug log file without polluting the UI.
    - All other messages (``[INF]``, ``[DBG]``) go to ``print_info_debug``.

    Args:
        context: Short label shown in the debug message (e.g. ``"smb-relay"``).
    """
    from adscan_core.rich_output import print_info_debug  # local import — avoids circular at module load

    async def _cb(msg: str) -> None:
        if not msg:
            return
        for marker in _PACKET_MARKERS:
            if marker in msg:
                return
        for marker in _RELAY_LIFECYCLE_MARKERS:
            if marker in msg:
                return
        if is_benign_native_noise(msg):
            return
        print_info_debug(f"[{context}] {msg}")

    return _cb


def tame_native_stack_loggers() -> None:
    """Strip rogue handlers and install the benign-noise filter once.

    Idempotent — subsequent calls are no-ops. Safe to invoke before any of the
    native libraries are imported: loggers that do not yet exist are created
    on demand by :func:`logging.getLogger`, the (empty) handler list is left
    alone, and the filter remains in place if/when the library is loaded
    later. Once the library imports and adds its own handler, that handler is
    not retroactively stripped — call this function after ``init_logging``
    and *before* any native-stack import to guarantee a clean console.
    """

    global _taming_installed
    if _taming_installed:
        return

    noise_filter = BenignNativeNoiseFilter()

    for name in _NATIVE_STACK_LOGGER_NAMES:
        logger = logging.getLogger(name)
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
        logger.propagate = True
        logger.addFilter(noise_filter)

    logging.getLogger().addFilter(noise_filter)

    _taming_installed = True
