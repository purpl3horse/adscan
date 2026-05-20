"""Shared state, console initialisation, and infrastructure helpers.

This module holds every piece of global state and the setup/accessor functions
that the rest of adscan_core.rich_output (and callers) depend on.  Moving them
here allows the public ``adscan_core.rich_output`` module to be progressively
split into focused submodules while keeping a single source-of-truth for all
mutable globals.

Circular-import note
--------------------
This module MUST NOT import from ``adscan_core.rich_output`` at module level.
Functions that need symbols from that module (e.g. ``print_info_debug``,
``install_prompt_logging_wrappers``) must use deferred (lazy) imports inside
the function body.
"""

from __future__ import annotations

import logging
import os
import sys
from typing import Callable, Dict, Optional

from rich.console import Console

from adscan_core.theme import ADSCAN_PRIMARY  # noqa: F401 (re-exported convenience)

# ---------------------------------------------------------------------------
# Module-level globals
# ---------------------------------------------------------------------------

# Global console instance (will be initialized from adscan.py)
_console: Optional[Console] = None

# Secondary console dedicated to telemetry recording.
# This console is never shown directly to the user; it is used only to
# capture a full Rich session (including info/warning/error messages)
# for sanitized upload to remote storage (Vercel/n8n).
_telemetry_console: Optional[Console] = None

# Global mode flags (will be initialized from adscan.py)
_verbose_mode: bool = False
_debug_mode: bool = False
_secret_mode: bool = False

# Track last message type for intelligent spacing
_last_message_type: Optional[str] = None
_last_was_panel: bool = False

# Logger instance (will be initialized from logging_config)
_logger: Optional[logging.Logger] = None

# ---------------------------------------------------------------------------
# Sensitive masking helpers
# ---------------------------------------------------------------------------


def strip_sensitive_markers(text: str) -> str:
    """Remove invisible sensitive markers from a string.

    These markers are used by :func:`mark_sensitive` to tag sensitive values
    (user/domain/ip/path/etc.) in Rich output so telemetry can sanitize them.
    They must never be present in real OS commands or filesystem paths because
    external tools would receive a different byte sequence and fail.

    Args:
        text: Input string that may contain invisible markers.

    Returns:
        The same string with all known markers removed.
    """
    from adscan_core.sensitive import strip_sensitive_markers as _strip

    return _strip(text)


def mark_passthrough(value: str) -> str:
    """Wrap a non-sensitive value with invisible passthrough markers.

    Use this when you want the value to remain unchanged in session recordings
    (telemetry sanitization will skip it), for example public URLs.

    Args:
        value: Public/non-sensitive value to preserve verbatim.

    Returns:
        Value wrapped with invisible passthrough markers.
    """
    from adscan_core.sensitive import mark_passthrough as _mark

    return _mark(value)


def mark_sensitive(value: str, data_type: str) -> str:
    """Wrap sensitive data with invisible markers for automatic sanitization.

    This function wraps sensitive values with zero-width space markers that are
    invisible to users but can be detected by telemetry sanitization code. This
    allows us to show sensitive data to users while automatically sanitizing it
    before uploading to telemetry services.

    Args:
        value: The sensitive value to mark (e.g., "example.local", "10.0.0.1", "admin")
        data_type: Type of sensitive data, one of:
            - "user": Usernames, account names
            - "domain": Domain names, FQDNs
            - "ip": IP addresses
            - "password": Passwords, hashes, credentials
            - "service": Service names, SPNs, delegation targets
            - "path": File paths, registry keys, share paths
            - "hostname": Hostnames, computer names
            - "workspace": Workspace names/identifiers

    Returns:
        String with invisible markers wrapping the value

    Example:
        >>> marked = mark_sensitive("example.local", "domain")
        >>> # User sees: "example.local"
        >>> # Telemetry sees the value wrapped with invisible markers that
        >>> # are later replaced by \"{DOMAIN}\" during sanitization.
    """
    from adscan_core.sensitive import mark_sensitive as _mark

    return _mark(value, data_type)


def mark_dict_values(
    data: Dict[str, str],
    type_mapping: Dict[str, str],
) -> Dict[str, str]:
    """Mark all values in a dictionary based on key-to-type mapping.

    This helper function applies mark_sensitive() to all values in a dictionary
    based on a mapping from dictionary keys to sensitive data types.

    Args:
        data: Dictionary with keys and values to mark
        type_mapping: Dictionary mapping keys to data types (e.g., {"Domain": "domain", "Username": "user"})

    Returns:
        New dictionary with marked values

    Example:
        >>> data = {"Domain": "example.local", "Username": "admin", "Target": "10.0.0.1"}
        >>> mapping = {"Domain": "domain", "Username": "user", "Target": "ip"}
        >>> marked = mark_dict_values(data, mapping)
        >>> # marked = {"Domain": "\\u200b[SENSITIVE:DOMAIN]\\u200bexample.local\\u200b[/SENSITIVE:DOMAIN]\\u200b", ...}
    """
    result = {}
    for key, value in data.items():
        data_type = type_mapping.get(key)
        if data_type:
            result[key] = mark_sensitive(str(value), data_type)
        else:
            result[key] = value
    return result


def _mark_operation_details(details: Dict[str, str]) -> Dict[str, str]:
    """Automatically mark sensitive values in operation details based on key patterns.

    This function intelligently detects sensitive data types based on dictionary key names
    and applies appropriate marking. Used by print_operation_header() and similar functions.

    Args:
        details: Dictionary of operation details (e.g., {"Domain": "example.local", "Username": "admin"})

    Returns:
        New dictionary with sensitive values marked

    Example:
        >>> details = {"Domain": "example.local", "PDC": "10.0.0.1", "Username": "admin"}
        >>> marked = _mark_operation_details(details)
        >>> # All sensitive values are marked with invisible markers
    """
    import re

    marked = {}

    for key, value in details.items():
        if not value or not isinstance(value, str):
            marked[key] = value
            continue

        key_lower = key.lower()
        value_lower = value.lower()

        # Detect IP addresses
        ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b"
        if re.search(ip_pattern, value):
            marked[key] = mark_sensitive(value, "ip")
            continue

        # Domain-related keys
        if any(
            keyword in key_lower for keyword in ["domain", "fqdn", "realm", "forest"]
        ):
            # Skip generic values
            if value_lower not in ["n/a", "-", "none", "any"]:
                marked[key] = mark_sensitive(value, "domain")
            else:
                marked[key] = value
            continue

        # User-related keys
        if any(
            keyword in key_lower for keyword in ["user", "account", "admin", "owner"]
        ):
            # Skip generic/anonymous values
            if value_lower not in ["n/a", "-", "none", "anonymous", "guest", "system"]:
                marked[key] = mark_sensitive(value, "user")
            else:
                marked[key] = value
            continue

        # Hostname/Computer keys (PDC, DC, Target Host, Computer, Server, etc.)
        # More specific patterns to avoid false positives like "Scan Target" or "Target Domain"
        if any(
            keyword in key_lower
            for keyword in [
                "pdc",
                "dc",
                "target host",
                "target computer",
                "target server",
                "computer name",
                "server name",
                "hostname",
            ]
        ) or (
            key_lower in ["host", "computer", "server"]
        ):  # Exact match only for these
            # Could be IP (already handled) or hostname/FQDN
            if not re.search(ip_pattern, value):
                # Check if it looks like a domain (has dots) or hostname
                if "." in value and value_lower not in ["n/a", "-"]:
                    # Could be FQDN - mark as domain
                    marked[key] = mark_sensitive(value, "domain")
                elif value_lower not in ["n/a", "-", "none", "any", "all"]:
                    # Hostname without domain
                    marked[key] = mark_sensitive(value, "hostname")
                else:
                    marked[key] = value
            else:
                # IP already marked above
                marked[key] = marked.get(key, value)
            continue

        # Path-related keys (Search Path, Output, Registry Key, etc.)
        if any(
            keyword in key_lower
            for keyword in ["path", "output", "directory", "folder", "file", "registry"]
        ):
            if value_lower not in ["n/a", "-", "none"]:
                marked[key] = mark_sensitive(value, "path")
            else:
                marked[key] = value
            continue

        # Service-related keys (Service, Protocol, Scan Target with specific services)
        if any(keyword in key_lower for keyword in ["service", "spn"]):
            if value_lower not in [
                "n/a",
                "-",
                "none",
                "smb",
                "ldap",
                "winrm",
                "rdp",
                "ssh",
                "http",
                "https",
            ]:
                # Don't mark generic protocol names, but mark specific service targets
                if "/" in value or "\\" in value:
                    # Looks like SPN or service path
                    marked[key] = mark_sensitive(value, "service")
                else:
                    marked[key] = value
            else:
                marked[key] = value
            continue

        # Password/Credential Type keys - mark the type but not generic values
        if any(
            keyword in key_lower
            for keyword in ["password", "hash", "credential", "secret"]
        ):
            # Only mark if it looks like actual credential data (long strings, hex patterns, etc.)
            if len(value) > 8 and value_lower not in [
                "password",
                "hash",
                "ntlm",
                "aes",
            ]:
                marked[key] = mark_sensitive(value, "password")
            else:
                marked[key] = value
            continue

        # Default: don't mark
        marked[key] = value

    return marked


# ---------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------


def _diag_enabled() -> bool:
    return os.getenv("ADSCAN_DIAG_LOGGING", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }


def _diag_log(message: str) -> None:
    if _diag_enabled():
        print(f"[DIAG][rich_output] {message}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Console init / getters
# ---------------------------------------------------------------------------


def init_rich_output(
    console: Console,
    verbose_mode: bool = False,
    debug_mode: bool = False,
    secret_mode: bool = False,
    logger: Optional[logging.Logger] = None,
):
    """Initialize the rich output module with console and mode flags.

    Args:
        console: Rich Console instance to use for output
        verbose_mode: Enable verbose output mode
        debug_mode: Enable debug output mode
        secret_mode: Enable secret mode (show internal details)
        logger: Optional logger instance (if None, will get from logging_config)
    """
    global _console, _verbose_mode, _debug_mode, _secret_mode, _logger
    previous_console = _console
    _console = console

    # CRITICAL FIX: If console is already initialized and modes are already active,
    # don't overwrite them with False values (prevents reset during module reimport)
    # Only update if:
    # 1. First initialization (_console is None), OR
    # 2. New values are "better" (activating modes that were previously False)
    if previous_console is None or previous_console is not console:
        # First initialization (or a new Console instance) - set all values
        _verbose_mode = verbose_mode
        _debug_mode = debug_mode
        _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: set modes (new console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
    else:
        # Already initialized - only update if new values are "better" (activating modes)
        # Don't deactivate modes that are already active
        if verbose_mode and not _verbose_mode:
            _verbose_mode = verbose_mode
        if debug_mode and not _debug_mode:
            _debug_mode = debug_mode
        if secret_mode and not _secret_mode:
            _secret_mode = secret_mode
        _diag_log(
            "init_rich_output: preserved modes (existing console) "
            f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
        )
        # Note: We intentionally don't deactivate modes here to prevent reset during reimport

    # Set logger if provided, otherwise get from logging_config
    if logger is not None:
        _logger = logger
        _diag_log("init_rich_output: logger injected")
    else:
        try:
            from adscan_core.logging_config import get_logger

            _logger = get_logger()
            _diag_log("init_rich_output: logger from logging_config")
        except ImportError:
            # Fallback: create basic logger if logging_config not available
            _logger = logging.getLogger("adscan")
            _diag_log("init_rich_output: fallback logger")


def set_telemetry_console(console: Optional[Console]) -> None:
    """Configure optional telemetry console used for session recordings.

    This console is intended to record ALL rendered output (at least for the
    high-level helpers in this module) regardless of verbose/debug flags, while
    the primary console continues to control what the end user actually sees.
    """
    global _telemetry_console
    _telemetry_console = console


def is_debug_mode() -> bool:
    """Return True when debug output mode is active."""
    return _debug_mode


def is_verbose_mode() -> bool:
    """Return True when verbose output mode is active."""
    return _verbose_mode


def update_modes(
    verbose_mode: Optional[bool] = None,
    debug_mode: Optional[bool] = None,
    secret_mode: Optional[bool] = None,
):
    """Update mode flags dynamically.

    Args:
        verbose_mode: New verbose mode value (None to keep current)
        debug_mode: New debug mode value (None to keep current)
        secret_mode: New secret mode value (None to keep current)
    """
    global _verbose_mode, _debug_mode, _secret_mode
    if verbose_mode is not None:
        _verbose_mode = verbose_mode
    if debug_mode is not None:
        _debug_mode = debug_mode
    if secret_mode is not None:
        _secret_mode = secret_mode

    _diag_log(
        "update_modes: "
        f"verbose={_verbose_mode}, debug={_debug_mode}, secret={_secret_mode}"
    )

    # Update logging console level when modes change
    try:
        from adscan_core.logging_config import update_logging_console_level

        update_logging_console_level(
            verbose_mode=_verbose_mode,
            debug_mode=_debug_mode,
        )
    except ImportError:
        pass  # logging_config not available, skip


def _get_console() -> Console:
    """Get the global console instance."""
    if _console is None:
        return Console()
    return _console


def _get_telemetry_console() -> Optional[Console]:
    """Get the optional telemetry console instance."""
    return _telemetry_console


def get_console() -> Console:
    """Public accessor for the shared Rich console instance."""
    return _get_console()


def set_output_config(
    *, verbose: bool, debug: bool, telemetry_console: Optional[Console] = None
) -> None:
    """Configure shared Rich output + logging modes.

    This is the canonical setup path for both launcher and runtime callers.
    It mirrors the initialization sequence used by the monolithic CLI:
    1. Initialize Rich-aware logging handlers.
    2. Bind shared console/logger into rich_output.
    3. Apply runtime modes (verbose/debug/secret).
    """
    from adscan_core.logging_config import init_logging

    console = get_console()
    secret_mode = debug

    logger = init_logging(
        console=console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        telemetry_console=telemetry_console,
    )
    init_rich_output(
        console,
        verbose_mode=verbose,
        debug_mode=debug,
        secret_mode=secret_mode,
        logger=logger,
    )
    if telemetry_console is not None:
        set_telemetry_console(telemetry_console)
    # Lazy import to avoid circular dependency: _prompts -> _state -> _prompts
    from adscan_core.output._prompts import install_prompt_logging_wrappers  # noqa: PLC0415

    install_prompt_logging_wrappers()
    update_modes(verbose_mode=verbose, debug_mode=debug, secret_mode=secret_mode)


# ---------------------------------------------------------------------------
# Prompt-mode helpers
# ---------------------------------------------------------------------------


def configure_prompt_behavior(
    *,
    should_disable_interactive_prompts: Callable[[object | None], bool] | None = None,
    interrupt_logger: Callable[[str, str], None] | None = None,
    use_questionary_in_container: Callable[[], bool] | None = None,
) -> None:
    """Configure centralized prompt behavior hooks.

    Args:
        should_disable_interactive_prompts: Predicate used to decide whether
            prompts must auto-resolve defaults (non-interactive runs).
        interrupt_logger: Callable invoked on EOF/KeyboardInterrupt.
        use_questionary_in_container: Predicate to enable Questionary fallback
            for Prompt/Confirm when running in container runtime.
    """
    from adscan_core import prompting

    prompting.configure_prompt_behavior(
        should_disable_interactive_prompts=should_disable_interactive_prompts,
        interrupt_logger=interrupt_logger,
        use_questionary_in_container=use_questionary_in_container,
    )


def set_prompt_auto_mode(active: bool) -> None:
    """Enable/disable centralized prompt auto-mode."""
    from adscan_core import prompting

    prompting.set_prompt_auto_mode(active)


def is_prompt_auto_mode_enabled() -> bool:
    """Return whether centralized prompt auto-mode is currently active."""
    from adscan_core import prompting

    return prompting.is_prompt_auto_mode_enabled()


def _should_disable_prompt_interaction(shell: object | None = None) -> bool:
    """Best-effort predicate for non-interactive prompt behavior."""
    from adscan_core import prompting

    return prompting.should_disable_prompt_interaction(shell)


def _emit_prompt_interrupt_debug(*, kind: str, source: str) -> None:
    """Emit standardized interrupt debug messages for prompt flows."""
    from adscan_core import prompting

    # Lazy import to avoid circular dependency
    from adscan_core.rich_output import print_info_debug  # noqa: PLC0415

    prompting.emit_prompt_interrupt_debug(
        kind=kind, source=source, debug=print_info_debug
    )


def _should_use_questionary_prompt() -> bool:
    """Return True when Prompt/Confirm should use Questionary fallback."""
    from adscan_core import prompting

    return prompting.should_use_questionary_prompt()


# ---------------------------------------------------------------------------
# TelemetryAwareConsole
# ---------------------------------------------------------------------------


class TelemetryAwareConsole:
    """Wrapper console that duplicates output to a telemetry console.

    This ensures that direct console.print() calls in the shell (e.g. do_help tables)
    are captured in the session recording, not just output routed through the
    logging system or rich_output helpers.
    """

    def __init__(self, main_console, telemetry_console):
        self.main_console = main_console
        self.telemetry_console = telemetry_console

    def print(self, *args, **kwargs):
        self.main_console.print(*args, **kwargs)
        if self.telemetry_console:
            self.telemetry_console.print(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self.main_console, name)


__all__ = [
    # accessors / init
    "get_console",
    "set_telemetry_console",
    "init_rich_output",
    "set_output_config",
    "update_modes",
    "is_debug_mode",
    "is_verbose_mode",
    # prompt-mode helpers
    "configure_prompt_behavior",
    "set_prompt_auto_mode",
    "is_prompt_auto_mode_enabled",
    # sensitive masking
    "strip_sensitive_markers",
    "mark_passthrough",
    "mark_sensitive",
    "mark_dict_values",
    # console wrapper
    "TelemetryAwareConsole",
]
