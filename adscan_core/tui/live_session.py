"""Premium TUI session — single source of truth for ``rich.live.Live``.

Every Live surface in ADscan goes through :class:`LiveSession`. The class
wraps :class:`rich.live.Live` with the defaults that ship a premium-grade
terminal experience and that prevent the four recurring failure modes we
have shipped slices to fix in the past:

1. **Header stacking.** Without ``redirect_stdout``/``redirect_stderr``,
   any ``print_*`` call issued while Live is rendering inserts a fresh
   block above the live region — every refresh "stamps" a new header.
   ``LiveSession`` always sets the redirects on TTYs.
2. **Scrollback leak.** Live updates that grow in height push earlier
   frames into the user's scrollback. ``screen=True`` (alt-screen buffer)
   contains the entire dashboard inside an isolated scroll region;
   when the session exits, the alt-screen pops cleanly and only the
   :paramref:`summary` callback writes to the permanent scrollback.
3. **Non-TTY breakage.** CI runs, pytest captured stdout and shell pipes
   do not support alt-screen escape codes. ``LiveSession`` detects this
   via :pyattr:`rich.console.Console.is_terminal` (and the
   ``ADSCAN_NO_LIVE`` env var) and falls back to inline plain-text
   logging — the same caller code works in both modes.
4. **Signal-handling corruption.** A ``Ctrl-C`` while alt-screen is
   active must pop the screen before the traceback is printed,
   otherwise the user is left staring at an empty alt-screen until they
   blindly type ``reset``. ``LiveSession`` installs an interrupt hook
   that tears Live down cleanly, runs the optional callback for partial
   output, then re-raises.

The module is intentionally framework-light: no ``adscan_internal``
imports. It is safe to use from launcher code, services and CLI alike.
"""

from __future__ import annotations

import asyncio
import os
import sys
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Callable, Optional

from rich.console import Console
from rich.live import Live

if TYPE_CHECKING:
    from rich.console import RenderableType


__all__ = ["LiveSession", "LiveSessionConfig"]


# Env var honoured by the legacy widgets (``trust_enum_live``, etc.) — kept
# so customers that already export it for paranoid engagements keep getting
# the inline-logging behaviour after the migration.
_NO_LIVE_ENV = "ADSCAN_NO_LIVE"


@dataclass(frozen=True)
class LiveSessionConfig:
    """Premium-CLI defaults for a :class:`LiveSession`.

    Override per call site only when the call site has a documented UX
    reason. The defaults are tuned for the most common case (long-running
    dashboard, interactive operator, scrollback must stay clean).

    Attributes:
        refresh_per_second: How often Live re-renders the cached
            renderable. ``8`` matches the existing ``cves_native`` /
            widget cadence; bump to ``10`` only for sub-second progress
            visuals (timeroasting).
        alt_screen: When ``True`` and the console is a TTY, Live renders
            inside the terminal's alternate-screen buffer. On exit the
            alt-screen pops back to normal and only the summary block
            stays in scrollback. Disable when the call site relies on
            inline scrolling (small progress bars, transient renders).
        redirect_io: When ``True``, ``stdout``/``stderr`` are routed
            through Live so concurrent ``print_*`` calls interleave with
            the live region instead of stacking headers above it.
        transient: Forwarded to :class:`rich.live.Live`. Only honoured
            when ``alt_screen`` is ``False`` — alt-screen already wipes
            the dashboard on exit.
        show_summary_on_exit: Whether to invoke the optional ``summary``
            callback after Live exits. Set to ``False`` to suppress
            persistent output (e.g. when the caller prints its own
            recap).
    """

    refresh_per_second: int = 8
    alt_screen: bool = True
    redirect_io: bool = True
    transient: bool = False
    show_summary_on_exit: bool = True


def _resolve_console() -> Console:
    """Return the shared ADscan console, falling back to a plain one.

    ``LiveSession`` must work even before ``adscan_core.rich_output`` has
    been initialised (early launcher path, structural tests). When the
    shared console is unavailable we construct a default :class:`Console`
    so the abstraction never raises during import.
    """
    try:
        from adscan_core.output._state import get_console as _get_console

        return _get_console()
    except Exception:  # noqa: BLE001 — defensive, never propagate
        return Console()


def _is_no_live_env() -> bool:
    """True when the operator has opted out of Live UIs via env."""
    return os.environ.get(_NO_LIVE_ENV, "") == "1"


def _renderable_summary_text(renderable: "RenderableType", console: Console) -> str:
    """Best-effort one-line digest of a Rich renderable for non-TTY logs.

    We deliberately pass through :meth:`Console.render` so styled text,
    tables and panels degrade to readable plain text without colour
    codes. The first non-empty line is returned; everything else is
    truncated so the inline log never floods the operator's terminal.
    """
    try:
        with console.capture() as capture:
            console.print(renderable, no_wrap=False, soft_wrap=False)
        text = capture.get().strip()
    except Exception:  # noqa: BLE001
        return ""
    if not text:
        return ""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


class LiveSession:
    """Premium TUI session wrapping :class:`rich.live.Live`.

    Use as a synchronous context manager from sync callers, and as an
    asynchronous context manager from coroutine callers. The two flavours
    are equivalent — ``__aenter__``/``__aexit__`` simply delegate to the
    sync entry/exit so callers do not need to think about which version
    the caller is on.

    Example:
        ```python
        from adscan_core.tui import LiveSession, LiveSessionConfig

        config = LiveSessionConfig(refresh_per_second=8)
        with LiveSession(dashboard.render(), config=config) as session:
            for event in stream:
                session.update(dashboard.render())
        ```

    On non-TTY consoles (CI, pytest captured stdout, ``ADSCAN_NO_LIVE=1``)
    the session never enters Live; ``update()`` emits a one-line digest
    and ``announce()`` prints the message verbatim. The same code keeps
    working without branches in the caller.
    """

    def __init__(
        self,
        renderable: "RenderableType",
        *,
        config: LiveSessionConfig | None = None,
        summary: Callable[[Console], None] | None = None,
        on_interrupt: Callable[[], None] | None = None,
    ) -> None:
        """Initialise the session.

        Args:
            renderable: The initial Rich renderable to display.
            config: Optional override of the default
                :class:`LiveSessionConfig`. The defaults are correct for
                most call sites — only override when there is a
                documented UX reason.
            summary: Optional callback invoked once after Live exits and
                the alt-screen has popped. Receives the shared
                :class:`Console`. Use this for the persistent recap that
                stays in the operator's scrollback.
            on_interrupt: Optional callback invoked on
                :class:`KeyboardInterrupt`. Runs after Live tears down
                cleanly but before the exception is re-raised. Use this
                to print a partial summary so Ctrl-C never leaves the
                operator with a blank terminal.
        """
        self._renderable = renderable
        self._config = config or LiveSessionConfig()
        self._summary = summary
        self._on_interrupt = on_interrupt
        self._console = _resolve_console()
        self._live: Optional[Live] = None
        # ``is_live`` is decided at __enter__ time and cached so the rest
        # of the lifecycle never has to re-check sys.stdout / env vars.
        self._is_live: bool = False
        self._entered: bool = False

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def console(self) -> Console:
        """Shared Rich console — same instance ``print_*`` writes to."""
        return self._console

    @property
    def is_live(self) -> bool:
        """``True`` when Live is rendering (TTY mode), ``False`` otherwise."""
        return self._is_live

    # ------------------------------------------------------------------
    # Sync context
    # ------------------------------------------------------------------

    def __enter__(self) -> "LiveSession":
        """Enter Live (TTY) or set up inline-logging fallback (non-TTY)."""
        self._entered = True
        self._is_live = bool(self._console.is_terminal) and not _is_no_live_env()
        if not self._is_live:
            # Non-TTY: emit the initial frame as a single digest line so
            # the operator at least sees what the dashboard would have
            # shown.
            self._inline_log(self._renderable)
            return self

        live_kwargs: dict[str, Any] = {
            "console": self._console,
            "refresh_per_second": self._config.refresh_per_second,
        }
        if self._config.redirect_io:
            live_kwargs["redirect_stdout"] = True
            live_kwargs["redirect_stderr"] = True
        if self._config.alt_screen:
            # Alt-screen makes ``transient`` redundant — the buffer pop
            # already wipes the dashboard. Forwarding both confuses Rich
            # on some terminals, so we honour ``transient`` only in the
            # non-alt-screen branch.
            live_kwargs["screen"] = True
        else:
            live_kwargs["transient"] = self._config.transient

        self._live = Live(self._renderable, **live_kwargs)
        try:
            self._live.__enter__()
        except Exception:
            # If Live failed to start (rare — locked terminal, exotic
            # env) we degrade to inline logging so the caller still gets
            # useful output instead of crashing.
            self._live = None
            self._is_live = False
            self._inline_log(self._renderable)
        return self

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        """Tear Live down, then run summary / interrupt callbacks."""
        try:
            if self._live is not None:
                # Flush the last cached frame so the alt-screen captures
                # the final state before popping.
                with suppress(Exception):
                    self._live.refresh()
                with suppress(Exception):
                    self._live.__exit__(exc_type, exc, tb)
                self._live = None
                self._is_live = False

            # Interrupt path runs before summary so partial summaries
            # stay clean even if the operator hit Ctrl-C mid-scan.
            if exc_type is KeyboardInterrupt and self._on_interrupt is not None:
                with suppress(Exception):
                    self._on_interrupt()

            if (
                exc_type is None
                and self._summary is not None
                and self._config.show_summary_on_exit
            ):
                # Only run the success-path summary when the body
                # finished cleanly. Errors get the interrupt callback or
                # propagate as-is.
                self._summary(self._console)
        finally:
            # Never swallow exceptions — re-raising is the caller's
            # contract. Returning ``None`` (the default) lets Python
            # propagate ``exc`` if any.
            pass
        return None

    # ------------------------------------------------------------------
    # Async context — delegates to sync. We use ``asyncio.to_thread`` so
    # that on a heavily-loaded loop the alt-screen entry/exit syscalls
    # don't block the event loop, but the entry/exit semantics remain
    # identical to the sync path.
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "LiveSession":
        """Async-context entry — equivalent to the sync ``__enter__``."""
        await asyncio.to_thread(self.__enter__)
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> bool | None:
        """Async-context exit — equivalent to the sync ``__exit__``."""
        await asyncio.to_thread(self.__exit__, exc_type, exc, tb)
        return None

    # ------------------------------------------------------------------
    # Update / announce API
    # ------------------------------------------------------------------

    def update(self, renderable: "RenderableType", *, refresh: bool = False) -> None:
        """Replace the live renderable.

        Args:
            renderable: New Rich renderable to display.
            refresh: When ``True`` force an immediate re-render rather
                than waiting for the next refresh tick. Mirrors
                :meth:`rich.live.Live.update`.
        """
        self._renderable = renderable
        if self._live is not None:
            with suppress(Exception):
                self._live.update(renderable, refresh=refresh)
            return
        if self._is_live:
            # Live failed to start but ``is_live`` was True at entry —
            # this should not happen, but if it does we still want the
            # inline log so the operator sees progress.
            self._inline_log(renderable)
            return
        # Non-TTY: log the digest line.
        self._inline_log(renderable)

    def announce(self, message: str, *, severity: str = "info") -> None:
        """Surface a one-line status line to the operator.

        On TTY consoles the renderable is expected to expose its own
        "activity" region; this method is a stub for that layout — it
        only writes to the Live region if the renderable is a
        :class:`rich.layout.Layout` with a region named ``activity``,
        otherwise it is a no-op (TTY) or a plain print (non-TTY).

        Args:
            message: Human-readable status line.
            severity: One of ``"info"``, ``"warning"``, ``"error"``.
                Used to colour the line in non-TTY mode and for the
                ``activity`` region styling.
        """
        if self._is_live:
            self._update_activity_region(message, severity=severity)
            return
        # Non-TTY: emit a styled plain line. Severity-based colour is
        # purely advisory — the console may strip styling.
        style = {
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
        }.get(severity, "cyan")
        self._console.print(f"[{style}]{message}[/{style}]")

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _update_activity_region(self, message: str, *, severity: str) -> None:
        """Write ``message`` into the renderable's ``activity`` region.

        No-op when the cached renderable does not expose a Layout with
        that region — the abstraction must not break call sites that do
        not opt into the activity convention.
        """
        try:
            from rich.layout import (
                Layout,
            )  # local import: avoid Rich layout cost on non-TTY
            from rich.text import Text
        except Exception:  # noqa: BLE001
            return
        if not isinstance(self._renderable, Layout):
            return
        try:
            region = self._renderable["activity"]
        except (KeyError, IndexError, AttributeError):
            return
        style = {
            "info": "cyan",
            "warning": "yellow",
            "error": "red",
        }.get(severity, "cyan")
        with suppress(Exception):
            region.update(Text(message, style=style))
            if self._live is not None:
                with suppress(Exception):
                    self._live.refresh()

    def _inline_log(self, renderable: "RenderableType") -> None:
        """Emit a single readable line for non-TTY consumers."""
        line = _renderable_summary_text(renderable, self._console)
        if line:
            # ``file=sys.stderr`` would split the stream from
            # ``print_*`` output; we keep stdout to match the rest of
            # ADscan's logging conventions.
            print(line, file=sys.stdout, flush=True)
