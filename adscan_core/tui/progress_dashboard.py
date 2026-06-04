"""Reusable live progress dashboard for long-running ADscan operations.

Single source of truth for the "this operation is alive" UX. Wraps
:class:`adscan_core.tui.LiveSession` with the mandatory premium pattern
(``alt_screen=True`` + a ``summary`` callback) and owns the vocabulary every
long op shares: an ``X / N`` progress bar, throughput (items/s), ETA, the
secondary success/error/in-flight counter row, and a single "last item" line
whose value ALWAYS goes through :func:`mark_sensitive` (the dashboard is
mirrored to the telemetry console via ``_TeeConsole`` — an unmasked host here
would be an exfiltration leak, see CLAUDE.md § Sensitive-Data and the design
spec § 6).

Two modes:

* **Determinate** (``total`` is an int): full ``X / N`` bar + rate + ETA.
* **Indeterminate** (``total is None``): spinner + elapsed + "found N so far".
  Used by opaque subprocess ops (manspider, nmap) and subprocess ops whose
  stdout is not reliably parseable (kerbrute userenum).

The module is dependency-light: it imports only ``adscan_core`` primitives so
it stays importable from launcher, services and CLI alike. Do NOT import
``adscan_internal`` here.
"""

from __future__ import annotations

import itertools
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Callable, Iterator, Optional

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.progress_bar import ProgressBar
from rich.table import Table
from rich.text import Text

from adscan_core.sensitive import mark_sensitive
from adscan_core.theme import (
    ADSCAN_PRIMARY,
    ADSCAN_PRIMARY_BRIGHT,
    COLOR_AMBER,
    COLOR_MUTED,
    COLOR_SAGE,
)
from adscan_core.tui.live_session import LiveSession, LiveSessionConfig

__all__ = ["ProgressDashboard", "ProgressDashboardConfig", "format_eta"]

# Braille spinner frames — the modern default per tui-design § 5.
_SPINNER_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def format_eta(seconds: Optional[float]) -> str:
    """Format a seconds count as a compact ``Xh Ym`` / ``Xm Ys`` / ``Xs`` string.

    Args:
        seconds: Remaining seconds, or ``None`` when unknown.

    Returns:
        ``"--"`` when ``seconds`` is ``None``; otherwise a human-readable
        duration capped at two units.
    """
    if seconds is None:
        return "--"
    secs = int(round(seconds))
    if secs <= 0:
        return "0s"
    if secs < 60:
        return f"{secs}s"
    if secs < 3600:
        return f"{secs // 60}m {secs % 60}s"
    hours = secs // 3600
    minutes = (secs % 3600) // 60
    return f"{hours}h {minutes}m"


@dataclass(frozen=True)
class ProgressDashboardConfig:
    """Static configuration for a :class:`ProgressDashboard`.

    Attributes:
        title: Operation name shown in the panel title (English only).
        total: Total item count for determinate mode, or ``None`` for the
            indeterminate spinner mode.
        unit: Plural noun for the items ("hosts", "users", "shares").
        last_item_type: ``mark_sensitive`` data_type for the "last item"
            value ("hostname", "ip", "user"). When ``None`` the last-item
            line is suppressed.
        show_counters: Render the success/error/in-flight counter row.
        refresh_per_second: Forwarded to :class:`LiveSessionConfig`.
    """

    title: str
    total: Optional[int]
    unit: str = "items"
    last_item_type: Optional[str] = None
    show_counters: bool = True
    refresh_per_second: int = 8


class ProgressDashboard:
    """Live progress surface driven by :meth:`update`.

    Construct one, drive it inside :meth:`live_session` (sync) or
    :meth:`async_live_session` (async), calling :meth:`update` per completed
    item. The dashboard computes rate + ETA internally; the caller only
    supplies cumulative counts.
    """

    def __init__(
        self,
        config: ProgressDashboardConfig,
        *,
        _clock: Callable[[], float] = time.monotonic,
    ) -> None:
        """Initialise the dashboard.

        Args:
            config: Static :class:`ProgressDashboardConfig`.
            _clock: Injected monotonic clock (tests pass a deterministic one).
        """
        self._config = config
        self._clock = _clock
        self._start = _clock()
        self._elapsed_snapshot = 0.0
        self._done = 0
        self._success = 0
        self._error = 0
        self._in_flight = 0
        self._last: Optional[str] = None
        self._last_detail: Optional[str] = None
        self._spinner: Iterator[str] = itertools.cycle(_SPINNER_FRAMES)
        self._spinner_frame = next(self._spinner)
        self._session: Optional[LiveSession] = None

    # ------------------------------------------------------------------
    # Derived metrics
    # ------------------------------------------------------------------

    @property
    def elapsed(self) -> float:
        """Seconds since construction (snapshot taken at the last update)."""
        return self._elapsed_snapshot

    @property
    def rate(self) -> float:
        """Throughput in items/second (0.0 before any time has elapsed)."""
        elapsed = self.elapsed
        if elapsed <= 0 or self._done <= 0:
            return 0.0
        return self._done / elapsed

    @property
    def eta_seconds(self) -> Optional[float]:
        """Estimated seconds remaining, or ``None`` in indeterminate mode."""
        total = self._config.total
        if total is None or total <= 0:
            return None
        rate = self.rate
        if rate <= 0:
            return None
        remaining = max(0, total - self._done)
        return remaining / rate

    # ------------------------------------------------------------------
    # Drive API
    # ------------------------------------------------------------------

    def update(
        self,
        *,
        done: Optional[int] = None,
        success: Optional[int] = None,
        error: Optional[int] = None,
        in_flight: Optional[int] = None,
        last: Optional[str] = None,
        last_detail: Optional[str] = None,
    ) -> None:
        """Update cumulative counts and push a new frame to Live.

        All count args are CUMULATIVE (totals so far), not deltas. Omitted
        args leave the prior value unchanged. ``last`` is the raw item value
        (host/ip/user) — it is masked at RENDER time, never stored masked.

        Args:
            done: Items completed so far.
            success: Items that succeeded so far.
            error: Items that errored so far.
            in_flight: Items currently being processed.
            last: Raw value for the "last item" line (masked at render).
            last_detail: Optional pre-formatted detail string for the line
                (e.g. "shares 3 · sessions 7"); rendered after the value.
        """
        if done is not None:
            self._done = done
        if success is not None:
            self._success = success
        if error is not None:
            self._error = error
        if in_flight is not None:
            self._in_flight = in_flight
        if last is not None:
            self._last = last
            self._last_detail = last_detail
        self._elapsed_snapshot = max(0.0, self._clock() - self._start)
        self._spinner_frame = next(self._spinner)
        if self._session is not None:
            self._session.update(self.render())

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def render(self) -> RenderableType:
        """Build the current dashboard renderable (Panel)."""
        rows: list[RenderableType] = []
        detail_line = self._render_detail_line()
        if detail_line is not None:
            rows.append(detail_line)
        rows.append(self._render_progress_line())
        if self._config.show_counters:
            rows.append(self._render_counter_row())
        last_line = self._render_last_line()
        if last_line is not None:
            rows.append(last_line)
        title = Text(self._config.title, style=f"bold {ADSCAN_PRIMARY_BRIGHT}")
        return Panel(
            Group(*rows),
            title=title,
            title_align="left",
            border_style=ADSCAN_PRIMARY,
            padding=(0, 1),
        )

    def _render_detail_line(self) -> Optional[RenderableType]:
        """Determinate-mode subtitle: the scope of the run (total + unit)."""
        total = self._config.total
        if total is None or total <= 0:
            return None
        return Text(f"{total} reachable {self._config.unit}", style=COLOR_MUTED)

    def _render_progress_line(self) -> RenderableType:
        total = self._config.total
        grid = Table.grid(expand=True, padding=(0, 1))
        grid.add_column(justify="left", ratio=1)
        grid.add_column(justify="right")
        if total is not None and total > 0:
            bar = ProgressBar(
                total=total,
                completed=min(self._done, total),
                width=28,
                complete_style=ADSCAN_PRIMARY_BRIGHT,
                finished_style=COLOR_SAGE,
                style=COLOR_MUTED,
            )
            count = Text(f"  {self._done} / {total} {self._config.unit}",
                         style=ADSCAN_PRIMARY)
            left = Table.grid(padding=(0, 0))
            left.add_row(bar, count)
            right = Text(
                f"rate {self.rate:.0f}/s · ETA {format_eta(self.eta_seconds)}",
                style=COLOR_MUTED,
            )
            grid.add_row(left, right)
        else:
            # Indeterminate: spinner + elapsed + "found N".
            left = Text(
                f"{self._spinner_frame} working… "
                f"found {self._done} {self._config.unit}",
                style=ADSCAN_PRIMARY,
            )
            right = Text(f"elapsed {format_eta(self.elapsed)}", style=COLOR_MUTED)
            grid.add_row(left, right)
        return grid

    def _render_counter_row(self) -> RenderableType:
        row = Table.grid(padding=(0, 2))
        row.add_row(
            Text(f"✓ {self._config.unit} {self._success}", style=COLOR_SAGE),
            Text(f"⚠ errors {self._error}", style=COLOR_AMBER),
            Text(f"⏳ in-flight {self._in_flight}", style=COLOR_MUTED),
        )
        return row

    def _render_last_line(self) -> Optional[RenderableType]:
        if self._config.last_item_type is None or self._last is None:
            return None
        masked = mark_sensitive(self._last, self._config.last_item_type)
        text = Text("last: ", style=COLOR_MUTED)
        text.append(masked, style=ADSCAN_PRIMARY)
        if self._last_detail:
            text.append("  ·  ", style=COLOR_MUTED)
            text.append(self._last_detail, style=COLOR_MUTED)
        return text

    # ------------------------------------------------------------------
    # LiveSession lifecycle
    # ------------------------------------------------------------------

    def _live_config(self) -> LiveSessionConfig:
        return LiveSessionConfig(
            refresh_per_second=self._config.refresh_per_second,
            alt_screen=True,
        )

    def _summary(self, console) -> None:
        """Re-print the final dashboard to scrollback after the alt-screen pops."""
        try:
            console.print(self.render())
        except Exception:  # noqa: BLE001 — summary must never break the flow
            pass

    @contextmanager
    def live_session(self) -> Iterator["ProgressDashboard"]:
        """Sync context manager: enters a LiveSession bound to this dashboard."""
        session = LiveSession(
            self.render(), config=self._live_config(), summary=self._summary
        )
        self._session = session
        with session:
            try:
                yield self
            finally:
                self._session = None

    def async_live_session(self) -> "_AsyncDashboardSession":
        """Async context manager equivalent of :meth:`live_session`."""
        return _AsyncDashboardSession(self)


class _AsyncDashboardSession:
    """Async-context wrapper binding a :class:`LiveSession` to a dashboard."""

    def __init__(self, dashboard: ProgressDashboard) -> None:
        self._dashboard = dashboard
        self._session: Optional[LiveSession] = None

    async def __aenter__(self) -> ProgressDashboard:
        self._session = LiveSession(
            self._dashboard.render(),
            config=self._dashboard._live_config(),
            summary=self._dashboard._summary,
        )
        self._dashboard._session = self._session
        await self._session.__aenter__()
        return self._dashboard

    async def __aexit__(self, exc_type, exc, tb) -> bool | None:
        self._dashboard._session = None
        if self._session is not None:
            await self._session.__aexit__(exc_type, exc, tb)
        return None
