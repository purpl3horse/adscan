"""Post-scan ``Scan complete`` panel.

Tier-aware: LITE shows scan results, LITE-friendly next commands, and a
single line mentioning the PRO Client Deliverable Kit. PRO shows the full
deliverable kit as actionable next steps.

GIVE first, ASK at end (LITE) or pure GIVE (PRO). The earlier registry-
driven implementation surfaced PRO-only verbs to LITE users, which is a
give/ask regression — this module is the canonical fix.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from adscan_core import tier
from adscan_core.rich_output import print_panel
from adscan_internal.cli.shell_commands import (
    ShellCommandSpec,
    specs_suggested_after,
)


# LITE-friendly next-step commands. Each verb MUST map to a real
# ``PentestShell.do_<verb>`` method that is usable in LITE — no deliverable
# PDF verbs (those are PRO-gated and surfaced via the demo line below). The
# anti-drift test ``tests/unit/cli/test_post_scan_lite_commands_exist.py``
# fails CI if a verb here has no matching ``do_<verb>`` or is a deliverable.
_LITE_NEXT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("attack_paths", "explore the attack graph"),
)


@dataclass(frozen=True)
class ScanSummary:
    """Severity counts pulled from the scan summary, when available."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    report_path: str | None = None

    def render_findings_line(self) -> str:
        return (
            f"{self.critical} critical · {self.high} high · {self.medium} medium"
        )


def _render_header(summary: ScanSummary | None) -> list[str]:
    """Render the GIVE: scan results header. Always first."""
    findings = summary.render_findings_line() if summary else "— · — · —"
    report = (summary.report_path if summary else None) or "(see workspace)"
    return [
        f"  [bold]Findings:[/] [grey70]{findings}[/]",
        f"  [bold]Report:[/]   [bright_cyan]{report}[/]",
    ]


def _render_lite_body(summary: ScanSummary | None) -> str:
    lines: list[str] = []
    lines.extend(_render_header(summary))
    lines.append("")
    lines.append("  [bold bright_cyan]Next:[/]")
    verb_width = max(len(v) for v, _ in _LITE_NEXT_COMMANDS)
    for verb, desc in _LITE_NEXT_COMMANDS:
        verb_cell = f"[bright_cyan on grey11]{verb.ljust(verb_width)}[/]"
        lines.append(f"    {verb_cell}    [grey70]{desc}[/]")
    lines.append("")
    lines.append(
        "  [grey70]PRO ships a client deliverable kit. "
        "See [bold bright_cyan]adscan demo[/].[/]"
    )
    return "\n".join(lines)


def _render_pro_body(
    summary: ScanSummary | None,
    suggestions: Iterable[ShellCommandSpec],
) -> str:
    rows = list(suggestions)
    lines: list[str] = []
    lines.extend(_render_header(summary))
    lines.append("")
    lines.append("  [bold bright_cyan]Generate the client deliverable:[/]")
    if not rows:
        return "\n".join(lines)
    verb_width = max(len(s.verb) for s in rows)
    for spec in rows:
        verb_cell = f"[bright_cyan on grey11]{spec.verb.ljust(verb_width)}[/]"
        lines.append(f"    {verb_cell}    [grey70]{spec.short_help}[/]")
    return "\n".join(lines)


def print_post_scan_suggestions(
    verb: str,
    summary: ScanSummary | None = None,
) -> None:
    """Render the ``Scan complete`` panel for the operator.

    LITE users see scan results, LITE-friendly next commands, and a single
    line mentioning the PRO kit. PRO users see the full deliverable kit
    as actionable next steps. Output is silent when the verb has no
    suggestions registered AND no summary is provided — keeps the success
    paths clean for non-scan flows that wire this in defensively.

    Args:
        verb: The shell verb that just completed successfully (e.g.
            ``"start_auth"`` or ``"start_unauth"``).
        summary: Optional :class:`ScanSummary` with finding counts. When
            omitted, placeholder dashes are rendered — caller should
            populate this once the scan summary is available.
    """
    is_pro = tier.is_pro()
    suggestions = specs_suggested_after(verb)

    # Silent for unknown verbs unless we have something concrete to show
    # (a summary). Preserves the existing no-op contract for non-scan
    # flows.
    if not suggestions and summary is None:
        return

    if is_pro:
        body = _render_pro_body(summary, suggestions)
    else:
        body = _render_lite_body(summary)

    if not body:
        return

    print_panel(
        body,
        title="[bold bright_cyan]Scan complete[/]",
        border_style="bright_cyan",
        title_align="left",
        padding=(1, 2),
    )


__all__ = ["print_post_scan_suggestions", "ScanSummary"]
