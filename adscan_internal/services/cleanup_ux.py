"""Rich terminal UX for environment change ledger summary display."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from rich.console import Group
from rich.table import Table
from rich.text import Text

from adscan_internal.rich_output import mark_sensitive, print_panel

if TYPE_CHECKING:
    from adscan_internal.services.environment_change_ledger import EnvironmentChangeLedger

_STATUS_ICON: dict[str, str] = {
    "reverted": "✓",
    "kept": "★",
    "pending": "●",
    "failed": "✗",
    "operator_required": "⚠",
    "not_applicable": "–",
}

_STATUS_STYLE: dict[str, str] = {
    "reverted": "green",
    "kept": "cyan",
    "pending": "dim",
    "failed": "bold red",
    "operator_required": "yellow",
    "not_applicable": "dim",
}

_KIND_DISPLAY: dict[str, str] = {
    "group_membership_added":   "Group membership",
    "file_uploaded":            "File upload",
    "user_created":             "User created",
    "password_changed":         "Password reset",
    "template_modified":        "Template modified",
    "acl_modified":             "ACL modified",
    "shadow_credentials_added": "Shadow credentials",
    "dacl_ace_added":           "DACL ACE (GenericAll)",
    "owner_changed":            "Object owner",
    "spn_added":                "SPN (Kerberoast)",
    "machine_account_created":  "Machine account",
    "rbcd_delegation_added":    "RBCD delegation",
    "keycredentiallink_added":  "KeyCredentialLink",
}


class _ChangesTable(Table):
    """Rich Table subclass that exposes ``column_count`` as a convenience property."""

    @property
    def column_count(self) -> int:
        """Return the number of columns currently defined in the table."""
        return len(self.columns)


def render_cleanup_exit_panel(ledger: "EnvironmentChangeLedger") -> None:
    """Render the cleanup summary panel at scan exit. No-op when no changes.

    Args:
        ledger: EnvironmentChangeLedger instance with recorded changes.
    """
    changes = ledger.get_changes()
    if not changes:
        return

    summary = ledger.get_summary()
    reverted = [c for c in changes if c.get("revert_status") == "reverted"]
    kept = [c for c in changes if c.get("revert_status") == "kept"]
    needs_action = [
        c for c in changes
        if c.get("revert_status") in ("operator_required", "failed", "pending")
    ]

    renderables: list[Any] = []

    if reverted:
        count = len(reverted)
        renderables.append(
            Text(
                f"✓ REVERTED                        {count} change{'s' if count != 1 else ''}",
                style="bold green",
            )
        )
        renderables.append(_build_changes_table(reverted, show_instructions=False))

    if kept:
        if renderables:
            renderables.append(Text(""))
        count = len(kept)
        renderables.append(
            Text(
                f"★ KEPT BY OPERATOR                {count} change{'s' if count != 1 else ''}",
                style="bold cyan",
            )
        )
        renderables.append(_build_changes_table(kept, show_instructions=False))

    if needs_action:
        if renderables:
            renderables.append(Text(""))
        count = len(needs_action)
        renderables.append(
            Text(
                f"⚠ REQUIRES MANUAL ACTION          {count} change{'s' if count != 1 else ''}",
                style="bold yellow",
            )
        )
        renderables.append(_build_changes_table(needs_action, show_instructions=True))

    border_style = "green"
    if summary.get("failed", 0) > 0:
        border_style = "red"
    elif summary.get("pending_manual", 0) > 0:
        border_style = "yellow"
    elif kept and not reverted:
        border_style = "cyan"

    print_panel(
        Group(*renderables),
        title="ENVIRONMENT CHANGES — CLEANUP REPORT",
        border_style=border_style,
        expand=False,
        spacing="before",
    )


def _build_changes_table(changes: list[dict[str, Any]], *, show_instructions: bool) -> _ChangesTable:
    """Build a Rich Table of change entries.

    Args:
        changes: List of change dictionaries from the ledger.
        show_instructions: Whether to include the manual cleanup instructions column.

    Returns:
        Populated _ChangesTable (subclass of Table) ready for rendering.
    """
    table = _ChangesTable(show_header=False, box=None, padding=(0, 1, 0, 0))
    table.add_column("icon", width=3, no_wrap=True)
    table.add_column("kind", min_width=18, no_wrap=True)
    table.add_column("target", min_width=30)
    if show_instructions:
        table.add_column("instructions")

    for change in changes:
        status = str(change.get("revert_status") or "pending")
        icon = _STATUS_ICON.get(status, "?")
        style = _STATUS_STYLE.get(status, "")
        kind_raw = str(change.get("kind") or "")
        kind_display = _KIND_DISPLAY.get(kind_raw, kind_raw)
        target = mark_sensitive(str(change.get("target") or ""), "text")

        if show_instructions:
            instructions = str(change.get("manual_cleanup_instructions") or "")
            instr_text = Text(f"→ {instructions}", style="dim") if instructions else Text("")
            table.add_row(
                Text(icon, style=style),
                Text(kind_display, style=style),
                Text(target, style=style),
                instr_text,
            )
        else:
            table.add_row(
                Text(icon, style=style),
                Text(kind_display, style=style),
                Text(target, style=style),
            )

    return table
