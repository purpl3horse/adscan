"""Centralized audit ledger for all environment changes made during a scan."""

from __future__ import annotations

import os
import uuid
from datetime import UTC, datetime
from typing import Any

from adscan_internal import print_error, print_info, print_success, print_warning, telemetry
from adscan_internal.cli.ci_events import emit_event
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.workspaces.io import read_json_file, write_json_file

_LEDGER_FILENAME = "environment_changes.json"
_SCHEMA_VERSION = "1.0"

# Change lifecycle classes. They govern WHEN/WHETHER a reversible change is
# reverted at workspace exit:
#   * AUTO_REVERT        — transient artifacts (uploaded files, Ligolo agents, an
#                          enabled xp_cmdshell). Reverted automatically by the
#                          owning service at exit. This is the historical
#                          default, so every existing caller keeps its behavior
#                          unchanged.
#   * OPERATOR_CONFIRMED — durable AD objects/grants ADscan minted (machine
#                          accounts, RBCD delegation, KeyCredentialLink). NOT
#                          auto-reverted: a successful run keeps them so the
#                          operator retains the access and can reuse the asset;
#                          at exit the operator is prompted whether to revert.
CHANGE_CLASS_AUTO_REVERT = "auto_revert"
CHANGE_CLASS_OPERATOR_CONFIRMED = "operator_confirmed"
_VALID_CHANGE_CLASSES = (CHANGE_CLASS_AUTO_REVERT, CHANGE_CLASS_OPERATOR_CONFIRMED)


def _utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat()


class EnvironmentChangeLedger:
    """Append-only audit ledger for environment changes during a scan.

    Persists every change to {workspace_dir}/environment_changes.json after
    each mutation. Emits structured events via ci_events for web UI consumption.
    Safe to instantiate even when the workspace directory does not exist yet —
    flush() will simply fail silently and capture via telemetry.
    """

    def __init__(self, workspace_dir: str) -> None:
        self._path = os.path.join(workspace_dir, _LEDGER_FILENAME)
        self._state: dict[str, Any] = self._load()

    # ── Public API ────────────────────────────────────────────────────────────

    def register_change(
        self,
        *,
        kind: str,
        domain: str,
        target: str,
        detail: dict[str, Any],
        method: str,
        change_class: str = CHANGE_CLASS_AUTO_REVERT,
    ) -> str:
        """Register a new environment change. Returns change_id. Flushes to disk.

        Args:
            kind: Change category (e.g. "group_membership_added", "file_uploaded").
            domain: Domain where the change occurred (e.g. "corp.local").
            target: Human-readable description of the affected object.
            detail: Arbitrary key-value metadata for the change.
            method: Attack method or technique that caused the change.
            change_class: Lifecycle class governing exit cleanup. Defaults to
                ``CHANGE_CLASS_AUTO_REVERT`` (the historical behavior — every
                existing caller is unaffected). Durable AD objects/grants pass
                ``CHANGE_CLASS_OPERATOR_CONFIRMED`` so they are kept on success
                and only reverted on operator confirmation at exit.

        Returns:
            Unique change_id string (UUID4).
        """
        normalized_class = (
            change_class if change_class in _VALID_CHANGE_CLASSES else CHANGE_CLASS_AUTO_REVERT
        )
        change_id = str(uuid.uuid4())
        entry: dict[str, Any] = {
            "change_id": change_id,
            "kind": str(kind),
            "change_class": normalized_class,
            "domain": str(domain),
            "target": str(target),
            "detail": dict(detail),
            "method": str(method),
            "registered_at": _utc_now_iso(),
            "revert_status": "pending",
            "reverted_at": None,
            "revert_error": None,
            "manual_cleanup_instructions": None,
        }
        self._state["changes"].append(entry)
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_registered",
            change_id=change_id,
            kind=kind,
            domain=domain,
            target=target,
            revert_status="pending",
            change_class=normalized_class,
        )
        print_info(
            f"Environment change registered · {kind} · {mark_sensitive(target, 'text')}"
        )
        return change_id

    def mark_reverted(self, change_id: str, *, reverted_at: str | None = None) -> None:
        """Mark a change as successfully reverted. Flushes to disk.

        Args:
            change_id: ID returned by register_change.
            reverted_at: Optional ISO timestamp; defaults to now.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = "reverted"
        entry["reverted_at"] = reverted_at or _utc_now_iso()
        self._recompute_summary()
        self.flush()
        emit_event("environment_change_reverted", change_id=change_id, revert_status="reverted")
        print_success(
            f"Reverted · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def mark_kept(self, change_id: str) -> None:
        """Mark an operator_confirmed change as intentionally kept by the operator.

        Used when the operator chooses to retain a durable AD object/grant at
        exit (or when a successful run keeps it). Distinct from a failed revert:
        the change is durable on purpose, not because cleanup failed. Flushes to
        disk.

        Args:
            change_id: ID returned by register_change.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = "kept"
        entry["reverted_at"] = None
        entry["revert_error"] = None
        self._recompute_summary()
        self.flush()
        emit_event("environment_change_kept", change_id=change_id, revert_status="kept")
        print_info(
            f"Kept by operator · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def mark_failed(
        self,
        change_id: str,
        *,
        error: str,
        manual_cleanup_instructions: str | None = None,
    ) -> None:
        """Mark a revert attempt as failed. Flushes to disk.

        Args:
            change_id: ID returned by register_change.
            error: Error message describing why the revert failed.
            manual_cleanup_instructions: Optional instructions for manual remediation.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = "failed"
        entry["revert_error"] = str(error)
        entry["manual_cleanup_instructions"] = manual_cleanup_instructions
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_failed",
            change_id=change_id,
            revert_status="failed",
            error=error,
        )
        print_error(
            f"Cleanup failed · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def mark_operator_required(
        self,
        change_id: str,
        *,
        manual_cleanup_instructions: str,
    ) -> None:
        """Mark a change as requiring manual operator action. Flushes to disk.

        Args:
            change_id: ID returned by register_change.
            manual_cleanup_instructions: Instructions the operator must follow to clean up.
        """
        entry = self._find(change_id)
        if entry is None:
            return
        entry["revert_status"] = "operator_required"
        entry["manual_cleanup_instructions"] = str(manual_cleanup_instructions)
        self._recompute_summary()
        self.flush()
        emit_event(
            "environment_change_failed",
            change_id=change_id,
            revert_status="operator_required",
            error="Operator action required",
        )
        print_warning(
            f"Manual action required · {entry['kind']} · {mark_sensitive(entry['target'], 'text')}"
        )

    def find_and_reset_failed(self, kind: str, target: str) -> str | None:
        """Find the most recent failed entry matching kind+target and reset it to pending.

        Returns the change_id if found and reset, None if no matching failed entry exists.
        Idempotent: a second call for the same entry returns None (it is no longer failed).
        Used by retry-on-reentry: cleanup services call this before register_change so that
        failed entries are reused and updated rather than duplicated in the ledger.

        Args:
            kind: Change category to match (e.g. "file_uploaded").
            target: Target string to match exactly.

        Returns:
            The change_id string of the reset entry, or None if no failed match exists.
        """
        matched: dict[str, Any] | None = None
        for entry in self._state["changes"]:
            if (
                entry.get("kind") == kind
                and entry.get("target") == target
                and entry.get("revert_status") == "failed"
            ):
                matched = entry  # keep iterating to get the last (most recent) match
        if matched is None:
            return None
        matched["revert_status"] = "pending"
        matched["revert_error"] = None
        self._recompute_summary()
        self.flush()
        return str(matched["change_id"])

    def get_operator_confirmed_pending(self) -> list[dict[str, Any]]:
        """Return durable operator_confirmed changes still standing (deep copies).

        "Still standing" means the change has not been reverted, kept, or marked
        for manual action yet — i.e. ``revert_status`` is ``pending`` or
        ``failed``. These are the changes the exit hook offers to revert. Each
        entry is a shallow copy of the record with a deep-copied ``detail`` so
        callers can read the prior-state metadata needed to revert.

        Returns:
            List of operator_confirmed change entry dicts.
        """
        out: list[dict[str, Any]] = []
        for entry in self._state["changes"]:
            if entry.get("change_class") != CHANGE_CLASS_OPERATOR_CONFIRMED:
                continue
            if entry.get("revert_status") not in ("pending", "failed"):
                continue
            copy = dict(entry)
            copy["detail"] = dict(entry.get("detail") or {})
            out.append(copy)
        return out

    def finalize(self) -> None:
        """Mark scan as complete and flush."""
        self._state["scan_completed_at"] = _utc_now_iso()
        self.flush()

    def get_summary(self) -> dict[str, int]:
        """Return current summary counts (copy).

        Returns:
            Dictionary with keys: total, reverted, kept, pending, pending_manual, failed.
        """
        return dict(self._state["summary"])

    def get_changes(self) -> list[dict[str, Any]]:
        """Return all change entries (shallow copy of the list, deep copy of each entry).

        Returns:
            List of change entry dicts.
        """
        return [dict(entry) for entry in self._state["changes"]]

    def flush(self) -> None:
        """Write current state to disk. Called automatically by mutating methods."""
        try:
            write_json_file(self._path, self._state)
        except Exception as exc:  # pylint: disable=broad-except
            telemetry.capture_exception(exc)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _load(self) -> dict[str, Any]:
        if os.path.exists(self._path):
            try:
                data = read_json_file(self._path)
                if isinstance(data, dict) and data.get("schema_version") == _SCHEMA_VERSION:
                    # Backfill change_class on records written before the field
                    # existed: a missing class is the historical auto_revert.
                    for entry in data.get("changes", []) or []:
                        if isinstance(entry, dict) and not entry.get("change_class"):
                            entry["change_class"] = CHANGE_CLASS_AUTO_REVERT
                    return data
            except Exception as exc:  # pylint: disable=broad-except
                telemetry.capture_exception(exc)
        return {
            "schema_version": _SCHEMA_VERSION,
            "session_id": str(uuid.uuid4()),
            "scan_started_at": _utc_now_iso(),
            "scan_completed_at": None,
            "changes": [],
            "summary": {
                "total": 0,
                "reverted": 0,
                "kept": 0,
                "pending": 0,
                "pending_manual": 0,
                "failed": 0,
            },
        }

    def _find(self, change_id: str) -> dict[str, Any] | None:
        for entry in self._state["changes"]:
            if entry.get("change_id") == change_id:
                return entry
        return None

    def _recompute_summary(self) -> None:
        changes = self._state["changes"]
        self._state["summary"] = {
            "total": len(changes),
            "reverted": sum(1 for c in changes if c.get("revert_status") == "reverted"),
            "kept": sum(1 for c in changes if c.get("revert_status") == "kept"),
            "pending": sum(1 for c in changes if c.get("revert_status") == "pending"),
            "pending_manual": sum(1 for c in changes if c.get("revert_status") == "operator_required"),
            "failed": sum(1 for c in changes if c.get("revert_status") == "failed"),
        }
