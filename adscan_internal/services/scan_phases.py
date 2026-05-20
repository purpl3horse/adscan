"""Single source of truth for ADscan's scan-phase chapters.

ADscan's authenticated scan is rendered to the operator as a sequence of
"chapters" — one per major phase (Topology & Trusts, Domain Collection,
Domain Intelligence, Attack Paths Discovery, ...). Each chapter banner shows
the phase number out of the total and a strip of the upcoming/completed
phases, so the pentester always knows where they are in the run.

Before this module existed, the chapter list lived as an inline ``list[str]``
inside :func:`adscan.run_enumeration` and the trust + collection chapters
were not surfaced at all (they ran via smaller ``print_operation_header``
calls). That left two of the most expensive steps invisible in the chapter
strip and made the numbering misleading.

Three problems solved here:
    1. Shared registry — one ordered list everyone agrees on.
    2. Mode-aware filtering — audit mode adds extras; default mode does not.
    3. Chapter emission helper — ``emit_chapter(phase_id, scan_type)`` builds
       the :class:`PhaseChapter` with the correct ``number`` / ``all_phases``
       so callers don't compute indices themselves.

The phase IDs match the keys of :data:`adscan_internal.cli.ci_events.PHASE_CATALOG`
so the structured event sink (consumed by the ADscan web service) and the
CLI chapter strip stay in lockstep — adding a phase here keeps both surfaces
coherent without any duplicate metadata.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ScanPhase:
    """Metadata for one scan-phase chapter.

    Attributes:
        phase_id: Stable identifier; matches ``PHASE_CATALOG`` keys for the
            structured event sink.
        title: Display title rendered in the chapter banner.
        subtitle: One-line description shown under the title.
        audit_only: When True, the phase is only included for ``scan_type``
            equal to ``"audit"``.
    """

    phase_id: str
    title: str
    subtitle: str
    audit_only: bool = False


# ---------------------------------------------------------------------------
# Canonical scan phases — order is the rendered order
# ---------------------------------------------------------------------------

SCAN_PHASES: tuple[ScanPhase, ...] = (
    ScanPhase(
        phase_id="topology_and_trusts",
        title="Topology & Trusts",
        subtitle="Map domain topology and enumerate trust relationships.",
    ),
    ScanPhase(
        phase_id="domain_collection",
        title="Domain Collection",
        subtitle="Native LDAP/SMB collector — graph, sessions, ACLs.",
    ),
    ScanPhase(
        phase_id="domain_analysis",
        title="Domain Intelligence",
        subtitle="Host inventory, identities, and ADCS discovery.",
    ),
    ScanPhase(
        phase_id="attack_paths_discovery",
        title="Attack Paths Discovery",
        subtitle="Compute reachable paths from the owned set.",
    ),
    ScanPhase(
        phase_id="quick_credential_wins",
        title="Quick Credential Wins",
        subtitle="Low-noise credential discovery (Timeroast, LDAP, GPP).",
    ),
    ScanPhase(
        phase_id="password_spraying",
        title="Password Spraying",
        subtitle="Spray validated wordlists across the user base.",
    ),
    ScanPhase(
        phase_id="share_credential_hunt",
        title="Share Credential Hunt",
        subtitle="Scan exposed SMB shares for embedded credentials.",
    ),
    ScanPhase(
        phase_id="unauthenticated_attack_surface",
        title="Unauthenticated Attack Surface",
        subtitle="Pre-auth attack surface review for audit mode.",
        audit_only=True,
    ),
    ScanPhase(
        phase_id="audit_extras",
        title="Audit-only Extras",
        subtitle="Broader CVE scan and configuration enumeration.",
        audit_only=True,
    ),
)


_PHASES_BY_ID: dict[str, ScanPhase] = {p.phase_id: p for p in SCAN_PHASES}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def phases_for_scan_type(scan_type: str) -> tuple[ScanPhase, ...]:
    """Return the ordered phases that apply to ``scan_type``.

    ``scan_type`` is the value of ``LdapShell.type`` — currently
    ``"audit"`` unlocks the two audit-only phases; everything else gets
    the base list.
    """
    if scan_type == "audit":
        return SCAN_PHASES
    return tuple(p for p in SCAN_PHASES if not p.audit_only)


def get_phase(phase_id: str) -> ScanPhase | None:
    """Return the :class:`ScanPhase` for ``phase_id`` or ``None``."""
    return _PHASES_BY_ID.get(phase_id)


def emit_chapter(phase_id: str, scan_type: str = "default") -> None:
    """Render the chapter banner for ``phase_id`` with correct numbering.

    Looks up the phase in the scan-type-filtered registry, derives the 1-based
    index, and renders a :class:`PhaseChapter` with the full phase strip so
    the operator sees exactly where they are in the run.

    Silently no-ops when ``phase_id`` is unknown — chapter emission must
    never block the underlying enumeration step.
    """
    phase = _PHASES_BY_ID.get(phase_id)
    if phase is None:
        return

    visible = phases_for_scan_type(scan_type)
    try:
        index = visible.index(phase)
    except ValueError:
        return  # Phase exists but is not visible for this scan_type.

    from adscan_core.rich_output_collection import (
        PhaseChapter,
        print_phase_chapter,
    )

    print_phase_chapter(
        PhaseChapter(
            number=index + 1,
            title=phase.title,
            subtitle=phase.subtitle,
            all_phases=tuple(p.title for p in visible),
        )
    )


def phase_titles(scan_type: str = "default") -> tuple[str, ...]:
    """Return the ordered tuple of phase titles for the given scan type.

    Provided for legacy callers in :mod:`adscan` that maintain their own
    inline list — they can replace it with a call to this helper to keep
    the two paths from drifting.
    """
    return tuple(p.title for p in phases_for_scan_type(scan_type))
