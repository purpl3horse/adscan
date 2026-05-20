"""Canonical edge severity — fourth dimension of the ADscan attack-graph model.

Severity is **not** a property of an edge. It is a **pure function** of:

* the source's :class:`CompromiseClass`
* the target's :class:`CompromiseClass`
* the edge's :class:`EdgeKind`
* whether the target is a Tier 0 asset (DC, Exchange, ADCS CA)
* whether the target is the Domain object itself

This separation resolves the false-positive observed on HTB Forest, where the
``Tactical Findings`` panel rendered 444 ``CRIT`` entries — >95% of which were
tautologies of the AD hierarchy (``Administrators -DCSync-> HTB.LOCAL``,
``Enterprise Admins -GenericAll-> HTB.LOCAL``, etc.). Those edges are not
findings; they are the definition of the Microsoft product. When everything is
critical, nothing is.

Reference: ``adscan-obsidian/business/12_nomenclature_standard.md`` §
"Severidad de edges — cuarta dimensión canónica" and ``CLAUDE.md`` §
"Edge severity — fourth canonical dimension".

This module is the single source of truth. CLI panel, report writer and web
app must consume :func:`compute_edge_severity` — never recompute.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from adscan_core.rich_output import print_warning

from adscan_internal.services.compromise_class import CompromiseClass
from adscan_internal.services.edge_kind import EdgeKind


class Severity(str, Enum):
    """Canonical severity levels for attack-graph edges.

    ``STRUCTURAL`` is reserved for ``MemberOf`` and similar topology edges
    that have no severity of their own — they only contribute to path
    materialization.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    STRUCTURAL = "STRUCTURAL"


# Per-process cache so an unknown EdgeKind warning fires once, not once per
# edge — a single Forest run can hit thousands of edges.
_WARNED_UNKNOWN_KIND: set[str] = set()


@dataclass(frozen=True)
class EdgeSeverityInput:
    """Input bundle for :func:`compute_edge_severity`.

    Attributes:
        source_compromise_class: The source principal's canonical compromise
            class. ``None`` denotes "low-priv / unclassified" — treated as
            equivalent to :attr:`CompromiseClass.COMPROMISE_ENABLER` for
            severity purposes (any unprivileged origin is symmetric).
        target_compromise_class: The target's canonical compromise class.
            ``None`` denotes a target with no membership-based classification
            (e.g. a regular user/computer that is not in any privileged
            group). Combined with ``target_is_tier0_asset`` and
            ``target_is_domain`` to determine the severity row.
        edge_kind: The canonical :class:`EdgeKind` of the edge. Use
            :func:`adscan_internal.services.edge_kind.classify_edge_kind`
            to derive it from a relation label.
        target_is_tier0_asset: True when the target is a Tier 0 asset
            (Domain Controller, Exchange server, ADCS CA). Distinct from
            ``target_is_domain`` — a Tier 0 *asset* is a host/server, the
            *domain* is the AD domain object itself.
        target_is_domain: True when the target node is the Domain object
            (kind == "Domain") — the canonical "Domain Compromised"
            terminal.
    """

    source_compromise_class: CompromiseClass | None
    target_compromise_class: CompromiseClass | None
    edge_kind: EdgeKind
    target_is_tier0_asset: bool = False
    target_is_domain: bool = False


def _is_low_priv_source(cls: CompromiseClass | None) -> bool:
    """Return True if source is low-priv / Compromise Enabler.

    The matrix treats unclassified principals (``None`` or
    :attr:`CompromiseClass.NONE`) and ``COMPROMISE_ENABLER`` symmetrically —
    they share the same severity row. Any path that *originates* in a
    non-privileged principal and crosses into Tier 0 is a choke point.
    """
    return cls is None or cls in (
        CompromiseClass.NONE,
        CompromiseClass.COMPROMISE_ENABLER,
        CompromiseClass.TIER0_FOOTHOLD,
    )


def _target_is_domain_or_breaker(inp: EdgeSeverityInput) -> bool:
    """Return True when target is the Domain object or a Domain Breaker."""
    if inp.target_is_domain:
        return True
    return inp.target_compromise_class is CompromiseClass.DOMAIN_BREAKER


def compute_edge_severity(inp: EdgeSeverityInput) -> Severity:
    """Compute the canonical severity for one edge.

    This is a **pure function** — same input, same output, no I/O. It
    implements the matrix in ``12_nomenclature_standard.md``.

    Invariant rules (in order of precedence):

    1. ``source = DomainBreaker`` → always ``INFO``. The AD hierarchy
       intrinsically grants Domain Breakers full control; rendering those
       edges as critical is the noise this module exists to remove.
    2. ``membership`` → always ``STRUCTURAL``. Topology, not severity.
    3. ``trust`` → ``INFO`` by default. Cross-domain elevation is a TODO.
    4. ``unknown`` → ``INFO`` with a one-shot verbose warning. Drift
       detection only — production data should classify.
    5. Compromise Enabler / low-priv → Domain or Domain Breaker via
       ``control``/``escalation``/``derived`` → ``CRITICAL``.
    6. Compromise Enabler / low-priv → Tier 0 asset via ``auth`` →
       ``CRITICAL`` (Tier 0 Foothold real).
    7. Privileged Escalator → Domain/Domain Breaker via ``control``/
       ``escalation`` → ``HIGH``.
    8. Privileged Escalator → Tier 0 asset via ``auth`` → ``HIGH``.
    9. Compromise Enabler / low-priv → Privileged Escalator via
       ``control``/``escalation`` → ``HIGH``.
    10. Compromise Enabler / low-priv → Compromise Enabler via ``control``
        → ``MEDIUM`` (multi-hop link).
    11. Default → ``LOW``.
    """
    kind = inp.edge_kind

    # Rule 2 — membership is always structural.
    if kind is EdgeKind.MEMBERSHIP:
        return Severity.STRUCTURAL

    # Rule 3 — trust defaults to INFO. TODO(cross-domain): elevate to
    # HIGH/CRITICAL when target_domain is itself comprometible. Requires
    # the trust-graph layer which is not yet wired into this function.
    if kind is EdgeKind.TRUST:
        return Severity.INFO

    # Rule 4 — unknown kinds. One-shot warning, then INFO.
    if kind is EdgeKind.UNKNOWN:
        token = "edge_kind=unknown"
        if token not in _WARNED_UNKNOWN_KIND:
            _WARNED_UNKNOWN_KIND.add(token)
            print_warning(
                "[severity] EdgeKind.UNKNOWN seen — falling back to INFO. "
                "Classify the edge in adscan_internal/services/edge_kind.py"
            )
        return Severity.INFO

    # Rule 1 — Domain Breaker as source is always INFO (AD hierarchy).
    # Applies to control / auth / escalation / derived alike.
    if inp.source_compromise_class is CompromiseClass.DOMAIN_BREAKER:
        return Severity.INFO

    target_is_terminal = _target_is_domain_or_breaker(inp)
    target_is_t0_asset = bool(inp.target_is_tier0_asset)
    target_is_escalator = (
        inp.target_compromise_class is CompromiseClass.PRIVILEGED_ESCALATOR
    )

    # Rule 4b — Unauthenticated Principal (Anonymous Logon, Network, Everyone
    # in a control edge to Tier 0). These principals only constitute a real
    # finding when null sessions / Pre-Windows 2000 Compatible Access are
    # enabled — uncertain without runtime validation. Cap at HIGH so the
    # panel does not raise CRITICAL alarms for what may be a hardened
    # environment.
    if inp.source_compromise_class is CompromiseClass.UNAUTHENTICATED_PRINCIPAL:
        if target_is_terminal and kind in (
            EdgeKind.CONTROL,
            EdgeKind.ESCALATION,
            EdgeKind.DERIVED,
        ):
            return Severity.HIGH
        if target_is_t0_asset and kind is EdgeKind.AUTH:
            return Severity.HIGH
        if kind in (EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED):
            return Severity.MEDIUM
        return Severity.LOW

    # Rule 5/6/7/8 — escalator vs low-priv source crossing into Tier 0.
    if target_is_terminal or target_is_t0_asset:
        if _is_low_priv_source(inp.source_compromise_class):
            # Rule 5 — control/escalation/derived to terminal → CRITICAL
            if target_is_terminal and kind in (
                EdgeKind.CONTROL,
                EdgeKind.ESCALATION,
                EdgeKind.DERIVED,
            ):
                return Severity.CRITICAL
            # Rule 6 — auth to Tier 0 asset → CRITICAL (real foothold)
            if target_is_t0_asset and kind is EdgeKind.AUTH:
                return Severity.CRITICAL
            # derived always >= HIGH (proof of compromise) — keep CRITICAL
            # when it lands on Tier 0 asset, HIGH otherwise.
            if kind is EdgeKind.DERIVED and target_is_t0_asset:
                return Severity.CRITICAL

        if inp.source_compromise_class is CompromiseClass.PRIVILEGED_ESCALATOR:
            # Rule 7 — escalator → terminal via control/escalation → HIGH
            if target_is_terminal and kind in (
                EdgeKind.CONTROL,
                EdgeKind.ESCALATION,
                EdgeKind.DERIVED,
            ):
                return Severity.HIGH
            # Rule 8 — escalator → Tier 0 asset via auth → HIGH
            if target_is_t0_asset and kind is EdgeKind.AUTH:
                return Severity.HIGH

    # Rule 9 — low-priv → Privileged Escalator via control/escalation → HIGH
    if (
        target_is_escalator
        and _is_low_priv_source(inp.source_compromise_class)
        and kind in (EdgeKind.CONTROL, EdgeKind.ESCALATION, EdgeKind.DERIVED)
    ):
        return Severity.HIGH

    # Rule 10 — low-priv → low-priv via control → MEDIUM (multi-hop link)
    if (
        _is_low_priv_source(inp.source_compromise_class)
        and _is_low_priv_source(inp.target_compromise_class)
        and not target_is_t0_asset
        and not target_is_terminal
        and not target_is_escalator
        and kind is EdgeKind.CONTROL
    ):
        return Severity.MEDIUM

    # Rule 11 — default fallback.
    return Severity.LOW


# Render order — used by the panel renderer to sort the visible band.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.STRUCTURAL: 5,
}


def severity_rank(sev: Severity) -> int:
    """Return a sort key — lower = more severe — for rendering order."""
    return _SEVERITY_RANK.get(sev, 9)
