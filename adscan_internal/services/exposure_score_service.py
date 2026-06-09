"""AD Exposure Score — the single, defensible headline metric.

Computes a 0–100% **AD Exposure Score** quantifying how exposed an Active
Directory is to **full domain compromise (Tier 0 / Domain Admin) starting from
a low-privilege foothold**, plus a **Proven Exposure** sub-number (the "we
actually demonstrated it" figure) and a per-compromise-class breakdown for
explainability.

This is the *single source of truth* (spec
``docs/specs/exposure-score-spec.md``): the CLI report, the
``technical_report.json`` export, and (later) ``adscan_web`` all consume
:func:`compute_exposure_score` — the logic is NEVER re-implemented downstream.

It is a **scoring/aggregation layer over already-computed data** — it does NOT
recompute attack paths. The caller passes the attack-path summaries already
produced by
``attack_graph_service.get_attack_path_summaries(scope=…, target="highvalue",
target_mode="tier0")``; this module only weights and aggregates them.

Model (v1) — union-saturating exposure:

    w(p)      = proof_weight(status) * ease_weight(hops)
    exposure  = 1 - Π_p (1 - w(p))           over all included S→Tier-0 paths

Properties (acceptance criteria, see spec §5):

* ``0%`` iff there is no supported path (proven or theoretical) from the
  low-priv start set to any Tier-0 target (empty product → ``1 - 1 = 0``).
* A single PROVEN path → ``w = 1`` → ``100%`` (honest AEV: demonstrated).
* Theoretical-only paths saturate below 100%; multiplicity adds but saturates.
* ``Proven Exposure ≤ Total Exposure`` always; theoretical is never counted as
  proven.

The spec assumed ``compromise_effort`` / ``confidence`` were emitted per path;
in practice they are ``None`` on the records, so the model relies on the fields
that ARE reliably present (``status`` for proof, ``length`` for ease,
``compromise_class`` for the breakdown) and degrades gracefully if the optional
ones ever appear (``compromise_effort`` would refine ``ease_weight``).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from adscan_internal.services.path_state import PathState

# --------------------------------------------------------------------------- #
# Tunables — the weights/shape are the only thing to tune; the union form and
# the acceptance properties above must NOT change.
# --------------------------------------------------------------------------- #

#: Proof weight by rolled-up path status. ``None`` => exclude the path entirely
#: (an unsupported/unavailable path contributes nothing to exposure). Covers
#: BOTH the edge-status vocabulary (theoretical/attempted/success/blocked/…)
#: and the executed PathState vocabulary (domain_compromised/foothold_obtained/…).
_PROOF_WEIGHT: dict[str, float | None] = {
    # Proven domain compromise — we demonstrably reached the Tier-0 target.
    "success": 1.0,
    "exploited": 1.0,
    "domain_compromised": 1.0,
    # Executed and on the way, reality demonstrated but not full domain yet.
    "foothold_obtained": 0.6,
    "post_ex_in_progress": 0.6,
    # Attempted but did not land (tried against the real DC, no compromise).
    "attempted": 0.6,
    "failed": 0.6,
    "error": 0.6,
    "post_ex_failed": 0.6,
    # Supported but never executed — LDAP-derived theoretical path.
    "theoretical": 0.4,
    "discovered": 0.4,
    # A control actively stopped this path (still a residual signal, not zero).
    "blocked": 0.1,
    # Not runnable / no reachable surface — excluded from the score.
    "unsupported": None,
    "unavailable": None,
}

#: Statuses that count as PROVEN domain compromise for the Proven Exposure
#: number. Strict on purpose: only a demonstrably-reached Tier-0 target counts,
#: so a failed post-ex is NOT presented as proven (honesty acceptance crit. §5.4).
_PROVEN_STATUSES: frozenset[str] = frozenset(
    {"success", "exploited", "domain_compromised"}
)

#: ease_weight(hops) = 1 / (1 + EASE_ALPHA * (hops - 1)). A 1-hop path scores
#: 1.0 (maximally exposing); longer chains decay. α=0.25 → 2-hop 0.80,
#: 3-hop 0.67, 5-hop 0.50, 9-hop 0.33.
EASE_ALPHA: float = 0.25

#: Compromise classes that constitute reaching domain compromise (Tier-0). A
#: path whose terminal is one of these counts toward exposure; enabler/pivot
#: terminals do not (they are not domain compromise on their own).
_TIER0_COMPROMISE_CLASSES: frozenset[str] = frozenset(
    {"domain_breaker", "tier0_foothold"}
)

#: How many top contributing paths to surface for explainability.
_TOP_CONTRIBUTORS: int = 8


# --------------------------------------------------------------------------- #
# Output model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ExposureContributor:
    """One attack path contributing to the exposure score (explainability)."""

    start: str
    target: str
    proof_state: str
    hops: int
    primary_vector: str
    weight: float


@dataclass(frozen=True)
class ExposureScore:
    """The AD Exposure Score and its honest breakdown.

    ``overall_pct`` is the headline; ``proven_pct`` is the AEV "demonstrated"
    figure (always ``<= overall_pct``). ``by_class`` explains which compromise
    classes drive the number; ``top_contributors`` lists the heaviest paths;
    ``explanation`` is an auditor-grade one-paragraph "why this number".
    """

    overall_pct: float
    proven_pct: float
    by_class: dict[str, float]
    reachable_tier0: int
    total_tier0: int | None
    top_contributors: list[ExposureContributor] = field(default_factory=list)
    explanation: str = ""
    scope: str = "domain"
    computed_at: str = ""
    scan_id: str | None = None
    workspace: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe representation for ``technical_report.json`` / the API."""
        return {
            "overall_pct": round(self.overall_pct, 1),
            "proven_pct": round(self.proven_pct, 1),
            "by_class": {k: round(v, 1) for k, v in self.by_class.items()},
            "reachable_tier0": self.reachable_tier0,
            "total_tier0": self.total_tier0,
            "top_contributors": [
                {
                    "start": c.start,
                    "target": c.target,
                    "proof_state": c.proof_state,
                    "hops": c.hops,
                    "primary_vector": c.primary_vector,
                    "weight": round(c.weight, 3),
                }
                for c in self.top_contributors
            ],
            "explanation": self.explanation,
            "scope": self.scope,
            "computed_at": self.computed_at,
            "scan_id": self.scan_id,
            "workspace": self.workspace,
        }


# --------------------------------------------------------------------------- #
# Scoring primitives
# --------------------------------------------------------------------------- #


def _proof_weight(status: str) -> float | None:
    """Return the proof weight for a path status, or ``None`` to exclude it."""
    return _PROOF_WEIGHT.get((status or "").strip().lower(), 0.4)


def _ease_weight(hops: int) -> float:
    """Return the ease weight: shorter paths are more exposing."""
    h = max(1, int(hops or 1))
    return 1.0 / (1.0 + EASE_ALPHA * (h - 1))


def _is_proven_status(status: str) -> bool:
    """Return whether a status demonstrably reached the Tier-0 target.

    Cross-checks the canonical :class:`PathState` so the proven set stays in
    lock-step with the engine's own ``is_proven`` notion for the reached states.
    """
    value = (status or "").strip().lower()
    if value in _PROVEN_STATUSES:
        return True
    try:
        return PathState(value) is PathState.DOMAIN_COMPROMISED
    except ValueError:
        return False


def _record_hops(record: Mapping[str, Any]) -> int:
    """Return the executable hop count of a path record (>=1)."""
    raw = record.get("length")
    if isinstance(raw, int):
        return max(1, raw)
    if isinstance(raw, str) and raw.strip().isdigit():
        return max(1, int(raw.strip()))
    relations = record.get("relations")
    if isinstance(relations, list) and relations:
        return max(1, len(relations))
    return 1


def _is_tier0_target(record: Mapping[str, Any]) -> bool:
    """Return whether a path's terminal IS domain compromise (Tier-0).

    Strict by design: the canonical ``compromise_class`` is the authority
    (always stamped by ``apply_path_based_classification``). Only
    ``domain_breaker`` and ``tier0_foothold`` are domain compromise — a path
    terminating at a ``privileged_escalator`` / ``compromise_enabler`` group
    (GPCO, Cert Publishers, DnsAdmins, …) is NOT domain compromise on its own
    and must NOT inflate the headline, even though such a group is Tier-0 in
    BloodHound. (Using the looser ``is_tier_zero`` flag here would wrongly pull
    enabler paths into the score — observed on Essos with JORAH.MORMONT.)

    Falls back to ``outcome_class`` only when ``compromise_class`` is absent
    (legacy records pre-dating the stamping).
    """
    cls = str(record.get("compromise_class") or "").strip().lower()
    if cls:
        return cls in _TIER0_COMPROMISE_CLASSES
    return str(record.get("outcome_class") or "").strip().lower() in {
        "direct_compromise",
        "tier0_foothold",
    }


def _primary_vector(record: Mapping[str, Any]) -> str:
    """Best-effort human label for the path's defining technique."""
    relations = record.get("relations")
    if isinstance(relations, list):
        # Last non-membership relation is the one that actually grants Tier-0.
        for rel in reversed(relations):
            r = str(rel or "").strip()
            if r and r.lower() not in {"memberof", "member of"}:
                return r
    return str(record.get("target_terminal_class") or "unknown")


def _union(weights: Sequence[float]) -> float:
    """Saturating union: ``1 - Π (1 - w)``. Empty → 0.0."""
    product = 1.0
    for w in weights:
        product *= 1.0 - max(0.0, min(1.0, w))
    return 1.0 - product


# --------------------------------------------------------------------------- #
# Public entry point
# --------------------------------------------------------------------------- #


def compute_exposure_score(
    summaries: Sequence[Mapping[str, Any]],
    *,
    scope: str = "domain",
    total_tier0: int | None = None,
    scan_id: str | None = None,
    workspace: str | None = None,
    computed_at: str | None = None,
) -> ExposureScore:
    """Compute the :class:`ExposureScore` from attack-path summaries.

    Args:
        summaries: Attack-path summary records from
            ``get_attack_path_summaries(...)`` (already computed — NOT
            recomputed here). Each is a mapping with at least ``status``,
            ``length``, ``compromise_class``/``outcome_class``, ``source``,
            ``target``, ``relations``.
        scope: The start-set scope these summaries were computed for
            (``"domain"`` for the low-priv headline, ``"owned"`` for the
            post-foothold view). Recorded on the result for context.
        total_tier0: Total number of Tier-0 targets in the domain (for the
            ``reachable / total`` display stat). ``None`` if not supplied.
        scan_id, workspace, computed_at: provenance metadata. ``computed_at``
            defaults to ``utcnow`` ISO-8601 when not given.

    Returns:
        A fully-populated, JSON-serialisable :class:`ExposureScore`.
    """
    stamp = computed_at or datetime.now(timezone.utc).isoformat()

    # Weight every included Tier-0 path. Each entry: (weight, is_proven, record).
    weighted: list[tuple[float, bool, Mapping[str, Any]]] = []
    for rec in summaries:
        if not isinstance(rec, Mapping):
            continue
        if not _is_tier0_target(rec):
            continue
        status = str(rec.get("status") or "theoretical").strip().lower()
        pw = _proof_weight(status)
        if pw is None:  # unsupported / unavailable — excluded from the score
            continue
        w = pw * _ease_weight(_record_hops(rec))
        if w <= 0.0:
            continue
        weighted.append((w, _is_proven_status(status), rec))

    overall = _union([w for w, _, _ in weighted]) * 100.0
    proven = _union([w for w, is_p, _ in weighted if is_p]) * 100.0

    # Per-compromise-class breakdown (union restricted to each class).
    by_class: dict[str, float] = {}
    for cls in ("domain_breaker", "tier0_foothold", "privileged_escalator", "compromise_enabler"):
        cls_weights = [
            w
            for w, _, rec in weighted
            if str(rec.get("compromise_class") or "").strip().lower() == cls
        ]
        by_class[cls] = _union(cls_weights) * 100.0

    reachable_targets = {
        str(rec.get("target") or "").strip().upper()
        for _, _, rec in weighted
        if str(rec.get("target") or "").strip()
    }
    reachable_tier0 = len(reachable_targets)

    top = sorted(weighted, key=lambda t: t[0], reverse=True)[:_TOP_CONTRIBUTORS]
    top_contributors = [
        ExposureContributor(
            start=str(rec.get("source") or ""),
            target=str(rec.get("target") or ""),
            proof_state=str(rec.get("status") or "theoretical"),
            hops=_record_hops(rec),
            primary_vector=_primary_vector(rec),
            weight=w,
        )
        for w, _, rec in top
    ]

    explanation = _build_explanation(
        overall=overall,
        proven=proven,
        reachable_tier0=reachable_tier0,
        total_tier0=total_tier0,
        path_count=len(weighted),
        proven_count=sum(1 for _, is_p, _ in weighted if is_p),
        scope=scope,
    )

    return ExposureScore(
        overall_pct=overall,
        proven_pct=proven,
        by_class=by_class,
        reachable_tier0=reachable_tier0,
        total_tier0=total_tier0,
        top_contributors=top_contributors,
        explanation=explanation,
        scope=scope,
        computed_at=stamp,
        scan_id=scan_id,
        workspace=workspace,
    )


def _build_explanation(
    *,
    overall: float,
    proven: float,
    reachable_tier0: int,
    total_tier0: int | None,
    path_count: int,
    proven_count: int,
    scope: str,
) -> str:
    """Return an auditor-grade one-paragraph 'why this number'."""
    if path_count == 0:
        return (
            "Exposure 0%: no supported attack path (proven or theoretical) from "
            "a low-privilege foothold to any Tier-0 / Domain Admin target was "
            "found in this scan."
        )
    start_label = "an already-compromised principal" if scope == "owned" else "a low-privilege user"
    tier0_label = (
        f"{reachable_tier0} of {total_tier0} Tier-0 targets"
        if total_tier0
        else f"{reachable_tier0} Tier-0 target(s)"
    )
    proven_clause = (
        f"{proven_count} of these were demonstrably executed end-to-end "
        f"(Proven Exposure {proven:.0f}%)."
        if proven_count
        else "none of these have been executed yet (Proven Exposure 0%); the "
        "figure reflects theoretical, LDAP-derived paths."
    )
    return (
        f"Exposure {overall:.0f}%: {path_count} supported attack path(s) reach "
        f"{tier0_label} from {start_label}. Shorter, higher-proof paths weigh "
        f"more; the score saturates as paths multiply. {proven_clause} "
        "0% is reached only when every such path is remediated."
    )


__all__ = [
    "ExposureScore",
    "ExposureContributor",
    "compute_exposure_score",
    "EASE_ALPHA",
]
