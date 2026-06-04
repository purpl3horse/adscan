"""Canonical compromise classification for ADscan.

This module defines the single source of truth for the customer-facing
compromise taxonomy used across CLI, report and web surfaces.

The taxonomy intentionally separates *what kind of impact* an account
represents from *how* that impact was discovered. It is the public
vocabulary documented in `CLAUDE.md` and
`adscan-obsidian/business/12_nomenclature_standard.md`.

Four classes (priority order, highest first):

* ``DOMAIN_BREAKER`` — accounts whose privileges directly equal domain
  compromise (Domain Admins, Enterprise Admins, BUILTIN\\Administrators,
  Schema Admins, krbtgt). One-step. No escalation required.
* ``PRIVILEGED_ESCALATOR`` — accounts in privileged groups that are not
  themselves domain compromise but whose membership unlocks a confirmed
  one-technique escalation (Backup Operators, Account Operators,
  DnsAdmins, Print/Server Operators, Cert Publishers, Key Admins,
  Exchange Trusted Subsystem, Exchange Windows Permissions, etc.).
* ``COMPROMISE_ENABLER`` — accounts without privileged group membership
  that nonetheless reach the domain through a confirmed multi-step
  attack path. This bucket is currently populated from attack-graph
  evidence (path-derived), not from group membership semantics.
* ``TIER0_FOOTHOLD`` *(Phase 1 refactor, 2026-05-02)* — paths that
  terminate in an :attr:`EdgeKind.AUTH` edge against a Tier 0 asset
  (DC, Exchange, ADCS CA). Confirms access — but not control — to a
  critical asset; the actual domain compromise requires post-exploitation
  to succeed.

The single attribute callers should read is :data:`CompromiseClass`. The
historical booleans (``is_direct_control``, ``is_enabler`` and
``is_high_impact``) remain as derivation inputs for backward
compatibility while the rest of the codebase is migrated.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Iterable, Mapping

from adscan_internal.services.edge_kind import EdgeKind, classify_edge_kind


class CompromiseClass(str, Enum):
    """Canonical customer-facing compromise classes."""

    DOMAIN_BREAKER = "domain_breaker"
    PRIVILEGED_ESCALATOR = "privileged_escalator"
    COMPROMISE_ENABLER = "compromise_enabler"
    TIER0_FOOTHOLD = "tier0_foothold"
    UNAUTHENTICATED_PRINCIPAL = "unauthenticated_principal"
    NONE = "none"

    @property
    def display_label(self) -> str:
        """Return the human label used in report and web surfaces."""
        return _DISPLAY_LABELS[self]

    @property
    def cli_badge(self) -> str:
        """Return the bracketed badge used in CLI output."""
        return _CLI_BADGES[self]


_DISPLAY_LABELS: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "Domain Breaker",
    CompromiseClass.PRIVILEGED_ESCALATOR: "Privileged Escalator",
    CompromiseClass.COMPROMISE_ENABLER: "Compromise Enabler",
    CompromiseClass.TIER0_FOOTHOLD: "Acceso a activo crítico (post-ex pendiente)",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "Unauthenticated Principal (null session)",
    CompromiseClass.NONE: "Standard",
}

_CLI_BADGES: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "[T0/Domain Breaker]",
    CompromiseClass.PRIVILEGED_ESCALATOR: "[T0/Privileged Esc.]",
    CompromiseClass.COMPROMISE_ENABLER: "[Compromise Enabler]",
    CompromiseClass.TIER0_FOOTHOLD: "[T0/Foothold]",
    CompromiseClass.UNAUTHENTICATED_PRINCIPAL: "[Unauth]",
    CompromiseClass.NONE: "[Standard]",
}


def derive_compromise_class(
    *,
    is_direct_control: bool = False,
    is_privileged_escalator: bool = False,
    has_path_to_domain: bool = False,
) -> CompromiseClass:
    """Derive the canonical compromise class from primitive evidence flags.

    Priority is highest-impact-wins: a principal that satisfies
    ``is_direct_control`` is a Domain Breaker even if it also has lower
    classifications. This matches how the CLI, report and web surfaces
    must label the principal — the highest impact wins.

    Args:
        is_direct_control: True when membership grants intrinsic domain
            compromise (Domain Admins, Enterprise Admins, etc.).
        is_privileged_escalator: True when membership grants a privileged
            group that has a confirmed one-technique escalation but is
            not itself domain compromise (Backup Operators, DnsAdmins,
            Account Operators, etc.).
        has_path_to_domain: True when attack-graph evidence shows a
            confirmed multi-step path from this principal to the domain
            without privileged group membership.

    Returns:
        The canonical compromise class. Returns
        :attr:`CompromiseClass.NONE` when no evidence applies.

    Note:
        This is the legacy flag-based API kept for backward compatibility.
        New call sites should prefer
        :func:`derive_compromise_class_from_path` which classifies based
        on the canonical EdgeKind of the path's last real edge.
    """
    if is_direct_control:
        return CompromiseClass.DOMAIN_BREAKER
    if is_privileged_escalator:
        return CompromiseClass.PRIVILEGED_ESCALATOR
    if has_path_to_domain:
        return CompromiseClass.COMPROMISE_ENABLER
    return CompromiseClass.NONE


def derive_compromise_class_from_semantics(
    semantics: dict[str, Any],
    *,
    has_path_to_domain: bool = False,
) -> CompromiseClass:
    """Derive the canonical compromise class from a control-semantics dict.

    This is the call site adapter for code that already produces the
    semantics dict returned by
    :func:`adscan_internal.services.control_semantics.classify_membership_control_semantics`.
    """
    return derive_compromise_class(
        is_direct_control=bool(semantics.get("is_direct_control")),
        is_privileged_escalator=bool(semantics.get("is_privileged_escalator"))
        or bool(semantics.get("is_enabler")),
        has_path_to_domain=has_path_to_domain,
    )


# ---------------------------------------------------------------------------
# Phase 1 — path-based classifier (NEW canonical API)
# ---------------------------------------------------------------------------


# Names of privileged-escalator groups whose membership unlocks a
# one-technique path to Tier 0. Mirrors the table in
# 12_nomenclature_standard.md. We compare case-insensitively against the
# target node's ``name`` or ``samaccountname`` field.
_PRIVILEGED_ESCALATOR_GROUP_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Schema Admins",
        "Backup Operators",
        "Server Operators",
        "Account Operators",
        "Print Operators",
        "DnsAdmins",
        "Hyper-V Administrators",
        "Storage Replica Administrators",
        "AD Recycle Bin",
        "Cert Publishers",
        "Key Admins",
        "Enterprise Key Admins",
        "Exchange Trusted Subsystem",
        "Exchange Windows Permissions",
    )
)


def _node_tier(node: Mapping[str, Any] | None) -> int | None:
    """Extract the tier from a node dict if present.

    Recognises every Tier-0 signal used across the ADscan stack:

    * Explicit ``tier`` / ``tier_level`` / ``asset_tier`` integer fields.
    * Snake-case ``is_tier0`` / ``is_dc`` flags (legacy).
    * Camel-case ``isTierZero`` flag (collector / BloodHound CE convention).
    * ``system_tags`` containing ``admin_tier_0`` (canonical Tier-0 tag).
    * ``kind == "Domain"`` — the Domain object IS the canonical domain
      compromise terminal in the new model. Controlling it (WriteDACL,
      GenericAll, AddMember on krbtgt-replicating principals, etc.) is by
      definition Tier-0.
    * ``target_terminal_class == "direct_compromise"`` — final fallback for
      principals classified as direct-compromise sinks (DA, EA, krbtgt…)
      via ``_node_target_terminal_class``.
    """
    if not node:
        return None
    for key in ("tier", "tier_level", "asset_tier"):
        value = node.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, str) and value.strip().isdigit():
            return int(value.strip())
    if bool(node.get("is_tier0")) or bool(node.get("is_dc")):
        return 0
    if bool(node.get("isTierZero")):
        return 0
    props = (
        node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    )
    if isinstance(props, Mapping) and bool(props.get("isTierZero")):
        return 0
    if str(node.get("kind") or "").strip().lower() == "domain":
        return 0
    tags = node.get("system_tags")
    if isinstance(tags, str) and "admin_tier_0" in tags.lower():
        return 0
    if isinstance(tags, list) and any(
        str(t).strip().lower() == "admin_tier_0" for t in tags
    ):
        return 0
    if isinstance(props, Mapping):
        prop_tags = props.get("system_tags")
        if isinstance(prop_tags, str) and "admin_tier_0" in prop_tags.lower():
            return 0
        if isinstance(prop_tags, list) and any(
            str(t).strip().lower() == "admin_tier_0" for t in prop_tags
        ):
            return 0
        if (
            str(props.get("target_terminal_class") or "").strip().lower()
            == "direct_compromise"
        ):
            return 0
    if (
        str(node.get("target_terminal_class") or "").strip().lower()
        == "direct_compromise"
    ):
        return 0
    return None


def _node_name(node: Mapping[str, Any] | None) -> str:
    if not node:
        return ""
    for key in ("name", "samaccountname", "label"):
        value = node.get(key)
        if isinstance(value, str) and value:
            return value
    return ""


# RIDs whose compromise IS a direct domain compromise (Tier 2 of the terminal
# taxonomy in docs/superpowers/specs/2026-06-03-attack-path-terminal-ordering.md):
# Administrator account (500), Domain Admins (512), Domain Controllers group
# (516), Enterprise Admins (519), BUILTIN\Administrators (544), krbtgt (502).
# DC computer accounts are also direct (handled via the ``is_dc`` flag below).
#
# Deliberately EXCLUDED (they are compromise ENABLERS — controlling them needs a
# further abuse, and the canonical nomenclature table classifies them as
# Privileged Escalators): Schema Admins (518, schema-write is delayed/indirect),
# Enterprise/Read-Only DCs (498/521, read-only — partial secrets), and every
# other Tier-0 group (GPCO, Cert Publishers, DnsAdmins, *Operators, Key Admins,
# Exchange groups, …).
_DIRECT_DOMAIN_BREAKER_RIDS: frozenset[int] = frozenset({500, 512, 516, 519, 544, 502})

# Name-based fallback for the same set, for nodes that carry only a name
# (no resolvable objectid/RID — common in synthesized targets and tests).
_DIRECT_DOMAIN_BREAKER_NAMES: frozenset[str] = frozenset(
    name.lower()
    for name in (
        "Administrator",
        "Administrators",
        "Domain Admins",
        "Enterprise Admins",
        "Domain Controllers",
        "Enterprise Domain Controllers",
        "krbtgt",
    )
)


def _node_rid(node: Mapping[str, Any] | None) -> int | None:
    """Return the RID (trailing SID component) of a node, or ``None``."""
    if not node:
        return None
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    for value in (
        props.get("objectid") if isinstance(props, Mapping) else None,
        props.get("objectId") if isinstance(props, Mapping) else None,
        node.get("objectid"),
        node.get("objectId"),
    ):
        if isinstance(value, str) and value.strip():
            try:
                return int(value.strip().upper().rsplit("-", 1)[-1])
            except (ValueError, IndexError):
                continue
    return None


def _is_direct_domain_breaker_target(node: Mapping[str, Any] | None) -> bool:
    """Return whether reaching *node* IS a direct domain compromise.

    True for the domain object itself, the canonical direct-compromise
    principals (:data:`_DIRECT_DOMAIN_BREAKER_RIDS`), and DC computer accounts.
    A control edge landing here is a real ``DOMAIN_BREAKER``; a control edge to
    any other Tier-0 group is a ``PRIVILEGED_ESCALATOR`` (compromise enabler).
    """
    if not node:
        return False
    if str(node.get("kind") or "").strip().lower() == "domain":
        return True
    rid = _node_rid(node)
    if rid is not None and rid in _DIRECT_DOMAIN_BREAKER_RIDS:
        return True
    # Name fallback when the node carries no resolvable RID.
    name = _node_name(node).strip().lower()
    if name:
        # Strip a trailing @domain suffix (label form) before matching.
        bare = name.split("@", 1)[0].strip()
        if bare in _DIRECT_DOMAIN_BREAKER_NAMES:
            return True
    if bool(node.get("is_dc")):
        return True
    props = node.get("properties") if isinstance(node.get("properties"), Mapping) else {}
    if isinstance(props, Mapping) and bool(props.get("is_dc")):
        return True
    return False


def _is_privileged_escalator_target(node: Mapping[str, Any] | None) -> bool:
    return _node_name(node).lower() in _PRIVILEGED_ESCALATOR_GROUP_NAMES


def _last_real_edge(edges: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Return the last edge that is not a pure ``MemberOf`` traversal.

    MemberOf is structural — it never determines the compromise class.
    The classifier looks at the last edge that actually grants something.
    """
    last: Mapping[str, Any] | None = None
    for edge in edges:
        relation = str(edge.get("relation") or edge.get("kind_label") or "")
        if classify_edge_kind(relation) is EdgeKind.MEMBERSHIP:
            continue
        last = edge
    return last


def derive_compromise_class_from_path(
    path_edges: list[dict[str, Any]],
    target_node: Mapping[str, Any] | None,
) -> CompromiseClass:
    """Classify an attack path by its **last real edge**, not by flags.

    This is the canonical Phase 1 classifier. It implements the rule
    documented in ``12_nomenclature_standard.md`` (§ Fase 1, "Regla del
    clasificador"):

    * If the last non-membership edge is ``control``/``derived``/
      ``escalation`` and lands on a Tier 0 asset → ``DOMAIN_BREAKER``.
    * If the last non-membership edge is ``auth`` and lands on a Tier 0
      asset → ``TIER0_FOOTHOLD`` (NEW Phase 1 — fixes the HTB Forest
      false positive where ``CanPSRemote`` to a DC was wrongly flagged
      as Domain Breaker).
    * If the last edge is ``control``/``escalation`` and the target is a
      privileged-escalator group → ``PRIVILEGED_ESCALATOR``.
    * Else, if the path contains any known terminal technique (control,
      derived or escalation kind) at all → ``COMPROMISE_ENABLER``.
    * Otherwise → ``NONE``.

    Args:
        path_edges: Ordered list of edge dicts. Each edge MUST expose a
            ``relation`` field with the BloodHound (or ADscan synthetic)
            label. Other fields are ignored by this classifier.
        target_node: The terminal node dict. Used to read ``tier`` and
            ``name``. May be ``None`` when the caller only knows the
            edges (in which case Tier 0 detection is best-effort and the
            classifier falls back to ``COMPROMISE_ENABLER`` if the path
            ends with a terminal kind).

    Returns:
        The canonical :class:`CompromiseClass`. Coexists with
        :func:`derive_compromise_class` during Phase 1 — call-site
        migration to this API is Phase 2.
    """
    if not path_edges:
        return CompromiseClass.NONE

    last = _last_real_edge(path_edges)
    if last is None:
        # Path is pure-membership — structural, never a compromise class.
        return CompromiseClass.NONE

    relation = str(last.get("relation") or last.get("kind_label") or "")
    last_kind = classify_edge_kind(relation)
    target_tier = _node_tier(target_node)

    if last_kind in {EdgeKind.CONTROL, EdgeKind.DERIVED, EdgeKind.ESCALATION}:
        if target_tier == 0:
            # A control edge to a Tier-0 asset is a DOMAIN_BREAKER only when the
            # asset IS a direct domain compromise (the domain object, DA/EA/
            # Administrators/Schema Admins/DCs/krbtgt). Every other Tier-0 group
            # (GPCO, Cert Publishers, DnsAdmins, *Operators, …) is a compromise
            # ENABLER: controlling it requires a further abuse (create GPO, ADCS
            # ESC, DLL) to actually break the domain, so it must rank below the
            # direct domain-compromise paths. See spec
            # 2026-06-03-attack-path-terminal-ordering.md.
            if _is_direct_domain_breaker_target(target_node):
                return CompromiseClass.DOMAIN_BREAKER
            return CompromiseClass.PRIVILEGED_ESCALATOR
        if _is_privileged_escalator_target(target_node):
            return CompromiseClass.PRIVILEGED_ESCALATOR
        # Terminal kind but target is not Tier 0 nor an escalator group:
        # the path is still a confirmed enabler when it had any technique.
        return CompromiseClass.COMPROMISE_ENABLER

    if last_kind is EdgeKind.AUTH and target_tier == 0:
        return CompromiseClass.TIER0_FOOTHOLD

    # Auth edges to non-Tier-0, trust edges, unknown — none of these
    # constitute a domain-compromise classification on their own.
    if any(
        classify_edge_kind(str(edge.get("relation") or ""))
        in {EdgeKind.CONTROL, EdgeKind.DERIVED, EdgeKind.ESCALATION}
        for edge in path_edges
    ):
        return CompromiseClass.COMPROMISE_ENABLER

    return CompromiseClass.NONE


# ---------------------------------------------------------------------------
# Phase 3 — materializer wiring
# ---------------------------------------------------------------------------


# Mapping from canonical CompromiseClass to the legacy ``outcome_class`` /
# ``target_terminal_class`` strings consumed by:
#   * adscan_core.output._attack_paths (CLI table)
#   * adscan_internal.pro.reporting.attack_path_render (PDF report)
#   * adscan_internal.pro.reporting.html_pdf_generator (executive PDF)
#   * adscan_internal.pro.reporting.templates/premium/report.html
#
# We keep the legacy strings to avoid invalidating cached records and the
# whole compliance/reporting layer in one go. The new ``tier0_foothold``
# string is the only addition; the rest are preserved verbatim.
_COMPROMISE_CLASS_TO_OUTCOME: dict[CompromiseClass, str] = {
    CompromiseClass.DOMAIN_BREAKER: "direct_compromise",
    CompromiseClass.PRIVILEGED_ESCALATOR: "followup_terminal",
    CompromiseClass.TIER0_FOOTHOLD: "tier0_foothold",
    CompromiseClass.COMPROMISE_ENABLER: "graph_extension",
    CompromiseClass.NONE: "pivot",
}


def compromise_class_to_outcome_class(cls: CompromiseClass) -> str:
    """Return the legacy ``outcome_class`` string for a canonical class."""
    return _COMPROMISE_CLASS_TO_OUTCOME.get(cls, "pivot")


def _record_path_edges(record: dict[str, Any]) -> list[dict[str, Any]]:
    """Return the path edges for one materialized record.

    Materialized records carry a ``relations`` list (BloodHound/ADscan
    labels) parallel to a ``nodes`` list. We rebuild a thin edge dict so
    the path-based classifier in
    :func:`derive_compromise_class_from_path` can run against the same
    contract as Phase 1/2 unit tests.
    """
    relations = record.get("relations")
    nodes = record.get("nodes")
    if not isinstance(relations, list):
        return []
    src_nodes: list[str] = []
    dst_nodes: list[str] = []
    if isinstance(nodes, list):
        for idx, _ in enumerate(relations):
            src_nodes.append(str(nodes[idx]) if idx < len(nodes) else "")
            dst_nodes.append(str(nodes[idx + 1]) if idx + 1 < len(nodes) else "")
    edges: list[dict[str, Any]] = []
    for idx, rel in enumerate(relations):
        edges.append(
            {
                "relation": str(rel or ""),
                "from": src_nodes[idx] if idx < len(src_nodes) else "",
                "to": dst_nodes[idx] if idx < len(dst_nodes) else "",
            }
        )
    return edges


def apply_path_based_classification(
    record: dict[str, Any],
    target_node: Mapping[str, Any] | None,
) -> CompromiseClass:
    """Stamp the canonical compromise class onto a materialized path record.

    This is the Phase 3 wiring helper invoked by the materializer right
    after :func:`_annotate_record_target_priority` has populated the
    target-node-derived fields (``target_priority_class``,
    ``target_terminal_class``, ``target_followup_status``).

    The path-based classifier is the single source of truth for the
    customer-facing compromise class. When it disagrees with the legacy
    target-node heuristic — e.g. an ``auth`` edge to a Tier 0 asset that
    the legacy heuristic would label ``direct_compromise`` — the
    path-based result wins.

    Mutates ``record`` in place by setting:

    * ``compromise_class``   — canonical :class:`CompromiseClass` value (str).
    * ``outcome_class``      — legacy outcome string consumed by renderers.
    * ``target_terminal_class`` — overridden when the new class disagrees
      with the legacy value, so downstream sort keys and section grouping
      reflect the new classification.

    Returns:
        The :class:`CompromiseClass` chosen by the path-based classifier.
    """
    edges = _record_path_edges(record)
    cls = derive_compromise_class_from_path(edges, target_node)
    outcome = compromise_class_to_outcome_class(cls)
    record["compromise_class"] = cls.value
    record["outcome_class"] = outcome
    # Override target_terminal_class so the existing sort keys and
    # section bucketing pick up the new classification. Only override when
    # the path classifier produced a non-NONE class — otherwise we keep
    # the target-node-derived value (which may legitimately be "pivot").
    if cls is not CompromiseClass.NONE:
        record["target_terminal_class"] = outcome
    return cls
