"""Helpers for rendering ADCS attack-path context without changing graph semantics."""

from __future__ import annotations

from typing import Any, Mapping


_ADCS_RELATIONS = {
    "adcsesc1",
    "adcsesc2",
    "adcsesc3",
    "adcsesc4",
    "adcsesc6",
    "adcsesc6a",
    "adcsesc6b",
    "adcsesc7",
    "adcsesc8",
    "adcsesc9",
    "adcsesc9a",
    "adcsesc9b",
    "adcsesc10",
    "adcsesc10a",
    "adcsesc10b",
    "adcsesc11",
    "adcsesc13",
    "adcsesc14",
    "adcsesc15",
    "adcsesc16",
    "adcsesc17",
    "coerceandrelayntlmtoadcs",
    "goldencert",
}
_CA_FIRST_RELATIONS = {
    "adcsesc6",
    "adcsesc6a",
    "adcsesc6b",
    "adcsesc8",
    "adcsesc11",
    "adcsesc16",
    "coerceandrelayntlmtoadcs",
    "goldencert",
}


def is_adcs_relation(relation: object) -> bool:
    """Return ``True`` when the relation is ADCS-related."""
    return str(relation or "").strip().lower() in _ADCS_RELATIONS


def extract_adcs_template_names(details: Mapping[str, Any] | None) -> list[str]:
    """Extract distinct template names from ADCS edge notes."""
    if not isinstance(details, Mapping):
        return []

    templates: list[str] = []

    def _append(candidate: object) -> None:
        if isinstance(candidate, str):
            name = candidate.strip()
            if name:
                templates.append(name)

    _append(details.get("template"))

    for key in ("templates", "agent_templates", "target_templates"):
        raw_value = details.get(key)
        if not isinstance(raw_value, list):
            continue
        for entry in raw_value:
            if isinstance(entry, dict):
                _append(entry.get("name") or entry.get("template"))
            else:
                _append(entry)

    # Compromise-centric ESC edges carry the abused templates / CAs in
    # ``vulnerable_resources`` (the canonical post-derivation field).
    raw_resources = details.get("vulnerable_resources")
    if isinstance(raw_resources, list):
        for entry in raw_resources:
            if isinstance(entry, dict):
                _append(entry.get("name"))

    summary = details.get("templates_summary")
    if isinstance(summary, str) and summary.strip():
        for item in summary.split(","):
            candidate = item.strip()
            if not candidate or candidate.startswith("+"):
                continue
            if "(" in candidate:
                candidate = candidate.split("(", 1)[0].strip()
            _append(candidate)

    return sorted({name for name in templates if name}, key=str.lower)


def has_compromise_centric_target(details: Mapping[str, Any] | None) -> bool:
    """Return True when the edge already targets the impersonated principal.

    Compromise-centric ESC edges carry ``vulnerable_resources`` in their notes
    (set by ``_persist_esc_compromise_steps``). Their ``to`` is the actual
    principal compromised (Domain Admins, Domain Controllers), so display
    redirects must not override the target — the templates belong as a
    relation-column annotation, not as a fake terminal.
    """
    if not isinstance(details, Mapping):
        return False
    raw_resources = details.get("vulnerable_resources")
    return isinstance(raw_resources, list) and bool(raw_resources)


def format_adcs_templates_summary(
    details: Mapping[str, Any] | None,
    *,
    template_metadata: Mapping[str, Mapping[str, Any]] | None = None,
    max_items: int = 3,
) -> str:
    """Build a compact template summary for ADCS notes."""
    template_names = extract_adcs_template_names(details)
    if not template_names:
        return ""

    labels: list[str] = []
    for name in template_names:
        min_key = None
        if isinstance(template_metadata, Mapping):
            metadata = template_metadata.get(name)
            if isinstance(metadata, Mapping):
                raw_min_key = metadata.get("min_key_length")
                if isinstance(raw_min_key, int) and raw_min_key > 0:
                    min_key = raw_min_key
        if min_key:
            labels.append(f"{name}(min_key={min_key})")
        else:
            labels.append(name)

    summary_items = labels[: max_items if max_items > 0 else len(labels)]
    remaining = len(labels) - len(summary_items)
    if remaining > 0:
        summary_items.append(f"+{remaining} more")
    return ", ".join(summary_items)


def resolve_adcs_display_target(
    relation: object,
    details: Mapping[str, Any] | None,
    *,
    fallback_target: str = "",
) -> str:
    """Return the UX display target for an ADCS edge while preserving domain impact internally."""
    fallback = str(fallback_target or "").strip()
    if not is_adcs_relation(relation):
        return fallback

    # Compromise-centric edges (post _persist_esc_compromise_steps) already point
    # at the impersonated principal. Do not override the target — the templates
    # surface as a relation annotation instead.
    if has_compromise_centric_target(details):
        return fallback

    info = details if isinstance(details, Mapping) else {}
    relation_key = str(relation or "").strip().lower()
    ca_name = str(
        info.get("enterpriseca_name") or info.get("enterpriseca") or ""
    ).strip()
    template_names = extract_adcs_template_names(info)

    if relation_key == "adcsesc13":
        linked_group = str(
            info.get("effective_group")
            or info.get("linked_group")
            or info.get("policy_group")
            or info.get("issuance_policy_group")
            or ""
        ).strip()
        return linked_group or fallback
    if relation_key in _CA_FIRST_RELATIONS and ca_name:
        return ca_name
    if len(template_names) == 1:
        return template_names[0]
    if len(template_names) > 1:
        summary = format_adcs_templates_summary(info)
        return f"Templates: {summary}" if summary else "Templates"
    if ca_name:
        return ca_name
    return fallback
