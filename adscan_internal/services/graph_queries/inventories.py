from __future__ import annotations

from typing import Any

from adscan_internal.services.graph_queries.filters import (
    STALE_DAYS_DEFAULT,
    domain_matches,
    is_enabled,
    is_stale,
)
from adscan_internal.services.graph_queries.tier_classification import (
    is_tier0_or_high_value,
)


def _nodes_props(graph: dict[str, Any], kind: str, domain: str) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == kind and domain_matches(node, domain)
    ]


def _prop_enabled(props: dict[str, Any]) -> bool:
    v = props.get("enabled")
    return bool(v) if v is not None else True


def _is_managed_service_account(props: dict[str, Any]) -> bool:
    distinguished_name = str(props.get("distinguishedname") or "").casefold()
    if "cn=managed service accounts," in distinguished_name:
        return True

    object_classes = props.get("objectclasses") or props.get("objectClass") or []
    if isinstance(object_classes, str):
        object_classes = [object_classes]
    return any(
        str(value).casefold()
        in {"msds-managedserviceaccount", "msds-groupmanagedserviceaccount"}
        for value in object_classes
    )


def _is_machine_or_trust_user(props: dict[str, Any]) -> bool:
    """Return True for machine-like principals represented as User nodes.

    Native collection can surface inter-domain trust accounts and some
    machine-like principals as BloodHound-compatible User nodes.  They are
    valid graph entities, but they should not enter human user inventories or
    user-focused attack workflows.
    """
    samaccountname = str(props.get("samaccountname") or "").strip()
    return samaccountname.endswith("$")


def get_enabled_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        p
        for p in _nodes_props(graph, "User", domain)
        if _prop_enabled(p) and not _is_machine_or_trust_user(p)
    ]


def get_enabled_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        p
        for p in _nodes_props(graph, "Computer", domain)
        if _prop_enabled(p) and not _is_managed_service_account(p)
    ]


def get_high_value_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == "User"
        and domain_matches(node, domain)
        and is_enabled(node)
        and is_tier0_or_high_value(node)
    ]


def get_kerberoastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("hasspn")]


def get_asreproastable_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("dontreqpreauth")]


def get_stale_users(
    graph: dict[str, Any],
    domain: str,
    stale_days: int = STALE_DAYS_DEFAULT,
) -> list[dict[str, Any]]:
    return [
        node.get("properties") or {}
        for node in (graph.get("nodes") or {}).values()
        if node.get("kind") == "User"
        and domain_matches(node, domain)
        and is_enabled(node)
        and is_stale(node, stale_days)
    ]


def get_admincount_users(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("admincount")]


def get_laps_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_computers(graph, domain) if p.get("haslaps")]


def get_non_laps_computers(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [p for p in get_enabled_computers(graph, domain) if not p.get("haslaps")]


def get_sessions(graph: dict[str, Any], domain: str) -> list[dict[str, Any]]:
    return [
        {"computer_id": e.get("from"), "user_id": e.get("to")}
        for e in (graph.get("edges") or [])
        if e.get("relation") == "HasSession"
    ]


def get_pwdneverexpires_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("pwdneverexpires")]


def get_passwordnotreqd_users(
    graph: dict[str, Any], domain: str
) -> list[dict[str, Any]]:
    return [p for p in get_enabled_users(graph, domain) if p.get("passwordnotreqd")]
