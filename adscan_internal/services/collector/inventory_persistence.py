"""Offline inventory persistence for native collector output."""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    CollectorNode,
    DomainPolicy,
    PasswordComplianceReport,
    PasswordSettingsObject,
)
from adscan_internal.workspaces import domain_subpath, write_json_file

INVENTORY_SCHEMA_VERSION = "inventory-1.0"

_NODE_KIND_TO_FILE: dict[str, str] = {
    "User": "users.json",
    "Group": "groups.json",
    "Computer": "computers.json",
    "OU": "ous.json",
    "GPO": "gpos.json",
    "Container": "containers.json",
    "ForeignSecurityPrincipal": "foreign_security_principals.json",
    "CertTemplate": "adcs_templates.json",
    "EnterpriseCA": "adcs_enterprise_cas.json",
    "RootCA": "adcs_root_cas.json",
    "AIACA": "adcs_aia_cas.json",
    "NTAuthStore": "adcs_ntauth_stores.json",
    "Domain": "domains.json",
}

_RELATION_TO_FILE: dict[str, str] = {
    "MemberOf": "memberships.json",
    "GPLink": "gpo_links.json",
    "TrustedBy": "trusts.json",
    "ADCSESC1": "adcs_attack_steps.json",
    "ADCSESC2": "adcs_attack_steps.json",
    "ADCSESC3": "adcs_attack_steps.json",
    "ADCSESC4": "adcs_attack_steps.json",  # write on template
    "ADCSESC5": "adcs_attack_steps.json",  # write on PKI container objects
    "ADCSESC6": "adcs_attack_steps.json",
    "ADCSESC7": "adcs_attack_steps.json",
    "ADCSESC8": "adcs_attack_steps.json",
    "ADCSESC9": "adcs_attack_steps.json",
    "ADCSESC10": "adcs_attack_steps.json",
    "ADCSESC11": "adcs_attack_steps.json",
    "ADCSESC13": "adcs_attack_steps.json",
    "ADCSESC14": "adcs_attack_steps.json",
    "ADCSESC15": "adcs_attack_steps.json",
    "ADCSESC16": "adcs_attack_steps.json",
    "ADCSESC17": "adcs_attack_steps.json",
}
_DCSYNC_RELATIONS: frozenset[str] = frozenset(
    {"GetChanges", "GetChangesAll", "GetChangesInFilteredSet"}
)

_DEFAULT_EDGE_FILE = "acls.json"


class CollectorInventoryPersistence:
    """Persist complete collector inventory into query-oriented JSON files."""

    def persist(
        self,
        shell: object,
        *,
        domain: str,
        result: CollectionResult,
    ) -> dict[str, int]:
        """Persist inventory files for one collector result.

        Args:
            shell: Runtime shell used to resolve workspace paths.
            domain: Domain being persisted.
            result: Complete collector output.

        Returns:
            File/category counters useful for logs and tests.
        """
        generated_at = datetime.now(timezone.utc).isoformat()
        inventory_dir = _inventory_dir(shell, domain)
        os.makedirs(inventory_dir, exist_ok=True)

        node_records_by_file = _group_node_records(result)
        edge_records_by_file = _group_edge_records(result)

        files_written = 0
        object_count = 0
        edge_count = 0
        index_files: dict[str, dict[str, Any]] = {}

        for filename, records in sorted(node_records_by_file.items()):
            _write_inventory_file(
                inventory_dir,
                filename,
                domain=domain,
                generated_at=generated_at,
                record_type="nodes",
                records=records,
            )
            files_written += 1
            object_count += len(records)
            index_files[filename] = {"type": "nodes", "count": len(records)}

        for filename, records in sorted(edge_records_by_file.items()):
            _write_inventory_file(
                inventory_dir,
                filename,
                domain=domain,
                generated_at=generated_at,
                record_type="edges",
                records=records,
            )
            files_written += 1
            edge_count += len(records)
            index_files[filename] = {"type": "edges", "count": len(records)}

        # Persist the DomainPolicy snapshot when the collector captured it.
        # This unblocks the web app's Password posture card — the data was
        # collected for the spray-policy heuristics but never made it past
        # the collector's in-process state. Writing it as one inventory
        # file keeps the workspace shape consistent with every other
        # collector artefact.
        if isinstance(result.domain_policy, DomainPolicy):
            _write_domain_policy_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                policy=result.domain_policy,
            )
            files_written += 1
            index_files["domain_policy.json"] = {
                "type": "policy",
                "count": 1,
            }

        # PSOs (fine-grained password policies). One file per workspace
        # listing every PSO under the Password Settings Container — can
        # be empty (no PSO configured) which is the common case.
        if result.psos:
            _write_psos_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                psos=result.psos,
            )
            files_written += 1
            index_files["password_settings_objects.json"] = {
                "type": "psos",
                "count": len(result.psos),
            }

        # Password compliance snapshot — per-user diagnostic of which
        # users are likely outside the current policy because their
        # pwdLastSet predates the last modification of the policy
        # object that governs them. Consumed by the report builder,
        # the web product and password-spraying candidate selection.
        if isinstance(result.password_compliance, PasswordComplianceReport):
            _write_password_compliance_file(
                inventory_dir,
                domain=domain,
                generated_at=generated_at,
                report=result.password_compliance,
            )
            files_written += 1
            index_files["password_compliance.json"] = {
                "type": "password_compliance",
                "count": result.password_compliance.users_total,
            }

        index = {
            "schema_version": INVENTORY_SCHEMA_VERSION,
            "domain": domain,
            "generated_at": generated_at,
            "files": index_files,
            "totals": {
                "files": files_written,
                "nodes": object_count,
                "edges": edge_count,
            },
        }
        write_json_file(os.path.join(inventory_dir, "index.json"), index)
        return {
            "inventory_files": files_written + 1,
            "inventory_nodes": object_count,
            "inventory_edges": edge_count,
        }


def _inventory_dir(shell: object, domain: str) -> str:
    workspace_cwd = (
        shell._get_workspace_cwd()  # noqa: SLF001
        if hasattr(shell, "_get_workspace_cwd")
        else getattr(shell, "current_workspace_dir", "")
    )
    domains_dir = getattr(shell, "domains_dir", "domains")
    return domain_subpath(workspace_cwd, domains_dir, domain, "inventory")


def _group_node_records(result: CollectionResult) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for node in result.nodes.values():
        if node.properties.get("well_known_sid"):
            filename = "well_known_principals.json"
        else:
            filename = _NODE_KIND_TO_FILE.get(str(node.kind), "objects.json")
        grouped[filename].append(_node_inventory_record(node))
    return {
        name: sorted(records, key=_record_sort_key) for name, records in grouped.items()
    }


def _group_edge_records(result: CollectionResult) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in result.edges:
        filename = _edge_inventory_filename(edge)
        grouped[filename].append(_edge_inventory_record(edge, result))
    return {
        name: sorted(records, key=_record_sort_key) for name, records in grouped.items()
    }


def _edge_inventory_filename(edge: CollectorEdge) -> str:
    relation = str(edge.relation or "").strip()
    if relation in _RELATION_TO_FILE:
        return _RELATION_TO_FILE[relation]
    if relation in _DCSYNC_RELATIONS:
        return "dcsync_rights.json"
    if str(edge.method or "").strip().lower() == "acl":
        return _DEFAULT_EDGE_FILE
    return "relationships.json"


def _node_inventory_record(node: CollectorNode) -> dict[str, Any]:
    payload = node.to_graph_payload()
    properties = (
        payload.get("properties") if isinstance(payload.get("properties"), dict) else {}
    )
    return {
        "object_id": node.object_id,
        "kind": node.kind,
        "name": node.name,
        "domain": node.domain,
        "samaccountname": node.samaccountname,
        "distinguished_name": node.distinguished_name,
        "enabled": node.enabled,
        "highvalue": node.highvalue,
        "properties": properties,
    }


def _edge_inventory_record(
    edge: CollectorEdge,
    result: CollectionResult,
) -> dict[str, Any]:
    source = result.nodes.get(edge.source_object_id.upper())
    target = result.nodes.get(edge.target_object_id.upper())
    return {
        "source_object_id": edge.source_object_id,
        "source_name": source.name if source else "",
        "source_kind": source.kind if source else "",
        "target_object_id": edge.target_object_id,
        "target_name": target.name if target else "",
        "target_kind": target.kind if target else "",
        "relation": edge.relation,
        "source": edge.source,
        "method": edge.method,
        "notes": edge.notes,
    }


def _write_inventory_file(
    inventory_dir: str,
    filename: str,
    *,
    domain: str,
    generated_at: str,
    record_type: str,
    records: list[dict[str, Any]],
) -> None:
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": record_type,
        "count": len(records),
        "records": records,
    }
    write_json_file(os.path.join(inventory_dir, filename), payload)


def _write_domain_policy_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    policy: DomainPolicy,
) -> None:
    """Persist the DomainPolicy snapshot as ``domain_policy.json``.

    Shape mirrors ``DomainPolicy`` exactly so the backend parser can
    rebuild the dataclass with no ambiguity. ``None`` values stay
    ``null`` in JSON — they distinguish "policy bit not set" from
    "policy bit explicitly zero" (lockoutThreshold=0 means lockout
    disabled, very different from None=not collected).
    """
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "policy",
        "policy": {
            "min_pwd_length": policy.min_pwd_length,
            "lockout_threshold": policy.lockout_threshold,
            "lockout_window_minutes": policy.lockout_window_minutes,
            "max_pwd_age_days": policy.max_pwd_age_days,
            "pwd_history_length": policy.pwd_history_length,
            "machine_account_quota": policy.machine_account_quota,
            # ``None`` distinguishes "attribute unreadable" from "explicitly
            # disabled"; downstream renderers must treat None as unknown.
            "complexity_enabled": policy.complexity_enabled,
            # ISO timestamp of the most recent password-policy attribute
            # change, derived from msDS-ReplAttributeMetaData. None when
            # the attribute was unreadable.
            "pwd_policy_last_changed": policy.pwd_policy_last_changed,
            # Per-attribute breakdown: list of [attr, iso_ts, version].
            # version==1 means set at provisioning, never explicitly changed.
            "pwd_attrs_when_changed": [
                list(t) for t in policy.pwd_attrs_when_changed
            ],
        },
    }
    write_json_file(os.path.join(inventory_dir, "domain_policy.json"), payload)


def _write_psos_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    psos: list[PasswordSettingsObject],
) -> None:
    """Persist all PSOs as ``password_settings_objects.json``.

    Shape mirrors :class:`PasswordSettingsObject` so the backend parser
    rebuilds the dataclass with no ambiguity. ``applies_to`` is a list
    of trustee DNs (the principals targeted by each PSO).
    """
    records = [
        {
            "name": pso.name,
            "distinguished_name": pso.distinguished_name,
            "precedence": pso.precedence,
            "min_pwd_length": pso.min_pwd_length,
            "max_pwd_age_days": pso.max_pwd_age_days,
            "min_pwd_age_days": pso.min_pwd_age_days,
            "lockout_threshold": pso.lockout_threshold,
            "lockout_observation_window_minutes": pso.lockout_observation_window_minutes,
            "lockout_duration_minutes": pso.lockout_duration_minutes,
            "pwd_history_length": pso.pwd_history_length,
            "complexity_enabled": pso.complexity_enabled,
            "reversible_encryption_enabled": pso.reversible_encryption_enabled,
            "applies_to": list(pso.applies_to),
            "pwd_policy_last_changed": pso.pwd_policy_last_changed,
            "pwd_attrs_when_changed": [list(t) for t in pso.pwd_attrs_when_changed],
        }
        for pso in psos
    ]
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "psos",
        "count": len(records),
        "psos": records,
    }
    write_json_file(
        os.path.join(inventory_dir, "password_settings_objects.json"), payload
    )


def _write_password_compliance_file(
    inventory_dir: str,
    *,
    domain: str,
    generated_at: str,
    report: PasswordComplianceReport,
) -> None:
    """Persist the password compliance snapshot as
    ``password_compliance.json``.

    Shape mirrors :class:`PasswordComplianceReport` exactly. The full
    list of enabled-user rows is included — downstream consumers can
    re-filter offline (e.g. password spraying may want only entries
    with ``pwd_predates_policy=True``; the PDF report may want admin
    rows first; the web UI may show paginated full data). Storing the
    full table once avoids re-running the analysis from each surface.
    """
    payload = {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "domain": domain,
        "generated_at": generated_at,
        "record_type": "password_compliance",
        "policy_pwd_last_changed": report.policy_pwd_last_changed,
        "policy_never_modified": report.policy_never_modified,
        "policy_pwd_attrs": [list(t) for t in report.policy_pwd_attrs],
        "psos_count": report.psos_count,
        "totals": {
            "users": report.users_total,
            "users_with_predates_policy": report.users_with_predates_policy,
            "users_with_over_max_age": report.users_with_over_max_age,
            "users_with_never_expires": report.users_with_never_expires,
        },
        "entries": [
            {
                "samaccountname": entry.samaccountname,
                "object_id": entry.object_id,
                "distinguished_name": entry.distinguished_name,
                "enabled": entry.enabled,
                "is_admin_like": entry.is_admin_like,
                "pwd_last_set_filetime": entry.pwd_last_set_filetime,
                "pwd_last_set_iso": entry.pwd_last_set_iso,
                "pwd_age_days": entry.pwd_age_days,
                "applied_policy_name": entry.applied_policy_name,
                "applied_policy_dn": entry.applied_policy_dn,
                "applied_policy_when_changed": entry.applied_policy_when_changed,
                "pwd_predates_policy": entry.pwd_predates_policy,
                "pwd_over_max_age": entry.pwd_over_max_age,
                "pwd_never_expires": entry.pwd_never_expires,
                "risk_level": entry.risk_level,
                "notes": list(entry.notes),
            }
            for entry in report.entries
        ],
    }
    write_json_file(
        os.path.join(inventory_dir, "password_compliance.json"), payload
    )


def _record_sort_key(record: dict[str, Any]) -> tuple[str, str, str]:
    return (
        str(record.get("name") or record.get("source_name") or "").casefold(),
        str(record.get("relation") or "").casefold(),
        str(record.get("target_name") or record.get("object_id") or "").casefold(),
    )
