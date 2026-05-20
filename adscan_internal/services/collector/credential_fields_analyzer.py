"""Analyze credential-bearing LDAP fields collected by ldap_collector.

Runs CredSweeper (library mode) over description, unixUserPassword,
userPassword and info fields from CollectionResult nodes in one batch,
returning structured CredentialFieldFinding instances.
"""

from __future__ import annotations

from adscan_internal import telemetry
from adscan_internal.rich_output import print_warning, print_warning_debug
from adscan_internal.services.collector.models import (
    CollectionResult,
    CredentialFieldFinding,
)
from adscan_internal.services.credsweeper_library_service import (
    CredSweeperLibraryService,
    InMemoryCredSweeperTarget,
)
from adscan_internal.services.credsweeper_service import (
    CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
)

_CRED_FIELDS = ("description", "unix_user_password", "user_password", "info_field")
_CRED_KINDS = {"User", "Computer", "Group"}


def _build_targets_from_result(
    result: CollectionResult,
) -> tuple[list[InMemoryCredSweeperTarget], dict[str, tuple[str, str, str]]]:
    """Build CredSweeper targets and path index from all credential-bearing node fields."""
    targets: list[InMemoryCredSweeperTarget] = []
    path_index: dict[str, tuple[str, str, str]] = {}
    for node in result.nodes.values():
        if node.kind not in _CRED_KINDS:
            continue
        fields_to_check = _CRED_FIELDS if node.kind == "User" else ("description",)
        for field in fields_to_check:
            value = str(node.properties.get(field) or "").strip()
            if not value:
                continue
            key = f"{node.object_id}/{field}"
            targets.append(
                InMemoryCredSweeperTarget(
                    content=value.encode("utf-8", errors="replace"),
                    file_path=key,
                    file_type=".txt",
                    info=f"{node.samaccountname}/{field}",
                )
            )
            path_index[key] = (node.object_id, field, node.samaccountname)
    return targets, path_index


def analyze_credential_fields(
    result: CollectionResult,
) -> list[CredentialFieldFinding]:
    """Scan all credential-bearing LDAP fields in result with CredSweeper.

    Operates in a single batch call to amortize CredSweeper initialization.
    Returns an empty list on any CredSweeper error (non-fatal).
    """
    targets, path_index = _build_targets_from_result(result)
    if not targets:
        return []

    try:
        raw = CredSweeperLibraryService().analyze_targets_with_options(
            targets,
            rules_profile=CREDSWEEPER_RULES_PROFILE_LDAP_DESCRIPTION,
            include_custom_rules=True,
            ml_threshold="0.0",
            no_filters=True,
            doc=True,
        )
    except Exception as exc:
        telemetry.capture_exception(exc)
        print_warning(
            f"Credential field analysis failed for domain {result.domain} — findings may be incomplete."
        )
        print_warning_debug(f"CredSweeper error: {type(exc).__name__}: {exc}")
        return []

    findings: list[CredentialFieldFinding] = []
    for rule_name, entries in raw.items():
        for value, ml_probability, context_line, _line_num, file_path in entries:
            if file_path not in path_index:
                continue
            object_id, field, samaccountname = path_index[file_path]
            findings.append(
                CredentialFieldFinding(
                    samaccountname=samaccountname,
                    object_id=object_id,
                    field=field,
                    raw_value=value,
                    rule_name=rule_name,
                    ml_probability=ml_probability,
                    context_line=context_line,
                )
            )
    return findings


__all__ = ["analyze_credential_fields"]
