"""Hygiene and misconfiguration audit findings for audit-mode workspaces.

Only called when collection_scope == "audit". All analysis runs on already-
collected CollectionResult data — no additional LDAP queries.
"""

from __future__ import annotations

import time
from typing import Any

from adscan_internal.services.collector.models import (
    AuditFinding,
    CollectionResult,
    DomainPolicy,
)

_FILETIME_EPOCH_OFFSET = 116_444_736_000_000_000
_100NS_PER_SECOND = 10_000_000

_OBSOLETE_OS_SUBSTRINGS = (
    "Windows XP",
    "Windows 7",
    "Windows Server 2003",
    "Windows Server 2008",
    "Windows Server 2012",
)


def _filetime_to_unix(filetime: int) -> float:
    return (filetime - _FILETIME_EPOCH_OFFSET) / _100NS_PER_SECOND


def _days_since_filetime(filetime: int | None) -> float | None:
    if not filetime:
        return None
    unix = _filetime_to_unix(filetime)
    return (time.time() - unix) / 86400


def _is_obsolete_os(os_string: str) -> bool:
    os_lower = os_string.lower()
    return any(obs.lower() in os_lower for obs in _OBSOLETE_OS_SUBSTRINGS)


def _password_compliance_findings(
    result: CollectionResult,
) -> list[AuditFinding]:
    """Build AuditFinding rows from the password compliance snapshot.

    The full per-user table lives on ``result.password_compliance`` and is
    persisted as ``password_compliance.json`` for downstream consumers
    (report, web, spraying). The hygiene panel only needs aggregate
    findings — one per affected user plus, optionally, a single
    domain-level note when the policy has never been modified.
    """
    from adscan_internal.services.password_policy_compliance import (
        analyze_password_compliance,
    )

    report = analyze_password_compliance(result)
    if report is None:
        return []
    result.password_compliance = report

    findings: list[AuditFinding] = []

    if report.policy_never_modified:
        findings.append(
            AuditFinding(
                category="pwd_policy_never_modified",
                samaccountname="(domain)",
                object_id="",
                detail=(
                    "Default Domain Policy has not been modified since the "
                    "domain was created — running the original provisioning "
                    "template, typically with weaker defaults."
                ),
                severity="medium",
            )
        )

    for entry in report.entries:
        if not entry.pwd_predates_policy:
            continue
        findings.append(
            AuditFinding(
                category="pwd_predates_policy",
                samaccountname=entry.samaccountname,
                object_id=entry.object_id,
                detail=(
                    f"pwdLastSet predates last modification of "
                    f"{entry.applied_policy_name}"
                    + (
                        f" ({entry.pwd_age_days}d ago)"
                        if entry.pwd_age_days is not None
                        else ""
                    )
                ),
                severity=entry.risk_level,
                highvalue=entry.is_admin_like,
            )
        )

    return findings


def analyze_audit_findings(
    result: CollectionResult,
    domain_policy: DomainPolicy | None,
    *,
    stale_days: int = 90,
    krbtgt_age_days: int = 180,
) -> list[AuditFinding]:
    """Compute hygiene findings from CollectionResult. Returns [] for ctf scope."""
    if result.collection_scope != "audit":
        return []

    findings: list[AuditFinding] = []

    def _is_human_user(node: Any) -> bool:
        """True for enabled, non-machine User nodes — mirrors get_enabled_users()."""
        return (
            node.kind == "User"
            and bool(node.enabled)
            and not str(node.samaccountname).endswith("$")
        )

    for node in result.nodes.values():
        if _is_human_user(node):
            lastlogon = node.properties.get("lastlogon")
            days_ago = _days_since_filetime(lastlogon)
            if days_ago is not None and days_ago > stale_days:
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="stale_user",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"Last logon {int(days_ago)} days ago",
                        # Catalog baseline: LOW (3.5); Tier-0 elevation: MEDIUM (6.0)
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            if node.properties.get("passwordnotreqd"):
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="passwd_notreqd",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="PASSWD_NOTREQD UAC flag set — account may have blank password",
                        # Catalog baseline: LOW (3.5); Tier-0 elevation: MEDIUM (6.0).
                        # Escalates to HIGH via blank-password spray confirmation
                        # (CONDITION_EXPLOITATION in contextual_rules.py).
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            # Exclude krbtgt (RID -502) — has its own dedicated krbtgt_age category.
            if node.properties.get("pwdneverexpires") and not node.object_id.endswith("-502"):
                is_hv = bool(node.highvalue or node.properties.get("admincount"))
                findings.append(
                    AuditFinding(
                        category="pwd_never_expires",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="DONT_EXPIRE_PASSWORD UAC flag set",
                        # Catalog baseline: LOW (3.7); Tier-0 elevation: MEDIUM (6.5)
                        severity="medium" if is_hv else "low",
                        highvalue=is_hv,
                    )
                )

            if node.properties.get("rc4_only"):
                findings.append(
                    AuditFinding(
                        category="rc4_only",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="Only RC4 (no AES) in msDS-SupportedEncryptionTypes",
                        severity="medium",
                        highvalue=bool(node.highvalue or node.properties.get("admincount")),
                    )
                )

        if node.kind == "User" and node.object_id.endswith("-502"):
            pwdlastset = node.properties.get("pwdlastset")
            days_ago = _days_since_filetime(pwdlastset)
            if days_ago is not None and days_ago > krbtgt_age_days:
                findings.append(
                    AuditFinding(
                        category="krbtgt_age",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"krbtgt password last changed {int(days_ago)} days ago",
                        # MEDIUM baseline — hygiene/rotation issue. Golden Ticket
                        # forgery requires the krbtgt hash, which already implies
                        # Domain Admin (DCSync). Promotes to CRITICAL via the
                        # separate krbtgt_pass finding when secret recovery or
                        # Golden Ticket usage is confirmed.
                        severity="medium",
                    )
                )

        if node.kind == "Computer":
            os_str = str(node.properties.get("os") or "")
            if os_str and _is_obsolete_os(os_str):
                findings.append(
                    AuditFinding(
                        category="obsolete_os",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail=f"Obsolete OS: {os_str}",
                        # LOW baseline — MAQ > 0 is the AD default, an enabler not confirmed exploitation.
                    severity="low",
                        highvalue=bool(node.highvalue),
                    )
                )

            if node.properties.get("rc4_only"):
                findings.append(
                    AuditFinding(
                        category="rc4_only",
                        samaccountname=node.samaccountname,
                        object_id=node.object_id,
                        detail="Only RC4 (no AES) in msDS-SupportedEncryptionTypes",
                        severity="medium",
                        highvalue=bool(node.highvalue or node.properties.get("admincount")),
                    )
            )

    if domain_policy is not None:
        maq = domain_policy.machine_account_quota
        if maq is not None and maq > 0:
            findings.append(
                AuditFinding(
                    category="machine_quota_risk",
                    samaccountname="(domain)",
                    object_id="",
                    detail=(
                        f"ms-DS-MachineAccountQuota = {maq} — "
                        "any domain user can add computers"
                    ),
                    # LOW baseline — MAQ > 0 is the AD default, an enabler not confirmed exploitation.
                    severity="low",
                )
            )

    findings.extend(_password_compliance_findings(result))

    return findings


def analyze_host_audit_findings(result: CollectionResult) -> list[AuditFinding]:
    """Hygiene findings that require SMB host-collection data.

    Called by the orchestrator AFTER collect_domain_hosts() so that Computer
    nodes already carry smb_signing_required / smb_dialect from the SMB
    negotiate phase. Safe to call even if host collection was skipped — nodes
    will simply lack the relevant properties and no findings are emitted.

    Note on SMBv1: the current smb_collector.py negotiate only offers SMB2+
    dialects (SMB202…SMB311). SMBv1 detection would require adding the legacy
    NT LM 0.12 dialect code to the offered list — tracked as a future change.
    """
    if result.collection_scope != "audit":
        return []

    findings: list[AuditFinding] = []

    for node in result.nodes.values():
        if node.kind != "Computer":
            continue

        # smb_signing_required is only present when host collection ran.
        signing_required = node.properties.get("smb_signing_required")
        if signing_required is None:
            continue

        if not signing_required:
            findings.append(
                AuditFinding(
                    category="smb_signing_disabled",
                    samaccountname=node.samaccountname,
                    object_id=node.object_id,
                    detail=(
                        f"SMB signing not required — "
                        f"dialect {node.properties.get('smb_dialect') or 'unknown'}"
                    ),
                    # HIGH if DC/high-value (ideal relay target), MEDIUM otherwise.
                    # Catalog baseline: MEDIUM (5.0); Tier-0 elevation: HIGH (8.0).
                    severity="high" if node.highvalue else "medium",
                    highvalue=node.highvalue,
                )
            )

        if node.properties.get("smb_v1"):
            findings.append(
                AuditFinding(
                    category="smb_v1_enabled",
                    samaccountname=node.samaccountname,
                    object_id=node.object_id,
                    detail="SMBv1 (NT LM 0.12) protocol accepted by host",
                    # HIGH — SMBv1 is deprecated, has known critical CVEs
                    # (EternalBlue/MS17-010), and should never be enabled.
                    severity="high" if node.highvalue else "medium",
                    highvalue=node.highvalue,
                )
            )

    return findings


__all__ = ["analyze_audit_findings", "analyze_host_audit_findings"]
