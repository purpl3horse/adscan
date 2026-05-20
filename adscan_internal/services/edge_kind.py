"""Canonical EdgeKind classification for the ADscan attack graph.

This module is the single source of truth that separates *what an edge is*
(its BloodHound ``relation`` label) from *what effect it grants* (its
``EdgeKind``). The separation is the foundation of the Phase 1 attack-graph
refactor and is documented in:

- ``adscan-private-tool/CLAUDE.md`` (§ Nomenclature Standard)
- ``adscan-obsidian/business/12_nomenclature_standard.md``
  (§ Fase 1 — separación canónica de tres dimensiones)

Motivation: the previous model conflated semantics, effect and lifecycle
state into a single string. That caused false positives such as the HTB
Forest path
``SVC-ALFRESCO -> MemberOf -> PRIVILEGED IT ACCOUNTS -> CanPSRemote -> FOREST$``
being classified as ``DOMAIN_BREAKER`` when ``CanPSRemote`` only opens a
WinRM session — it does not, by itself, modify the target object.

Adding a new edge to the attack graph **requires** adding it here. Edges
not present in the catalog map to :attr:`EdgeKind.UNKNOWN` and emit a
verbose warning so unclassified vectors surface during development.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

from adscan_core.rich_output import print_warning


class EdgeKind(str, Enum):
    """Canonical effect classification for an attack-graph edge.

    See :mod:`adscan_internal.services.edge_kind` module docstring and
    `12_nomenclature_standard.md` for the full taxonomy.
    """

    CONTROL = "control"
    AUTH = "auth"
    MEMBERSHIP = "membership"
    TRUST = "trust"
    DERIVED = "derived"
    ESCALATION = "escalation"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Catalog — closed set, mirrors the table in 12_nomenclature_standard.md.
# Adding a new edge in the codebase MUST come with an entry here. The
# UNKNOWN safety net only exists to surface drift during development; it is
# not a substitute for explicit classification.
# ---------------------------------------------------------------------------


_CONTROL_EDGES: Final[frozenset[str]] = frozenset(
    {
        # Object control (BloodHound DACL primitives)
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "AllExtendedRights",
        # Group manipulation
        "AddMember",
        "AddSelf",
        # Credential abuse — direct write/read of credential material
        "ForceChangePassword",
        "AddKeyCredentialLink",
        "HasShadowCredentials",
        "DCSync",
        "GetChanges",
        "GetChangesAll",
        "GetChangesInFilteredSet",
        "ReadGMSAPassword",
        "ReadLAPSPassword",
        # Delegation primitives — modify msDS-Allowed* attributes
        "AllowedToDelegate",
        "AllowedToAct",
        # Unconstrained Kerberos delegation — TrustedForDelegation=True on a
        # computer object.  Any user authenticating to this host leaks their TGT.
        "UnconstrainedDelegation",
        # Writes msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD setup)
        "AddAllowedToAct",
        # ADscan synthetic / writable-attribute control edges
        "ManageRODCPrp",
        "WriteLogonScript",
        # Writes msDS-AllowedToActOnBehalfOfOtherIdentity for RBCD —
        # same control class as WriteLogonScript (writable-attribute
        # primitive enabling delegation/code execution).
        "WriteAccountRestrictions",
        # Write servicePrincipalName — enables targeted Kerberoasting abuse
        "WriteSPN",
        # Write UNC/SMBPath attribute — enables NTLM coercion
        "WriteSMBPath",
        # LAPS password sync/replicate (credential read primitive)
        "SyncLAPSPassword",
        # Credential discovery in files/shares (read of plaintext credential)
        "GPPPassword",
        "PasswordInShare",
        "PasswordInFile",
        # SMB share access (ADscan native share collector). These are
        # access_capability_only edges over a share resource — not control
        # over an AD object — but they belong in the CONTROL kind because
        # they grant a write/read capability that downstream techniques
        # (lateral tool transfer, NTLM coercion via writable share) consume.
        "ReadShare",
        "WriteShare",
        "FullControlShare",
    }
)


_AUTH_EDGES: Final[frozenset[str]] = frozenset(
    {
        # Establish a session/shell on the target with the source's privilege
        "CanPSRemote",
        "CanRDP",
        "AdminTo",
        "ExecuteDCOM",
        "HasSession",
        "SQLAdmin",
        # SQL Server access (session-level, below sysadmin)
        "SQLAccess",
        # Anonymous / null sessions
        "GuestSession",
        "LDAPAnonymousBind",
    }
)


_MEMBERSHIP_EDGES: Final[frozenset[str]] = frozenset({"MemberOf"})


_TRUST_EDGES: Final[frozenset[str]] = frozenset(
    {
        "TrustedBy",
        "HasSIDHistory",
        "Contains",
        "GPLink",
    }
)


_DERIVED_EDGES: Final[frozenset[str]] = frozenset(
    {
        # Phase 6 — promoted by ADscan post-exploitation when proof exists
        "DumpedHashOf",
        "ForgedTicketFor",
        "ReadGMSAPasswordOf",
        "OwnsCertificateFor",
        # Golden certificate — forged from recovered CA private key (like ForgedTicketFor)
        "GoldenCert",
        # Credential dump techniques — also used as virtual bridge edges by the
        # implicit DumpLSA overlay in attack_graph_core._build_implicit_dumplsa_overlay
        "DumpLSA",
        "DumpLSASS",
        "DumpSAM",
        "DumpDPAPI",
        # RODC post-exploitation chain (extract krbtgt → forge golden ticket)
        "PrepareRODCCredentialCaching",
        "ExtractRODCKrbtgtSecret",
        "ForgeRODCGoldenTicket",
        # Kerberos keylist attack (RODC — reads pre-auth encryption keys)
        "KerberosKeyList",
        # Native CVE scanner — coercion techniques confirmed at runtime
        # BH CE PascalCase variants (CoercePetitPotam, etc.) kept for BH parity
        "CoercePetitPotam",
        "CoercePrinterBug",
        "CoerceShadowCoerce",
        "CoerceMSEvenCoerce",
        "CoerceDFSCoerce",
        # ADscan native coercion relation names (catalog uses short names)
        "PetitPotam",
        "PrinterBug",
        "DfsCoerce",
        "MsEven",
        # Coerce + relay NTLM to ADCS CA (composite technique confirmed at runtime)
        "CoerceAndRelayNTLMToADCS",
        # Coerce principal into authenticating → capture TGT
        "CoerceToTGT",
        # Native CVE scanner Slice 2 — DC-pack vulnerabilities confirmed at runtime
        "Zerologon",
        "NoPac",
        "PrintNightmare",
        "BadSuccessor",
        # Native CVE scanner Slice 3 — host-level CVEs and NTLM enablers
        "MS17-010",
        "SMBGhost",
        "PrinterBugSurface",
        "WebDAVEnabled",
        "DropTheMIC",
        "NTLMReflection",
    }
)


_ESCALATION_EDGES: Final[frozenset[str]] = frozenset(
    {
        # Privileged-group one-technique escalations to Tier 0
        "BackupOperatorsEscalation",
        "DnsAdminsEscalation",
        "AccountOperatorsEscalation",
        "PrintOperatorsEscalation",
        "ServerOperatorsEscalation",
        "SchemaAdminsEscalation",
        "ExchangeAclEscalation",
        # ADscan synthetic escalation aliases (attack_graph_core.py)
        "BackupOperatorEscalation",
        "DnsAdminAbuse",
        "PrintOperatorAbuse",
        # Credential-recovery techniques (require offline cracking)
        "Kerberoasting",
        "ASREPRoasting",
        "Timeroasting",
        # Privileged-group control (generic group-based escalation)
        "PrivilegedGroupControl",
        # Lateral / pass-reuse escalation across local-admin clusters
        "LocalAdminPassReuse",
        # Domain credential reuse (password reused across domain accounts)
        "DomainPassReuse",
        "DomainPassReuseSource",
        # Local credential reused in domain context
        "LocalCredReuseSource",
        "LocalCredToDomainReuse",
        # Single-attempt credential recovery via authentication test
        "PasswordSpray",
        "UserAsPass",
        "BlankPassword",
        "ComputerPre2k",
        # MSSQL post-exploitation escalation (ADscan native, not in BloodHound CE)
        # SeImpersonatePrivilege present  → CLR potato chain (GodPotato/SweetPotato)
        "MssqlSeImpersonateEscalation",
        # SeImpersonatePrivilege absent   → Forshaw shared logon session recovery
        "MssqlTokenTheftEscalation",
        # MSSQL linked-server lateral movement (sysadmin hop to a second SQL instance)
        "MssqlLinkedServerLateral",
        # MSSQL privilege escalation via EXECUTE AS LOGIN (e.g. low-priv → sa)
        "MssqlImpersonateLogin",
        # MSSQL privilege escalation via TRUSTWORTHY database dbo impersonation
        "MssqlTrustworthyDbEscalation",
        # MSSQL NTLMv2 hash theft via xp_dirtree / forced SMB auth
        "MssqlNtlmv2Theft",
    }
)


# ADCS ESC* are template/CA control techniques: they grant control over a
# certificate-issuance object that ultimately yields an authentication
# certificate for the target. We classify them as ``control`` because the
# step itself is a write/abuse on a CA or template object.
_ADCS_ESC_PREFIX: Final[str] = "ADCSESC"


# Case-insensitive lookup index built from the catalog above. Real-world
# edges drift in casing — ADscan native code emits ``WriteDACL`` (uppercase
# ACL), BloodHound CE emits ``WriteDacl`` (PascalCase). Both are the same
# edge; the index normalizes by lowercasing so both resolve to ``CONTROL``.
def _build_kind_index() -> dict[str, EdgeKind]:
    index: dict[str, EdgeKind] = {}
    for relation in _CONTROL_EDGES:
        index[relation.lower()] = EdgeKind.CONTROL
    for relation in _AUTH_EDGES:
        index[relation.lower()] = EdgeKind.AUTH
    for relation in _MEMBERSHIP_EDGES:
        index[relation.lower()] = EdgeKind.MEMBERSHIP
    for relation in _TRUST_EDGES:
        index[relation.lower()] = EdgeKind.TRUST
    for relation in _DERIVED_EDGES:
        index[relation.lower()] = EdgeKind.DERIVED
    for relation in _ESCALATION_EDGES:
        index[relation.lower()] = EdgeKind.ESCALATION
    return index


_KIND_BY_LOWER: Final[dict[str, EdgeKind]] = _build_kind_index()
_ADCS_ESC_PREFIX_LOWER: Final[str] = _ADCS_ESC_PREFIX.lower()

# Per-process cache of relations we've already warned about, so a
# truly-unknown relation is reported once instead of once per persisted
# edge (a single Forest run can hit the same edge label hundreds of times).
_WARNED_UNCLASSIFIED: set[str] = set()


def classify_edge_kind(relation: str | None) -> EdgeKind:
    """Return the canonical :class:`EdgeKind` for one edge ``relation``.

    Lookup is case-insensitive — collectors and the BloodHound CE sync layer
    emit the same logical edge with different casings (``WriteDACL`` vs
    ``WriteDacl``), and the catalog accepts both transparently.

    Args:
        relation: The BloodHound (or ADscan synthetic) edge label, e.g.
            ``"GenericAll"``, ``"CanPSRemote"``, ``"ADCSESC1"``,
            ``"LocalAdminPassReuse"``.

    Returns:
        The canonical kind. Returns :attr:`EdgeKind.UNKNOWN` and emits a
        verbose warning the first time an unclassified relation is seen —
        this is intentional drift detection, not a fallback for production
        data. Subsequent occurrences in the same process are silent.
    """
    canonical = (relation or "").strip()
    if not canonical:
        return EdgeKind.UNKNOWN

    lower = canonical.lower()
    kind = _KIND_BY_LOWER.get(lower)
    if kind is not None:
        return kind
    if lower.startswith(_ADCS_ESC_PREFIX_LOWER):
        return EdgeKind.CONTROL

    if lower not in _WARNED_UNCLASSIFIED:
        _WARNED_UNCLASSIFIED.add(lower)
        print_warning(
            f"[edge_kind] Unclassified edge relation '{canonical}' — "
            "add it to adscan_internal/services/edge_kind.py"
        )
    return EdgeKind.UNKNOWN


def is_terminal_kind(kind: EdgeKind) -> bool:
    """Return True when ``kind`` can terminate a domain-compromise path.

    Membership, trust and unknown edges never terminate a compromise path
    on their own. Auth edges terminate at a *foothold*, not full
    compromise — callers needing to distinguish must inspect the target
    tier directly.
    """
    return kind in {EdgeKind.CONTROL, EdgeKind.DERIVED, EdgeKind.ESCALATION}
