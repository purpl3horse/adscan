"""Domain CLI helpers (workspace sub-scope).

This module hosts interactive domain management logic used by the legacy CLI.
It intentionally depends on dependency injection (the shell object) to avoid
import cycles into `adscan.py`.
"""

from __future__ import annotations

from collections.abc import Sequence
import os
import sys
import time
import subprocess
from typing import Any, Protocol

import curses
from rich.prompt import IntPrompt

from adscan_internal import telemetry
from adscan_internal.rich_output import (
    mark_sensitive,
    print_error,
    print_info,
    print_info_debug,
    print_info_verbose,
    print_success,
    print_warning,
)
from adscan_internal.cli.ci_events import emit_phase
from adscan_internal.cli.dns import (
    confirm_domain_pdc_mapping,
    finalize_domain_context,
    prompt_pdc_ip_interactive,
)
from adscan_internal.cli.nmap import probe_host_reachability_with_nmap
from adscan_internal.services.domain_connectivity_service import (
    merge_domain_connectivity,
)


class DomainShell(Protocol):
    """Protocol for domain management methods on the legacy shell."""

    current_workspace: str | None
    current_workspace_dir: str | None
    current_domain: str | None
    current_domain_dir: str | None
    domains_dir: str
    domain_path: str | None
    domains: list[str]
    domains_data: dict[str, dict[str, Any]]
    cracking_dir: str
    ldap_dir: str
    enum_trusts_path: str | None
    netexec_path: str | None
    domain_connectivity: dict[str, dict[str, Any]]

    def save_domain_data(self) -> None: ...

    def load_workspace_data(self, workspace_path: str) -> None: ...

    def workspace_save(self) -> None: ...

    def select_domain_curses(self, stdscr: Any, domains: Sequence[str]) -> None: ...

    def run_command(
        self, command: str, timeout: int | None = None
    ) -> subprocess.CompletedProcess: ...

    def create_sub_workspace_for_domain(
        self, domain: str, pdc_ip: str | None = None
    ) -> None: ...

    def do_enum_domain_auth_phase1(self, domain: str) -> None: ...

    def ask_for_enum_domain_auth(self, domain: str) -> None: ...
    def save_workspace_data(self) -> bool: ...

    def _run_netexec(
        self,
        command: str,
        *,
        domain: str | None = None,
        timeout: int | None = None,
        pre_sync: bool = True,
        **kwargs: Any,
    ) -> subprocess.CompletedProcess[str] | None: ...

    def _get_dns_discovery_service(self) -> Any: ...


def domain_save(shell: DomainShell) -> None:
    """Save the current domain data."""
    if not shell.current_domain:
        print_error("No domain selected.")
        return
    shell.save_domain_data()
    print_success(f"Domain data for '{shell.current_domain}' saved.")


def domain_create(shell: DomainShell, domain_name: str) -> None:
    """Create a new domain directory under the current workspace."""
    from adscan_internal.workspaces import create_domain_dir, resolve_domain_paths

    domain_path = resolve_domain_paths(
        shell.current_workspace_dir,
        shell.domains_dir,
        domain_name,
    ).domain_dir
    if os.path.exists(domain_path):
        marked_domain_name = mark_sensitive(domain_name, "domain")
        print_error(f"Domain '{marked_domain_name}' already exists.")
        return
    create_domain_dir(shell.current_workspace_dir, shell.domains_dir, domain_name)
    marked_domain_name = mark_sensitive(domain_name, "domain")
    print_success(f"Domain '{marked_domain_name}' created in '{shell.domains_dir}'.")


def domain_delete(shell: DomainShell, domain_name: str) -> None:
    """Delete an existing domain directory."""
    from adscan_internal.workspaces import (
        delete_domain_dir,
        resolve_domain_paths,
        resolve_domains_root,
    )

    shell.domain_path = resolve_domains_root(
        shell.current_workspace_dir, shell.domains_dir
    )
    domain_path = resolve_domain_paths(
        shell.current_workspace_dir,
        shell.domains_dir,
        domain_name,
    ).domain_dir
    if not os.path.exists(domain_path):
        marked_domain_name = mark_sensitive(domain_name, "domain")
        print_error(f"Domain '{marked_domain_name}' does not exist.")
        return
    delete_domain_dir(shell.current_workspace_dir, shell.domains_dir, domain_name)
    marked_domain_name = mark_sensitive(domain_name, "domain")
    print_success(f"Domain '{marked_domain_name}' deleted.")


def domain_select(shell: DomainShell) -> None:
    """Select a domain under the current workspace."""
    from adscan_internal.workspaces import activate_domain, list_domains

    shell.domain_path = os.path.join(
        shell.current_workspace_dir or "", shell.domains_dir
    )
    domains = list_domains(shell.current_workspace_dir, shell.domains_dir)
    if not domains:
        print_error("No domains available.")
        return

    if shell.current_domain:
        domain_save(shell)

    if shell.current_workspace:
        shell.workspace_save()

    if len(domains) == 1:
        activate_domain(
            shell,
            workspace_dir=shell.current_workspace_dir,
            domains_dir_name=shell.domains_dir,
            domain=domains[0],
        )
        shell.load_workspace_data(shell.current_domain_dir or "")
        print_success(f"Domain '{shell.current_domain}' selected automatically.\n")
        return

    try:
        if (
            sys.stdin.isatty()
            and sys.stdout.isatty()
            and os.environ.get("TERM", "") not in ("", "dumb", "unknown")
        ):
            curses.wrapper(shell.select_domain_curses, domains)
            return
    except Exception as exc:  # noqa: BLE001
        try:
            telemetry.capture_exception(exc)
        except Exception:
            pass

    print_info("Select a domain:")
    for i, domain in enumerate(domains, 1):
        print_info(f"  {i}. {domain}", spacing="none")

    try:
        idx = IntPrompt.ask("Enter a number (0 to cancel)", default=1)
    except Exception:
        return
    if idx == 0:
        return
    if 1 <= idx <= len(domains):
        activate_domain(
            shell,
            workspace_dir=shell.current_workspace_dir,
            domains_dir_name=shell.domains_dir,
            domain=domains[idx - 1],
        )
        shell.load_workspace_data(shell.current_domain_dir or "")
        print_success(f"Domain '{shell.current_domain}' selected.")


def domain_show(shell: DomainShell) -> None:
    """List available domains."""
    from adscan_internal.workspaces import list_domains

    shell.domain_path = os.path.join(
        shell.current_workspace_dir or "", shell.domains_dir
    )
    domains = list_domains(shell.current_workspace_dir, shell.domains_dir)
    if not domains:
        print_error("No domains available.")
        return
    print_info("[bold]Available domains:[/bold]")
    for domain in domains:
        marked_domain = mark_sensitive(domain, "domain")
        print_info(f"  • {marked_domain}")


def run_enum_trusts(shell: DomainShell, domain: str) -> None:
    """Enumerate trusts for a domain and update workspace/domain metadata.

    This is a CLI orchestration helper extracted from the legacy shell to keep
    `adscan.py` slimmer. It expects PRO checks to have been done by the caller.
    """
    if (
        domain not in shell.domains_data
        or "pdc" not in shell.domains_data[domain]
        or not shell.domains_data[domain]["pdc"]
    ):
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Could not find the PDC for the domain {marked_domain}. Skipping trust enumeration."
        )
        return

    # Initialised at function scope so the outer finally can close the span
    # safely no matter where execution leaves the function.
    _trust_phase_cm = None
    try:
        from adscan_internal import get_console, print_operation_header
        from adscan_internal.cli.widgets.trust_enum_live import (
            TrustEnumLiveView,
            render_trust_summary_panel,
        )
        from adscan_internal.cli.widgets.intelligence_update import (
            render_intelligence_update,
        )
        from adscan_internal.services.domain_posture import get_posture
        from adscan_internal.services.domain_service import DomainService
        from adscan_internal.services.posture_sink import (
            make_workspace_posture_sink,
        )

        username = shell.domains_data[domain]["username"]
        password = shell.domains_data[domain]["password"]
        pdc = shell.domains_data[domain]["pdc"]
        domain_state = shell.domains_data.get(domain, {}) or {}
        auth_domain = str(domain_state.get("auth_domain") or domain)
        auth_kdc = str(domain_state.get("auth_kdc") or pdc)

        emit_phase("trust_enumeration")
        # Surface this as a top-level chapter so it shares the numbered
        # phase strip with Domain Collection and the analysis pipeline.
        # The timeline span is opened here and closed in the function-level
        # finally so the row is written even on the error path.
        try:
            from adscan_internal.services.scan_phases import emit_chapter
            from adscan_internal.services.scan_timeline import phase_span

            scan_type = getattr(shell, "type", "default")
            emit_chapter("topology_and_trusts", scan_type=scan_type)
            _trust_phase_cm = phase_span(
                shell,
                domain,
                phase_id="topology_and_trusts",
                phase_title="Topology & Trusts",
            )
            _trust_phase_cm.__enter__()
        except Exception:  # noqa: BLE001 — chapter/timeline must never block the scan
            _trust_phase_cm = None

        print_operation_header(
            "Trust Enumeration",
            details={
                "Domain": domain,
                "PDC": pdc,
                "Username": username,
                "Auth": "Kerberos (LDAPS w/ fallback)",
            },
            icon="🔗",
        )
        print_info_debug(
            "Native badldap recursive trust enumeration · BFS · timeout=60s/domain"
        )

        dns_service = None
        try:
            dns_service = shell._get_dns_discovery_service()
        except Exception:
            dns_service = None

        partner_hostname_cache: dict[str, str] = {}

        def _resolve_pdc_ip(trusted_domain: str, resolver_ip: str) -> str | None:
            if not dns_service or not hasattr(dns_service, "find_pdc_with_selection"):
                return None
            selected_ip, hostname = dns_service.find_pdc_with_selection(
                domain=trusted_domain,
                resolver_ip=resolver_ip,
                preferred_ips=[resolver_ip],
                reference_ip=resolver_ip,
            )
            if hostname:
                fqdn = (
                    hostname
                    if "." in hostname
                    else f"{hostname}.{trusted_domain.strip().lower()}"
                )
                partner_hostname_cache[trusted_domain.strip().lower()] = fqdn
            return selected_ip

        def _resolve_dc_hostname(trusted_domain: str, _resolver_ip: str) -> str | None:
            return partner_hostname_cache.get(trusted_domain.strip().lower())

        def _check_trusted_domain_reachability(
            trusted_domain: str,
            trusted_pdc_ip: str,
            source_domain: str,
        ) -> dict[str, Any]:
            probe_result = probe_host_reachability_with_nmap(
                shell,
                host=trusted_pdc_ip,
                ports=[88, 389, 53],
                timeout_seconds=20,
                report_label=f"trusted_dc_{trusted_domain.replace('.', '_')}",
            )
            probe_result["domain"] = trusted_domain
            probe_result["source_domain"] = source_domain
            probe_result["pdc_ip"] = trusted_pdc_ip
            return probe_result

        posture_sink = make_workspace_posture_sink(
            shell.domains_data,
            on_finding=lambda finding: get_console().print(
                render_intelligence_update(finding)
            ),
        )
        posture_snapshot = get_posture(shell.domains_data, domain=domain)

        service = DomainService()
        with TrustEnumLiveView(
            source_domain=domain,
            source_pdc=pdc,
            username=username,
        ) as live_view:
            result = service.enumerate_trusts(
                domain=domain,
                pdc=pdc,
                username=username,
                password=password,
                auth_domain=auth_domain,
                auth_kdc=auth_kdc,
                use_kerberos=True,
                dc_hostname=(
                    shell.domains_data.get(domain, {}).get("dc_fqdn")
                    or shell.domains_data.get(domain, {}).get("pdc_hostname")
                ),
                resolve_pdc_ip=_resolve_pdc_ip,
                resolve_dc_hostname=_resolve_dc_hostname,
                check_domain_reachability=_check_trusted_domain_reachability,
                progress_cb=live_view.on_event,
                posture_sink=posture_sink,
                posture_snapshot=posture_snapshot,
            )

        # Premium summary card.
        get_console().print(render_trust_summary_panel(result, source_domain=domain))

        merge_domain_connectivity(
            shell,
            source_domain=domain,
            connectivity_updates=result.domain_connectivity,
        )
        if result.domain_connectivity and hasattr(shell, "save_workspace_data"):
            try:
                shell.save_workspace_data()
            except Exception as exc:  # noqa: BLE001
                telemetry.capture_exception(exc)
                print_warning(
                    "Failed to persist trusted-domain reachability state to the workspace."
                )

        _handle_trust_enumeration_result(
            shell,
            domain=domain,
            trusts=result.trusts,
            discovered_domains=result.discovered_domains,
            domain_pdc_mapping=result.domain_controllers,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        from adscan_internal import print_error_context

        print_error_context(
            "Trust enumeration failed",
            context={
                "Domain": domain,
                "PDC": shell.domains_data[domain].get("pdc", "N/A"),
            },
            suggestions=[
                "Verify domain credentials are correct",
                "Check network connectivity to PDC",
                "Confirm LDAP (389) or LDAPS (636) is reachable on the PDC",
            ],
            show_exception=True,
            exception=exc,
        )
    finally:
        # Always close the timeline span so the row + delta footer are
        # emitted even when the trust enumeration failed.
        try:
            if _trust_phase_cm is not None:
                _trust_phase_cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass


def order_domains_for_scan(source_domain: str, domains: list[str]) -> list[str]:
    """Order domains for scanning: source first, then closest relations."""
    source_norm = source_domain.lower().strip()
    normalized_to_original: dict[str, str] = {}
    seen: set[str] = set()
    ordered_norm: list[str] = []

    for item in domains:
        item_norm = item.lower().strip()
        if not item_norm or item_norm in seen:
            continue
        seen.add(item_norm)
        normalized_to_original.setdefault(item_norm, item.strip())
        ordered_norm.append(item_norm)

    if source_norm:
        normalized_to_original.setdefault(source_norm, source_domain.strip())
        if source_norm in ordered_norm:
            ordered_norm = [source_norm] + [d for d in ordered_norm if d != source_norm]
        else:
            ordered_norm.insert(0, source_norm)

    parent_chain: list[str] = []
    source_parts = source_norm.split(".") if source_norm else []
    if len(source_parts) > 2:
        for idx in range(1, len(source_parts)):
            parent = ".".join(source_parts[idx:])
            if parent and parent not in parent_chain:
                parent_chain.append(parent)

    start_root = ".".join(source_parts[-2:]) if len(source_parts) >= 2 else ""

    def _group_key(dom: str) -> tuple[int, int | str]:
        if dom == source_norm:
            return (0, 0)
        if dom in parent_chain:
            return (1, parent_chain.index(dom))
        if start_root and dom.endswith(start_root):
            return (2, dom)
        parts = dom.split(".")
        root_rank = 0 if len(parts) == 2 else 1
        return (3, f"{root_rank}:{dom}")

    ordered_norm = sorted(ordered_norm, key=lambda d: _group_key(d))
    return [normalized_to_original.get(dom, dom) for dom in ordered_norm]


def _prompt_scope_selection(
    candidates: list[str],
    source_domain: str,
    phase1_complete_domains: set[str] | None = None,
) -> list[str]:
    """Ask the user which trusted domains to include in scope.

    Domains with Phase 1 already completed are shown with a re-run label so the
    operator understands only the attack graph is rebuilt, not the full BH collection.
    In non-interactive environments the full list is returned unchanged.

    Args:
        candidates: All reachable domains to offer (including source).
        source_domain: The domain trust enumeration was launched from.
        phase1_complete_domains: Domains whose BH collection is already done.

    Returns:
        Subset of candidates selected by the user, preserving original order.
    """
    done = phase1_complete_domains or set()
    new_domains = [d for d in candidates if d not in done]
    rerun_domains = [d for d in candidates if d in done]

    # Nothing to offer if every candidate is already fully enumerated
    # and there are no new domains at all.
    if not new_domains and not rerun_domains:
        return candidates

    from adscan_internal.interaction import is_non_interactive as _is_non_interactive
    if _is_non_interactive():
        return candidates

    try:
        from adscan_core import prompting
        from adscan_internal import get_console

        console = get_console()

        # Context panel — tactical intel aesthetic: dark background, sharp borders
        has_rerun = bool(rerun_domains)
        has_new = bool(new_domains)

        legend_lines: list[str] = []
        if has_new:
            legend_lines.append(
                "  [bold green]★[/bold green]  [dim]Full enumeration[/dim]   "
                "[dim]→ BH collection · attack graph · attack paths[/dim]"
            )
        if has_rerun:
            legend_lines.append(
                "  [bold yellow]↺[/bold yellow]  [dim]Attack paths only[/dim]  "
                "[dim]→ skip BH collection · rebuild graph with cross-domain context[/dim]"
            )

        from rich.panel import Panel
        from rich.padding import Padding

        panel_body = "\n".join(legend_lines)
        console.print(
            Panel(
                Padding(panel_body, (1, 2)),
                title="[bold]Trust Scope Selection[/bold]",
                border_style="dim cyan",
                expand=False,
            )
        )

        options: list[str] = []
        labels_by_value: dict[str, str] = {}
        for d in candidates:
            if d in done:
                label = f"↺  {d}   [already enumerated — rebuild attack graph only]"
            else:
                label = f"★  {d}   [full enumeration]"
            labels_by_value[d] = label
            options.append(d)

        selected = prompting.questionary_checkbox_values_raw(
            title="Select domains to include in scope:",
            options=options,
            default_values=options,
            labels_by_value=labels_by_value,
        )

        if selected is None:
            # Ctrl-C / cancelled — fall back to full list to avoid silent data loss
            return candidates

        return [d for d in candidates if d in set(selected)]
    except Exception:
        return candidates


def _persist_scope_selection(
    shell: DomainShell,
    *,
    source_domain: str,
    candidates: list[str],
    selected_domains: list[str],
    domain_pdc_mapping: dict[str, str],
) -> None:
    """Persist selected trusted-domain scope to the workspace scope.json."""
    try:
        from adscan_internal.services.collector.scope import (
            ScopeEntry,
            ScopeResult,
            save_scope,
        )

        workspace_cwd = (
            getattr(shell, "current_workspace_dir", None)
            or getattr(shell, "current_workspace", None)
            or os.getcwd()
        )
        selected = {item.lower().strip() for item in selected_domains}
        source_data = shell.domains_data.get(source_domain, {})
        auth_domain = str(source_data.get("auth_domain") or source_domain)
        auth_kdc = str(source_data.get("auth_kdc") or source_data.get("pdc") or "")
        entries: list[ScopeEntry] = []
        for candidate in candidates:
            candidate_data = shell.domains_data.get(candidate, {})
            connectivity = candidate_data.get("connectivity", {})
            summary = (
                connectivity.get("summary", {})
                if isinstance(connectivity, dict)
                and isinstance(connectivity.get("summary", {}), dict)
                else {}
            )
            reachability = "reachable_ldap"
            degraded_reason = None
            if isinstance(summary, dict) and summary.get("reachable") is False:
                reachability = "unreachable"
                degraded_reason = str(summary.get("reason") or "") or None
            entries.append(
                ScopeEntry(
                    domain=candidate,
                    dc_address=str(
                        candidate_data.get("pdc")
                        or domain_pdc_mapping.get(candidate)
                        or ""
                    ),
                    auth_domain=auth_domain,
                    auth_kdc=auth_kdc,
                    reachability=reachability,
                    in_scope=candidate.lower().strip() in selected,
                    kerberos_target_hostname=str(
                        candidate_data.get("pdc_hostname") or ""
                    )
                    or None,
                    degraded_reason=degraded_reason,
                )
            )

        scope_path = os.path.join(workspace_cwd, "scope.json")
        save_scope(ScopeResult(entries=entries), scope_path)
        print_info_debug(
            f"[scope] Persisted trust scope to {mark_sensitive(scope_path, 'path')}"
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_info_debug(f"[scope] Failed to persist scope.json: {exc}")


def _handle_trust_enumeration_result(
    shell: DomainShell,
    *,
    domain: str,
    trusts: list[Any],
    discovered_domains: list[str],
    domain_pdc_mapping: dict[str, str],
) -> None:
    """Process recursive trust enumeration results and update domain state."""
    try:

        def _domain_reachable_from_current_vantage(candidate_domain: str) -> bool:
            """Return whether one trusted domain is currently reachable."""
            if candidate_domain == domain:
                return True
            domain_state = (
                shell.domains_data.get(candidate_domain, {})
                if isinstance(getattr(shell, "domains_data", {}), dict)
                else {}
            )
            if not isinstance(domain_state, dict):
                return True
            connectivity = domain_state.get("connectivity", {})
            if not isinstance(connectivity, dict):
                return True
            summary = connectivity.get("summary", {})
            if not isinstance(summary, dict):
                return True
            if "reachable" not in summary:
                return True
            return bool(summary.get("reachable"))

        invalid_domains: set[str] = set()
        dns_service = None
        try:
            dns_service = shell._get_dns_discovery_service()
        except Exception:
            dns_service = None

        ordered_domains: list[str] = []
        seen_domains: set[str] = set()

        for main_domain in discovered_domains:
            if main_domain in invalid_domains or main_domain in seen_domains:
                continue
            seen_domains.add(main_domain)
            ordered_domains.append(main_domain)
            if main_domain not in shell.domains_data:
                shell.domains_data[main_domain] = {}
            is_reachable = _domain_reachable_from_current_vantage(main_domain)
            if is_reachable:
                shell.domains_data[main_domain]["auth"] = "auth"
                print_warning(f"Valid domain found: {main_domain}")
            else:
                marked_domain = mark_sensitive(main_domain, "domain")
                marked_pdc = mark_sensitive(
                    str(
                        shell.domains_data.get(main_domain, {})
                        .get("connectivity", {})
                        .get("summary", {})
                        .get("pdc_ip")
                        or domain_pdc_mapping.get(main_domain)
                        or ""
                    ),
                    "ip",
                )
                print_warning(
                    f"Trusted domain discovered but not currently reachable: {marked_domain}"
                    + (f" (PDC/DC {marked_pdc})" if str(marked_pdc).strip() else "")
                )
                continue
            pdc_ip = domain_pdc_mapping.get(main_domain)
            if (
                not pdc_ip
                and dns_service
                and hasattr(dns_service, "resolve_ipv4_addresses_robust")
            ):
                a_candidates = dns_service.resolve_ipv4_addresses_robust(main_domain)
                if len(a_candidates) == 1:
                    pdc_ip = a_candidates[0]
                    domain_pdc_mapping[main_domain] = pdc_ip
                    marked_domain = mark_sensitive(main_domain, "domain")
                    marked_ip = mark_sensitive(pdc_ip, "ip")
                    print_info_verbose(
                        f"Using A-record fallback for {marked_domain}: {marked_ip}"
                    )
                elif a_candidates:
                    marked_domain = mark_sensitive(main_domain, "domain")
                    marked_candidates = mark_sensitive(a_candidates, "ip")
                    print_info_verbose(
                        f"Multiple A-record candidates for {marked_domain}: {marked_candidates}"
                    )
            if pdc_ip:
                confirmed = confirm_domain_pdc_mapping(
                    shell,
                    domain=main_domain,
                    candidate_ip=pdc_ip,
                    interactive=bool(sys.stdin.isatty()),
                    mode_label="trust_enum",
                    on_reenter=lambda: (
                        main_domain,
                        prompt_pdc_ip_interactive(domain=main_domain),
                    ),
                )
                if confirmed:
                    main_domain, pdc_ip = confirmed
                else:
                    pdc_ip = None
                    print_warning(
                        "No confirmed DC/PDC for "
                        f"{mark_sensitive(main_domain, 'domain')}; continuing without a PDC."
                    )

            if pdc_ip:
                shell.domains_data.setdefault(main_domain, {})["pdc"] = pdc_ip
            if not os.path.exists(os.path.join("domains", main_domain)):
                shell.domains.append(main_domain)
                shell.domains = list(set(shell.domains))

                if pdc_ip:
                    marked_pdc_ip = mark_sensitive(pdc_ip, "ip")
                    print_info(
                        f"Creating workspace for {main_domain} with PDC IP: {marked_pdc_ip}"
                    )
                    shell.create_sub_workspace_for_domain(main_domain, pdc_ip)
                else:
                    print_info(f"Creating workspace for {main_domain} without PDC IP")
                    shell.create_sub_workspace_for_domain(main_domain)

                time.sleep(1)
                domain_path = os.path.join(shell.domains_dir, main_domain)
                cracking_path = os.path.join(domain_path, shell.cracking_dir)
                ldap_path = os.path.join(domain_path, shell.ldap_dir)

                for directory in [cracking_path, ldap_path]:
                    if not os.path.exists(directory):
                        os.makedirs(directory)

            if pdc_ip:
                finalize_domain_context(
                    shell,
                    domain=main_domain,
                    pdc_ip=pdc_ip,
                    interactive=False,
                )

        from adscan_internal import (
            create_domains_table,
            get_console,
            print_results_summary,
        )

        ordered_domains = order_domains_for_scan(domain, ordered_domains)

        discovered_domains_data: dict[str, dict[str, Any]] = {}
        for main_domain in ordered_domains:
            domain_state = (
                shell.domains_data.get(main_domain, {})
                if isinstance(getattr(shell, "domains_data", {}), dict)
                else {}
            )
            connectivity_summary = (
                domain_state.get("connectivity", {}).get("summary", {})
                if isinstance(domain_state, dict)
                and isinstance(domain_state.get("connectivity", {}), dict)
                else {}
            )
            discovered_domains_data[main_domain] = {
                "pdc": domain_pdc_mapping.get(main_domain, "N/A"),
                "auth": "auth",
                "reachable": (
                    bool(connectivity_summary.get("reachable"))
                    if isinstance(connectivity_summary, dict)
                    and "reachable" in connectivity_summary
                    else main_domain == domain
                ),
            }

        if trusts:
            # Legacy verbose-only summary; the new summary panel is rendered
            # in run_enum_trusts() before this handler. Keep as a debug aid.
            if getattr(shell, "verbose", False):
                print_results_summary(
                    "Trust Enumeration Results",
                    {
                        "Source Domain": domain,
                        "Trusted Domains Found": max(len(ordered_domains) - 1, 0),
                        "Trust Relationships Found": len(trusts),
                        "Status": "Completed Successfully",
                    },
                )
                if discovered_domains_data:
                    console = get_console()
                    table = create_domains_table(
                        discovered_domains_data,
                        title="Discovered Trust Relationships",
                    )
                    console.print(table)
            for trusted_domain, connectivity in sorted(
                (
                    (name, data)
                    for name, data in domain_pdc_mapping.items()
                    if name != domain
                ),
                key=lambda item: item[0].lower(),
            ):
                stored_connectivity = (
                    shell.domains_data.get(trusted_domain, {}).get("connectivity", {})
                    if isinstance(shell.domains_data.get(trusted_domain, {}), dict)
                    else {}
                )
                if not isinstance(stored_connectivity, dict) or not stored_connectivity:
                    continue
                summary = stored_connectivity.get("summary", {})
                if isinstance(summary, dict) and summary.get("reachable"):
                    continue
                marked_domain = mark_sensitive(trusted_domain, "domain")
                marked_pdc = mark_sensitive(
                    str(
                        (
                            summary.get("pdc_ip")
                            if isinstance(summary, dict)
                            else stored_connectivity.get("pdc_ip")
                        )
                        or connectivity
                    ),
                    "ip",
                )
                print_warning(
                    f"Skipping recursive trust enumeration for {marked_domain}: "
                    f"PDC/DC {marked_pdc} is not reachable from the current vantage."
                )

            # All reachable domains — including those with Phase 1 already done.
            # Domains with Phase 1 complete are still included because they need
            # their attack graph rebuilt with the new cross-domain context.
            all_reachable = [
                main_domain
                for main_domain in ordered_domains
                if _domain_reachable_from_current_vantage(main_domain)
            ]

            # Track which domains already have BH data collected.
            phase1_complete_set: set[str] = {
                d
                for d in all_reachable
                if bool(shell.domains_data.get(d, {}).get("phase1_complete"))
            }

            # Exclude domains fully enumerated with no new cross-domain peers.
            # If every reachable domain already ran Phase 1 AND there are no new
            # domains to add context, there is nothing to do.
            new_domains = [d for d in all_reachable if d not in phase1_complete_set]
            if all_reachable == [domain] and any(
                candidate != domain for candidate in ordered_domains
            ):
                print_info(
                    "Trust analysis found no reachable trusted domains from the current vantage."
                )
                shell.domains_data.setdefault(domain, {})["auth"] = "auth"
                shell.ask_for_enum_domain_auth(domain)
                return
            if not all_reachable or (not new_domains and len(all_reachable) <= 1):
                print_info(
                    "Trust analysis completed, but all reachable trusted domains "
                    "were already fully enumerated."
                )
                return

            selected_domains = _prompt_scope_selection(
                all_reachable,
                source_domain=domain,
                phase1_complete_domains=phase1_complete_set,
            )
            _persist_scope_selection(
                shell,
                source_domain=domain,
                candidates=all_reachable,
                selected_domains=selected_domains,
                domain_pdc_mapping=domain_pdc_mapping,
            )

            if not selected_domains:
                print_info("No trusted domains selected for enumeration.")
                return

            # Separate domains by what work they need.
            phase1_needed = [
                d for d in selected_domains if d not in phase1_complete_set
            ]
            phase2_all = selected_domains  # every selected domain needs graph rebuilt

            from adscan_internal.cli.intelligence import (
                run_attack_path_discovery,
                run_cross_domain_attack_path_discovery,
            )

            # Phase 1: native collection only for domains that haven't been collected yet.
            for main_domain in phase1_needed:
                shell.do_enum_domain_auth_phase1(main_domain)

            if len(phase2_all) > 1:
                # Phase 2 build-only for all: populate every attack_graph.json
                # before computing paths so multi-hop cross-domain edges are present.
                for main_domain in phase2_all:
                    run_attack_path_discovery(shell, main_domain, build_only=True)
                # Single merged cross-domain path display.
                run_cross_domain_attack_path_discovery(shell, phase2_all)
            else:
                # Single domain — build + display in one pass (no merge needed).
                run_attack_path_discovery(shell, phase2_all[0])

            # Phase 3+: only for new domains (credential spraying, share scan, etc.)
            # Already-enumerated domains completed these phases before the pivot.
            for main_domain in phase1_needed:
                shell.run_enumeration(main_domain, start_from_phase=3)
        else:
            print_info("No trust relationships found.")
            shell.domains_data[domain]["auth"] = "auth"
            shell.ask_for_enum_domain_auth(domain)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error(
            "An unexpected error occurred while processing trust enumeration output."
        )
        from adscan_internal.rich_output import print_exception

        print_exception(show_locals=False, exception=exc)
