"""Flags CLI orchestration helpers.

Native-first CTF flag collection. Reads HTB / THM flag files
(``user.txt``, ``root.txt``, ``system.txt``) directly from the target
host's ``C$`` share via aiosmb byte-streaming. Falls back to the
:mod:`remote_exec` cascade only when SMB returns ACCESS_DENIED.

This module replaced the legacy NetExec ``cmd /c type`` flow. The
parser and helper for the legacy path are kept private and used only
by the cascade fallback inside
:mod:`adscan_internal.services.ctf_flag_collector`.
"""

from __future__ import annotations

from typing import Any
import asyncio
import os
import re

from adscan_internal import (
    print_error,
    print_info,
    print_warning,
    print_warning_verbose,
    telemetry,
)
from adscan_internal.cli.flags_panel import render_flags_captured_panel
from adscan_internal.cli.smb import run_get_flags
from adscan_internal.rich_output import confirm_operation, mark_sensitive
from adscan_internal.services.ctf_flag_collector import (
    FlagCollectionResult,
    collect_ctf_flags,
)
from adscan_internal.services.remote_exec import (
    build_smb_config_from_credential,
)
from adscan_internal.text_utils import strip_ansi_codes


def ask_for_flags(
    shell: Any,
    domain: str,
    username: str,
    password: str,
    *,
    secret_kind: str | None = None,
) -> None:
    """Ask the user whether to obtain flags from ``domain``.

    Args:
        shell: ADscan shell.
        domain: Target domain.
        username: Authenticating principal.
        password: Password, NT hash, AES key, or ccache path; interpreted
            according to ``secret_kind``.
        secret_kind: One of ``"password"`` / ``"nt_hash"`` / ``"aes256_key"``
            / ``"aes128_key"`` / ``"ccache_path"``. ``None`` falls back to
            the legacy auto-detect heuristic in :func:`execute_get_flags`.
    """
    if shell.auto:
        get_flags(shell, domain, username, password, secret_kind=secret_kind)
    else:
        domain_entry = (
            shell.domains_data.get(domain) if hasattr(shell, "domains_data") else None
        ) or {}
        pdc = domain_entry.get("pdc") or domain_entry.get("pdc_ip") or "N/A"
        cred_type = "Hash" if (hasattr(shell, "is_hash") and shell.is_hash(password)) else "Password"
        if confirm_operation(
            operation_name="CTF Flag Collection",
            description=(
                "Reads flag files (user.txt, root.txt, system.txt) from the target "
                "host via SMB byte-streaming; falls back to remote-exec on ACCESS_DENIED"
            ),
            context={
                "Domain": domain,
                "Host / PDC": pdc,
                "Username": username,
                "Credential": cred_type,
            },
            default=True,
            icon="★",
            show_panel=True,
        ):
            get_flags(shell, domain, username, password, secret_kind=secret_kind)


def get_flags(
    shell: Any,
    domain: str,
    username: str,
    password: str,
    *,
    secret_kind: str | None = None,
) -> None:
    """Obtain flags from ``domain`` using the configured credentials."""
    return run_get_flags(
        shell,
        domain=domain,
        username=username,
        password=password,
        secret_kind=secret_kind,
    )


def do_get_flags(shell: Any, args: str) -> None:
    """Shell handler: ``get_flags <domain> <username> <password>``."""
    args_list = args.split()
    if len(args_list) != 3:
        print_error("Usage: get_flags <domain> <username> <password>")
        return
    domain, username, password = args_list
    get_flags(shell, domain, username, password)


# ---------------------------------------------------------------------------
# Legacy parser, used only by the remote_exec fallback inside the
# collector when stdout-shaped data needs interpreting. Kept here so
# external callers that still rely on it keep working.
# ---------------------------------------------------------------------------


def _parse_flags_from_output(stdout: str) -> list[tuple[str, str, str]]:
    """Parse flags from a NetExec-style stdout transcript.

    Returns:
        List of ``(kind, path, flag)`` triples where ``kind`` is one of
        ``user`` / ``root`` / ``system`` / ``unknown``.
    """
    stdout = stdout or ""
    clean_stdout = strip_ansi_codes(stdout)
    lines = clean_stdout.splitlines()

    last_path: str | None = None
    results: list[tuple[str, str, str]] = []
    for line in lines:
        if '>type "' in line:
            try:
                start = line.index('>type "') + len('>type "')
                end = line.index('"', start)
                last_path = line[start:end]
            except Exception:
                last_path = None
            continue
        if last_path:
            m = re.search(r"\b[a-f0-9]{32}\b", line.lower())
            if m:
                low = last_path.lower()
                if low.endswith("user.txt"):
                    kind = "user"
                elif low.endswith("root.txt"):
                    kind = "root"
                elif low.endswith("system.txt"):
                    kind = "system"
                else:
                    kind = "unknown"
                results.append((kind, last_path, m.group(0)))
                last_path = None

    return results


# ---------------------------------------------------------------------------
# Workspace persistence
# ---------------------------------------------------------------------------


def _save_flags_to_files(
    shell: Any, results: list[tuple[str, str, str]], _domain: str
) -> None:
    """Persist flags to ``<workspace>/flags/{user,root,system}.txt``.

    Args:
        shell: ADscan shell.
        results: ``(kind, path, flag)`` triples.
        _domain: Unused; kept for legacy callers.
    """
    if not getattr(shell, "current_workspace_dir", None):
        return

    flags_dir = os.path.join(shell.current_workspace_dir, "flags")
    os.makedirs(flags_dir, exist_ok=True)

    user_flag = root_flag = system_flag = None
    for kind, _path, flag in results:
        if kind == "user" and user_flag is None:
            user_flag = flag
        elif kind == "root" and root_flag is None:
            root_flag = flag
        elif kind == "system" and system_flag is None:
            system_flag = flag

    def _persist(name: str, value: str | None, label: str) -> None:
        if value is None:
            return
        path = os.path.join(flags_dir, name)
        try:
            with open(path, "w", encoding="utf-8") as fp:
                fp.write(value)
            print_info(f"{label} saved to: {path}")
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            print_warning_verbose(f"Failed to save {label.lower()}: {exc}")

    _persist("user.txt", user_flag, "User flag")
    _persist("root.txt", root_flag, "Root flag")
    _persist("system.txt", system_flag, "System flag")

    # Compatibility: some flows look for root.txt as the "privileged"
    # marker. If only system.txt exists, mirror it.
    if system_flag and not root_flag:
        _persist("root.txt", system_flag, "Privileged flag")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def execute_get_flags(
    shell: Any,
    *,
    domain: str,
    host: str,
    username: str,
    password: str,
    secret_kind: str | None = None,
) -> None:
    """Collect flags via the native byte-read path and render the panel.

    Args:
        shell: ADscan shell.
        domain: Target domain.
        host: Target host (typically the PDC FQDN).
        username: Authenticating principal.
        password: Secret material, interpreted per ``secret_kind``.
        secret_kind: Optional explicit secret kind. When ``None`` the
            kind is inferred from the value (NT-hash form vs. plaintext)
            for backward compatibility with legacy callers.
    """
    if secret_kind is None:
        is_hash = bool(getattr(shell, "is_hash", lambda _v: False)(password))
        secret_kind = "nt_hash" if is_hash else "password"

    domain_entry = (
        shell.domains_data.get(domain) if hasattr(shell, "domains_data") else None
    ) or {}
    pdc_ip = domain_entry.get("pdc_ip") or domain_entry.get("pdc")
    kdc_ip = domain_entry.get("kdc_ip") or pdc_ip

    from adscan_internal import print_info_debug as _dbg
    _dbg(
        f"[ctf-flags] execute_get_flags: "
        f"user={mark_sensitive(username, 'user')} "
        f"secret_kind={secret_kind} "
        f"host={mark_sensitive(host, 'hostname')} "
        f"pdc_ip={mark_sensitive(str(pdc_ip or '-'), 'ip')} "
        f"kdc_ip={mark_sensitive(str(kdc_ip or '-'), 'ip')}"
    )

    # When the credential is an NT hash OR a cleartext password, the
    # Kerberos-first posture may reuse the ambient KRB5CCNAME (e.g.
    # support.ccache set during a prior LDAP query) instead of doing a fresh
    # AS-REQ for the privileged account, causing all SMB/exec probes to land
    # as the wrong user (ACCESS_DENIED on C$, wrong WinRM auth).
    # Pre-obtain TGT+CIFS TGS explicitly via kerbad and hand a ccache_path to
    # the config so there is no ambiguity regardless of the secret type.
    effective_secret = password
    effective_kind = secret_kind
    _smb_ccache_tmp: str | None = None
    if secret_kind in {"nt_hash", "password"} and kdc_ip:
        try:
            import tempfile as _tf
            from adscan_internal.services.kerberos_transport import (
                KerberosConfig as _KrbCfg,
                get_tgs as _get_tgs,
            )
            _spn = f"cifs/{host}"
            _krb = _KrbCfg(
                username=username,
                domain=domain,
                kdc_ip=kdc_ip,
                nt_hash=password if secret_kind == "nt_hash" else None,
                password=password if secret_kind == "password" else None,
            )
            try:
                _ccache_bytes = asyncio.run(_get_tgs(_krb, _spn))
            except RuntimeError:
                import concurrent.futures as _cf
                with _cf.ThreadPoolExecutor(max_workers=1) as _pool:
                    _ccache_bytes = _pool.submit(asyncio.run, _get_tgs(_krb, _spn)).result(timeout=30)
            _tmp = _tf.NamedTemporaryFile(suffix=".ccache", prefix="adscan_smb_tgt_", delete=False)
            _tmp.write(_ccache_bytes)
            _tmp.close()
            _smb_ccache_tmp = _tmp.name
            effective_secret = _smb_ccache_tmp
            effective_kind = "ccache"
            from adscan_internal import print_info_debug as _dbg2
            _dbg2(
                f"[ctf-flags] {secret_kind} → CIFS TGT+TGS obtained for "
                f"{mark_sensitive(username, 'user')}@{domain.upper()} spn={_spn}"
            )
        except Exception as _exc:
            from adscan_internal import print_info_debug as _dbg3
            _dbg3(
                f"[ctf-flags] CIFS TGT+TGS pre-fetch failed, using {secret_kind} directly: "
                f"{type(_exc).__name__}: {_exc}"
            )

    config = build_smb_config_from_credential(
        domain=domain,
        username=username,
        secret=effective_secret,
        secret_kind=effective_kind,
        target_host=host,
        target_ip=pdc_ip or host,
        kdc_ip=kdc_ip,
        prefer_kerberos=False,
    )

    try:
        result: FlagCollectionResult = asyncio.run(
            collect_ctf_flags(
                shell=shell,
                domain=domain,
                host=host,
                config=config,
            )
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_domain = mark_sensitive(domain, "domain")
        print_error(f"Error obtaining flags from domain {marked_domain}: {exc}")
        return
    finally:
        if _smb_ccache_tmp:
            try:
                import os as _os
                _os.unlink(_smb_ccache_tmp)
            except OSError:
                pass

    # Persist raw flag values to the workspace.
    triples = [(h.kind, h.path, h.value) for h in result.hits]
    _save_flags_to_files(shell, triples, domain)

    render_flags_captured_panel(
        console=getattr(shell, "console", None) or _fallback_console(),
        result=result,
        domain=domain,
        host=host,
    )

    if not result.hits and result.errors:
        print_warning(
            "No flags captured from host "
            + mark_sensitive(host, "hostname")
            + ". Run with --debug to see per-path diagnostics. "
            "Check SMB access, credential validity, or try a fallback exec method."
        )


def _fallback_console():
    """Return a default Rich console when ``shell.console`` is missing."""
    from rich.console import Console

    return Console()


__all__ = [
    "ask_for_flags",
    "get_flags",
    "do_get_flags",
    "execute_get_flags",
]
