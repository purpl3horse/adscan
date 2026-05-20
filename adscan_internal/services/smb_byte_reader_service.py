"""Read SMB remote files in-memory with aiosmb for AI analysis flows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from adscan_internal.services.base_service import BaseService
from adscan_internal.services.smb_guest_auth_service import (
    is_guest_alias,
    resolve_smb_guest_username,
)
from adscan_internal.services.smb_transport import (
    SMBConfig,
    SMBTransportError,
    _looks_like_nt_hash,
    run_smb_operation,
    smb_machine_for,
)


@dataclass(frozen=True)
class SMBByteReadResult:
    """Result of reading one remote SMB file as bytes."""

    success: bool
    data: bytes
    truncated: bool
    error_message: str | None = None
    auth_username: str = ""
    auth_domain: str = ""
    auth_mode: str = ""
    resolved_domain_key: str = ""
    normalized_path: str = ""
    status_code: str | None = None
    source_path: str = ""


class SMBByteReaderService(BaseService):
    """Read remote SMB files directly into memory without local download."""

    backend: str = "smb_aiosmb"

    @staticmethod
    def _resolve_domain_entry(
        *,
        domains_data: dict[str, Any],
        requested_domain: str,
        active_domain: str,
    ) -> tuple[str, dict[str, Any]]:
        """Resolve domain entry using exact then case-insensitive key matching."""
        candidates: list[str] = []
        for candidate in (requested_domain, active_domain):
            value = str(candidate or "").strip()
            if value and value not in candidates:
                candidates.append(value)

        for candidate in candidates:
            entry = domains_data.get(candidate)
            if isinstance(entry, dict):
                return candidate, entry

        lowered_map: dict[str, str] = {}
        for key in domains_data.keys():
            key_text = str(key).strip()
            if key_text:
                lowered_map.setdefault(key_text.lower(), key_text)

        for candidate in candidates:
            match_key = lowered_map.get(candidate.lower())
            if not match_key:
                continue
            entry = domains_data.get(match_key)
            if isinstance(entry, dict):
                return match_key, entry

        return "", {}

    @staticmethod
    def _extract_status_code(error_text: str) -> str | None:
        """Extract a Windows NTSTATUS code from an error string when present."""
        if not error_text:
            return None
        match = re.search(r"0x[0-9a-fA-F]{8}", error_text)
        if match:
            return match.group(0).lower()
        return None

    def read_file_bytes(
        self,
        *,
        shell: Any,
        domain: str,
        host: str,
        share: str,
        source_path: str | None = None,
        remote_path: str | None = None,
        max_bytes: int = 262144,
        timeout_seconds: int = 30,
        auth_username: str | None = None,
        auth_password: str | None = None,
        auth_domain: str | None = None,
    ) -> SMBByteReadResult:
        """Read one remote SMB file by byte stream through aiosmb."""
        effective_source_path = str(source_path or remote_path or "").strip()
        if max_bytes <= 0:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="max_bytes must be positive.",
                source_path=effective_source_path,
            )

        domains_data = (
            shell.domains_data
            if hasattr(shell, "domains_data") and isinstance(shell.domains_data, dict)
            else {}
        )
        active_domain = str(getattr(shell, "domain", "") or "").strip()
        resolved_domain_key, domain_data = self._resolve_domain_entry(
            domains_data=domains_data,
            requested_domain=domain,
            active_domain=active_domain,
        )
        resolved_auth_domain = (
            str(auth_domain or "").strip()
            or resolved_domain_key
            or str(domain or "").strip()
            or active_domain
        )
        username = (
            str(auth_username).strip()
            if auth_username is not None
            else str(domain_data.get("username", "")).strip()
        )
        password = (
            str(auth_password).strip()
            if auth_password is not None
            else str(domain_data.get("password", "")).strip()
        )
        domain_auth_mode = str(domain_data.get("auth", "")).strip().lower()
        has_hash_detector = callable(getattr(shell, "is_hash", None))
        is_hash = bool(
            has_hash_detector and shell.is_hash(password)
        ) or _looks_like_nt_hash(password)
        is_guest_context = domain_auth_mode == "guest" or is_guest_alias(username)
        if is_hash:
            auth_mode = "hash"
        elif password:
            auth_mode = "password"
        elif username and is_guest_context:
            auth_mode = "guest"
        else:
            auth_mode = "missing"

        if auth_mode == "guest" and (not username or is_guest_alias(username)):
            username = resolve_smb_guest_username(shell=shell, domain=domain)

        self.logger.debug(
            (
                "SMB byte read auth context: requested_domain=%s active_domain=%s "
                "resolved_domain=%s username=%s auth_mode=%s has_password=%s host=%s share=%s path=%s max_bytes=%s "
                "override_user=%s override_domain=%s domain_auth_mode=%s"
            ),
            domain,
            active_domain,
            resolved_auth_domain,
            username,
            auth_mode,
            bool(password),
            host,
            share,
            effective_source_path,
            max_bytes,
            auth_username is not None,
            auth_domain is not None,
            domain_auth_mode or "-",
        )

        if auth_mode == "missing":
            if username:
                error_message = (
                    "Missing password for non-guest SMB byte read credentials "
                    f"(domain {domain}, user {username})."
                )
            else:
                error_message = (
                    f"Missing authenticated credentials for domain {domain}."
                )
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message=error_message,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        # Normalise path: forward-slash → backslash, no leading backslash.
        normalized_path = effective_source_path.replace("/", "\\").lstrip("\\")
        if not normalized_path:
            return SMBByteReadResult(
                success=False,
                data=b"",
                truncated=False,
                error_message="Remote path is empty.",
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                source_path=effective_source_path,
            )

        # Build aiosmb config — UNC path for the file is \\share\path
        unc_file_path = f"\\{share}\\{normalized_path}"

        config = SMBConfig(
            target_ip=host,
            target_hostname=host,
            domain=domain or resolved_domain_key or active_domain or None,
            username=username or None,
            password=password if auth_mode == "password" else None,
            nt_hash=password if auth_mode == "hash" else None,
            auth_domain=resolved_auth_domain or None,
            timeout=timeout_seconds,
        )

        chunks = bytearray()
        truncated = False

        async def _read_file() -> None:
            nonlocal truncated
            try:
                from aiosmb.commons.interfaces.file import SMBFile
            except ImportError as exc:
                raise SMBTransportError(f"aiosmb is not available: {exc}") from exc

            async with smb_machine_for(config) as machine:
                file_obj = SMBFile.from_remotepath(machine.connection, unc_file_path)
                # aiosmb ≤0.4.14 raises bare StopIteration inside async generators
                # at EOF; Python 3.7+ converts that to RuntimeError. Catch it here
                # so callers see a clean end-of-stream rather than a spurious error.
                try:
                    async for chunk, err in machine.get_file_data(file_obj):
                        if err is not None:
                            raise SMBTransportError(str(err))
                        if not chunk:
                            continue
                        remaining = max_bytes - len(chunks)
                        if remaining <= 0:
                            truncated = True
                            return
                        if len(chunk) > remaining:
                            chunks.extend(chunk[:remaining])
                            truncated = True
                            return
                        chunks.extend(chunk)
                except RuntimeError as exc:
                    if not (exc.__cause__ and isinstance(exc.__cause__, StopIteration)):
                        raise

        try:
            run_smb_operation(_read_file())
            return SMBByteReadResult(
                success=True,
                data=bytes(chunks),
                truncated=truncated,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                normalized_path=normalized_path,
                source_path=effective_source_path,
            )
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            status_code = self._extract_status_code(error_text)
            self.logger.exception(
                (
                    "SMB byte stream read failed for host=%s share=%s path=%s "
                    "auth_user=%s auth_domain=%s auth_mode=%s status=%s"
                ),
                host,
                share,
                normalized_path,
                username,
                resolved_auth_domain,
                auth_mode,
                status_code or "-",
            )
            return SMBByteReadResult(
                success=False,
                data=bytes(chunks),
                truncated=truncated,
                error_message=error_text,
                auth_username=username,
                auth_domain=resolved_auth_domain,
                auth_mode=auth_mode,
                resolved_domain_key=resolved_domain_key,
                normalized_path=normalized_path,
                status_code=status_code,
                source_path=effective_source_path,
            )


# ---------------------------------------------------------------------------
# Backward-compatibility alias — removed once all callers are updated
# ---------------------------------------------------------------------------

ImpacketSMBByteReaderService = SMBByteReaderService
