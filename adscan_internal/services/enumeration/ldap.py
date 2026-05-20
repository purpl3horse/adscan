"""LDAP enumeration mixin.

This module provides LDAP-specific enumeration operations including
user enumeration, group enumeration, and computer enumeration.
"""

from collections.abc import Callable
from typing import List, Optional, Dict, Any
from dataclasses import dataclass, field
import asyncio
import subprocess
import logging

from adscan_internal.core import AuthMode, requires_auth
from adscan_internal.command_runner import CommandSpec, default_runner
from adscan_internal.subprocess_env import (
    command_string_needs_clean_env,
    get_clean_env_for_compilation,
)
from adscan_internal.execution_outcomes import (
    result_is_exact_ldap_connection_timeout,
)


logger = logging.getLogger(__name__)

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


def _native_anonymous_user_inventory(
    *,
    pdc: str,
    ldap_filter: str,
    timeout: int,
) -> list[dict[str, object]]:
    """Native anonymous LDAP user-object dump via badldap simple-bind.

    Mirrors the connection pattern used by
    :func:`adscan_internal.services.unauth_enrichment_service._enrich_ldap_active_users_native`
    so the unauth flow and any external callers go through the same
    ``ldap+simple://`` simple-bind code path. Returns a list of
    ``{"distinguished_name": str, "attributes": dict[str, list]}`` items.
    Empty list when the directory denies the search after a successful
    anonymous bind.
    """
    from adscan_internal import telemetry as _telemetry
    from badldap.commons.factory import LDAPConnectionFactory

    async def _run() -> list[dict[str, object]]:
        conn = None
        last_exc: Exception | None = None
        for transport, port in (("ldaps", 636), ("ldap", 389)):
            url = f"{transport}+simple://@{pdc}:{port}"
            try:
                factory = LDAPConnectionFactory.from_url(url)
                client = factory.get_client()
                if hasattr(client, "_disable_signing"):
                    client._disable_signing = True
                if hasattr(client, "_disable_channel_binding"):
                    client._disable_channel_binding = True
                ok, err = await asyncio.wait_for(client.connect(), timeout=timeout)
                if not ok:
                    raise err or RuntimeError(
                        f"{transport.upper()} connect returned ok=False"
                    )
                conn = client
                break
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                continue
        if conn is None:
            if last_exc is not None:
                _telemetry.capture_exception(last_exc)
                raise last_exc
            return []

        try:
            server_info = None
            if hasattr(conn, "get_server_info"):
                server_info = conn.get_server_info()
            if not server_info:
                server_info = getattr(conn, "_serverinfo", None)
            base_dn = ""
            if isinstance(server_info, dict):
                raw = server_info.get("defaultNamingContext")
                if isinstance(raw, list):
                    base_dn = str(raw[0]) if raw else ""
                elif raw:
                    base_dn = str(raw)
                if not base_dn:
                    ncs = server_info.get("namingContexts")
                    if isinstance(ncs, list) and ncs:
                        base_dn = str(ncs[0])
            if not base_dn:
                return []

            collected: list[dict[str, object]] = []
            try:
                async for item, err in conn.pagedsearch(
                    ldap_filter,
                    ["*"],
                    controls=None,
                    tree=base_dn,
                    search_scope=2,
                ):
                    if err is not None:
                        raise err
                    attrs = dict(item.get("attributes", {}) or {})
                    dn = item.get("objectName") or attrs.get("distinguishedName") or ""
                    if isinstance(dn, list):
                        dn = dn[0] if dn else ""
                    collected.append(
                        {
                            "distinguished_name": str(dn or ""),
                            "attributes": attrs,
                        }
                    )
            except Exception as exc:  # noqa: BLE001
                # Hardened directory: bind OK but search refused. Return
                # what we have (empty) instead of raising "Connected, but
                # not bound." up the stack.
                _telemetry.capture_exception(exc)
                logger.debug(
                    f"Anonymous LDAP search denied on {pdc}: {exc}"
                )
                return []
            return collected
        finally:
            try:
                disconnect = getattr(conn, "disconnect", None)
                if disconnect is not None:
                    maybe = disconnect()
                    if asyncio.iscoroutine(maybe):
                        await maybe
            except Exception:  # noqa: BLE001
                pass

    try:
        return asyncio.run(_run())
    except RuntimeError as exc:
        if "asyncio.run() cannot be called" in str(exc) or "running event loop" in str(exc):
            # Caller is already inside a loop — run on a fresh loop in a thread.
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                return pool.submit(asyncio.run, _run()).result()
        raise


@dataclass
class LDAPUser:
    """Represents a domain user from LDAP.

    Attributes:
        username: User's sAMAccountName
        distinguished_name: User's DN
        description: User description (may contain passwords)
        user_principal_name: User's UPN
        is_enabled: Whether account is enabled
        password_last_set: When password was last changed
        admin_count: AdminCount attribute (1 = privileged account)
    """

    username: str
    distinguished_name: str = ""
    description: str = ""
    user_principal_name: str = ""
    is_enabled: bool = True
    password_last_set: Optional[str] = None
    admin_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "username": self.username,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "user_principal_name": self.user_principal_name,
            "is_enabled": self.is_enabled,
            "password_last_set": self.password_last_set,
            "admin_count": self.admin_count,
        }


@dataclass
class LDAPGroup:
    """Represents a domain group from LDAP.

    Attributes:
        name: Group's sAMAccountName
        distinguished_name: Group's DN
        description: Group description
        member_count: Number of members (if available)
        is_privileged: Whether this is a privileged group
    """

    name: str
    distinguished_name: str = ""
    description: str = ""
    member_count: int = 0
    is_privileged: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "name": self.name,
            "distinguished_name": self.distinguished_name,
            "description": self.description,
            "member_count": self.member_count,
            "is_privileged": self.is_privileged,
        }


@dataclass
class LDAPComputer:
    """Represents a domain computer from LDAP.

    Attributes:
        hostname: Computer's DNS hostname or sAMAccountName
        samaccountname: Computer's sAMAccountName
        distinguished_name: Computer's DN
        operating_system: Operating system name
        os_version: Operating system version
        is_enabled: Whether computer account is enabled
        dns_hostname: Computer's DNS hostname
    """

    hostname: str
    samaccountname: str = ""
    distinguished_name: str = ""
    operating_system: str = ""
    os_version: str = ""
    is_enabled: bool = True
    dns_hostname: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "hostname": self.hostname,
            "samaccountname": self.samaccountname,
            "distinguished_name": self.distinguished_name,
            "operating_system": self.operating_system,
            "os_version": self.os_version,
            "is_enabled": self.is_enabled,
            "dns_hostname": self.dns_hostname,
        }


@dataclass
class LDAPAnonymousUserRecord:
    """Represents a partially-visible user object from anonymous LDAP bind.

    Attributes:
        distinguished_name: Distinguished name of the object.
        common_name: ``cn`` attribute or best-effort DN-derived CN.
        samaccountname: ``sAMAccountName`` when visible to the anonymous bind.
        description: ``description`` attribute, if exposed.
        object_classes: Multi-valued ``objectClass`` entries.
        is_enabled: Best-effort enabled state derived from ``userAccountControl``.
        raw_attributes: Full lower-cased attribute mapping parsed from NetExec.
    """

    distinguished_name: str
    common_name: str = ""
    samaccountname: str = ""
    description: str = ""
    object_classes: list[str] = field(default_factory=list)
    is_enabled: bool = True
    raw_attributes: Dict[str, list[str]] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for persistence/debugging."""
        return {
            "distinguished_name": self.distinguished_name,
            "common_name": self.common_name,
            "samaccountname": self.samaccountname,
            "description": self.description,
            "object_classes": list(self.object_classes),
            "is_enabled": self.is_enabled,
            "raw_attributes": dict(self.raw_attributes),
        }


class LDAPEnumerationMixin:
    """LDAP enumeration operations.

    This mixin provides LDAP-specific enumeration methods that typically
    require authenticated access to query Active Directory.

    Note: This is a mixin, not a standalone service. It requires a parent
    EnumerationService to provide event_bus, logger, and license_mode.
    """

    def __init__(self, parent_service):
        """Initialize LDAP enumeration mixin.

        Args:
            parent_service: Parent EnumerationService instance
        """
        self.parent = parent_service
        self.logger = parent_service.logger

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_users(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPUser]:
        """Enumerate domain users via LDAP.

        This operation requires authenticated access.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of domain users

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_user_enumeration",
            progress=0.0,
            message=f"Enumerating users via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating users via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --users"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            if result_is_exact_ldap_connection_timeout(result):
                self.logger.warning(
                    "LDAP user enumeration hit the exact NetExec LDAP timeout signature; "
                    "treating LDAP as unavailable for this attempt."
                )
                self.parent._emit_progress(
                    scan_id=scan_id,
                    phase="ldap_user_enumeration",
                    progress=1.0,
                    message="LDAP user enumeration unavailable (connection timeout)",
                )
                return []

            users = []
            if result.returncode == 0 and result.stdout:
                users = self._parse_netexec_users_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message=f"User enumeration completed: {len(users)} user(s) found",
            )

            self.logger.info(f"Found {len(users)} domain users")
            return users

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP user enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message="User enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP user enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_user_enumeration",
                progress=1.0,
                message="User enumeration failed",
            )
            return []

    @requires_auth(AuthMode.AUTHENTICATED)
    def enumerate_groups(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPGroup]:
        """Enumerate domain groups via LDAP.

        This operation requires authenticated access.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of domain groups

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_group_enumeration",
            progress=0.0,
            message=f"Enumerating groups via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating groups via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --groups"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)
            if result_is_exact_ldap_connection_timeout(result):
                self.logger.warning(
                    "LDAP group enumeration hit the exact NetExec LDAP timeout signature; "
                    "treating LDAP as unavailable for this attempt."
                )
                self.parent._emit_progress(
                    scan_id=scan_id,
                    phase="ldap_group_enumeration",
                    progress=1.0,
                    message="LDAP group enumeration unavailable (connection timeout)",
                )
                return []

            groups = []
            if result.returncode == 0 and result.stdout:
                groups = self._parse_netexec_groups_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message=f"Group enumeration completed: {len(groups)} group(s) found",
            )

            self.logger.info(f"Found {len(groups)} domain groups")
            return groups

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP group enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message="Group enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP group enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_group_enumeration",
                progress=1.0,
                message="Group enumeration failed",
            )
            return []

    def _parse_netexec_users_output(self, output: str) -> List[LDAPUser]:
        """Parse NetExec --users output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPUser objects
        """
        users = []

        # NetExec LDAP --users output format:
        # LDAP  10.0.0.1  389    DC01  [+] example.local\user1
        # LDAP  10.0.0.1  389    DC01      CN=User1,CN=Users,DC=example,DC=local
        # LDAP  10.0.0.1  389    DC01      Description: IT Admin

        lines = output.splitlines()
        current_user = None

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a user line
            if "[+]" in line and "\\" in line:
                # Extract username
                parts = line.split("\\")
                if len(parts) >= 2:
                    username = parts[-1].strip()
                    current_user = LDAPUser(username=username)
                    users.append(current_user)

            # Parse additional attributes
            elif current_user:
                if "CN=" in line and "DC=" in line:
                    current_user.distinguished_name = line.split("DC01")[-1].strip()
                elif "Description:" in line:
                    current_user.description = line.split("Description:")[-1].strip()
                elif "userPrincipalName:" in line:
                    current_user.user_principal_name = line.split("userPrincipalName:")[
                        -1
                    ].strip()
                elif "adminCount:" in line:
                    try:
                        admin_count_str = line.split("adminCount:")[-1].strip()
                        current_user.admin_count = int(admin_count_str)
                    except ValueError:
                        pass

        return users

    def _parse_netexec_groups_output(self, output: str) -> List[LDAPGroup]:
        """Parse NetExec --groups output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPGroup objects
        """
        groups = []

        # NetExec LDAP --groups output format similar to --users
        lines = output.splitlines()
        current_group = None

        # Privileged groups list
        privileged_groups = {
            "Domain Admins",
            "Enterprise Admins",
            "Administrators",
            "Schema Admins",
            "Account Operators",
            "Backup Operators",
            "Server Operators",
            "Print Operators",
        }

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a group line
            if "[+]" in line or "Group:" in line:
                # Extract group name
                if "\\" in line:
                    parts = line.split("\\")
                    if len(parts) >= 2:
                        group_name = parts[-1].strip()
                    else:
                        continue  # Skip invalid group line
                else:
                    group_name = line.split()[-1].strip()

                if not group_name:
                    continue  # Skip empty group name

                is_privileged = group_name in privileged_groups

                current_group = LDAPGroup(
                    name=group_name,
                    is_privileged=is_privileged,
                )
                groups.append(current_group)

            # Parse additional attributes
            elif current_group:
                if "CN=" in line and "DC=" in line:
                    current_group.distinguished_name = line.split("DC01")[-1].strip()
                elif "Description:" in line:
                    current_group.description = line.split("Description:")[-1].strip()

        return groups


    def query_anonymous_user_inventory(
        self,
        *,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        ldap_filter: Optional[str] = None,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPAnonymousUserRecord]:
        """Query LDAP anonymously for user objects.

        Native badldap implementation using an explicit ``ldap+simple://`` /
        ``ldaps+simple://`` SIMPLE bind with empty credentials (RFC 4513
        §5.1.1 anonymous), so paged searches actually work. The previous
        sync ``ADscanLDAPConnection`` path used the NONE-protocol URL form
        which leaves the connection in CONNECTED (not BOUND) state and
        crashed pagedsearch with ``Connected, but not bound.`` on every
        hardened DC.

        On hardened directories that allow the anonymous bind but reject
        searches (``operationsError`` / ``ERROR_NOT_AUTHENTICATED``), this
        returns ``[]`` cleanly — no exception escapes.

        ``netexec_path``, ``log_file`` and ``executor`` are accepted for
        backward compatibility with legacy callsites and ignored.
        """
        _ = (netexec_path, log_file, executor)

        effective_filter = (
            ldap_filter
            or "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        )
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_user_inventory",
            progress=0.0,
            message=f"Querying anonymous LDAP user inventory on {pdc}",
        )

        try:
            objects = _native_anonymous_user_inventory(
                pdc=pdc,
                ldap_filter=effective_filter,
                timeout=timeout,
            )
        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP user inventory: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_user_inventory",
                progress=1.0,
                message="Anonymous LDAP user inventory failed",
            )
            return []

        records = self._parse_netexec_anonymous_user_inventory(objects)

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_user_inventory",
            progress=1.0,
            message=f"Anonymous LDAP user inventory completed: {len(records)} user object(s) found",
        )
        return records

    def _parse_ldap_entries_anonymous_user_inventory(
        self, entries: list[object]
    ) -> List[LDAPAnonymousUserRecord]:
        """Normalize LDAP entries into anonymous user records."""
        objects: list[dict[str, object]] = []
        for entry in entries:
            dn = str(getattr(entry, "dn", None) or getattr(entry, "entry_dn", "") or "").strip()
            attrs = entry.entry_attributes_as_dict
            if not isinstance(attrs, dict):
                attrs = {}
            objects.append({"distinguished_name": dn, "attributes": attrs})
        return self._parse_netexec_anonymous_user_inventory(objects)

    def enumerate_computers(
        self,
        domain: str,
        pdc: str,
        auth_mode: AuthMode,
        username: str,
        password: str,
        netexec_path: str,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 120,
    ) -> List[LDAPComputer]:
        """Enumerate domain computers via LDAP.

        This operation requires authenticated access.

        Args:
            domain: Domain name
            pdc: PDC hostname/IP
            auth_mode: Authentication mode (must be AUTHENTICATED)
            username: Username
            password: Password or hash
            netexec_path: Path to NetExec
            scan_id: Optional scan ID
            timeout: Timeout in seconds

        Returns:
            List of domain computers

        Raises:
            AuthenticationError: If auth_mode is not AUTHENTICATED
        """
        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_computer_enumeration",
            progress=0.0,
            message=f"Enumerating computers via LDAP on {domain}",
        )

        self.logger.info(f"Enumerating computers via LDAP on domain {domain}")

        # Build auth string
        is_hash = len(password) == 32 and all(
            c in "0123456789abcdef" for c in password.lower()
        )

        if is_hash:
            auth_string = f"-u '{username}' -H '{password}' -d '{domain}'"
        else:
            auth_string = f"-u '{username}' -p '{password}' -d '{domain}'"

        command = f"{netexec_path} ldap {pdc} {auth_string} --computers"

        try:
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=0.3,
                message="Executing LDAP query",
            )

            exec_fn = executor or _default_executor
            result = exec_fn(command, timeout)

            computers = []
            if result.returncode == 0 and result.stdout:
                computers = self._parse_netexec_computers_output(result.stdout)

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message=f"Computer enumeration completed: {len(computers)} computer(s) found",
            )

            self.logger.info(f"Found {len(computers)} domain computers")
            return computers

        except subprocess.TimeoutExpired:
            self.logger.error("LDAP computer enumeration timed out")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message="Computer enumeration timed out",
            )
            return []
        except Exception as e:
            self.logger.exception(f"Error during LDAP computer enumeration: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_computer_enumeration",
                progress=1.0,
                message="Computer enumeration failed",
            )
            return []

    def test_anonymous_access(
        self,
        pdc: str,
        netexec_path: str,
        log_file: Optional[str] = None,
        *,
        executor: CommandExecutor | None = None,
        scan_id: Optional[str] = None,
        timeout: int = 60,
    ) -> Dict[str, Any]:
        """Test anonymous LDAP access to the domain controller.

        Attempts to bind to LDAP with empty credentials to test if
        anonymous access is allowed.

        Args:
            pdc: PDC hostname/IP.
            netexec_path: Unused — kept for backward compatibility with the
                legacy NetExec-based signature; the bind is now native.
            log_file: Unused — kept for compatibility.
            executor: Unused — kept for compatibility.
            scan_id: Optional scan ID.
            timeout: Timeout in seconds for the underlying async probe.

        Returns:
            Dictionary with test results:
                - accessible: bool - Whether anonymous access succeeded
                - error: Optional[str] - Error message if failed
        """
        # Backward-compat shim: parameters retained so existing callers continue
        # to work, but we no longer shell out to NetExec.
        _ = (netexec_path, log_file, executor)

        self.parent._emit_progress(
            scan_id=scan_id,
            phase="ldap_anonymous_test",
            progress=0.0,
            message=f"Testing anonymous LDAP access on {pdc}",
        )

        self.logger.info(f"Testing anonymous LDAP access on {pdc}")

        try:
            from adscan_internal.services.unauth_probe_service import (
                _probe_ldap_anonymous,
            )

            probe_result = asyncio.run(_probe_ldap_anonymous(pdc, timeout))

            accessible = probe_result.status == "open"

            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message=(
                    f"Anonymous LDAP test completed: "
                    f"{'Accessible' if accessible else 'Not accessible'}"
                ),
            )

            error_message: Optional[str] = None
            if not accessible:
                error_message = probe_result.error or "Anonymous access denied."

            self.logger.info(
                f"Anonymous LDAP access test: "
                f"{'SUCCESS' if accessible else 'DENIED'}",
                extra={"pdc": pdc, "accessible": accessible},
            )

            return {"accessible": accessible, "error": error_message}

        except RuntimeError as e:
            # Asyncio loop conflict — caller is already inside an event loop.
            self.logger.exception(
                f"Anonymous LDAP test cannot run synchronously: {e}"
            )
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test could not run (loop conflict)",
            )
            return {"accessible": False, "error": str(e)}

        except Exception as e:
            self.logger.exception(f"Error during anonymous LDAP test: {e}")
            self.parent._emit_progress(
                scan_id=scan_id,
                phase="ldap_anonymous_test",
                progress=1.0,
                message="Test failed",
            )
            return {"accessible": False, "error": str(e)}

    def _parse_netexec_anonymous_user_inventory(
        self, objects: list[dict[str, object]]
    ) -> List[LDAPAnonymousUserRecord]:
        """Normalize NetExec LDAP query objects into anonymous user records."""
        records: list[LDAPAnonymousUserRecord] = []
        seen_dns: set[str] = set()

        for item in objects:
            dn = str(item.get("distinguished_name") or "").strip()
            if not dn:
                continue

            attrs_raw = item.get("attributes") or {}
            if not isinstance(attrs_raw, dict):
                continue

            attrs: dict[str, list[str]] = {}
            for key, values in attrs_raw.items():
                normalized_key = str(key or "").casefold()
                if not normalized_key:
                    continue
                if isinstance(values, list):
                    attrs[normalized_key] = [
                        str(value).strip() for value in values if str(value).strip()
                    ]
                else:
                    value = str(values or "").strip()
                    attrs[normalized_key] = [value] if value else []

            object_classes = [entry.casefold() for entry in attrs.get("objectclass", [])]
            if object_classes and "user" not in object_classes:
                continue

            cn = ""
            if attrs.get("cn"):
                cn = attrs["cn"][0]
            elif dn.upper().startswith("CN="):
                cn = dn.split(",", 1)[0].split("=", 1)[1].strip()

            samaccountname = ""
            if attrs.get("samaccountname"):
                samaccountname = attrs["samaccountname"][0]

            description = " | ".join(attrs.get("description", []))

            is_enabled = True
            if attrs.get("useraccountcontrol"):
                try:
                    uac = int(attrs["useraccountcontrol"][0], 10)
                    is_enabled = not bool(uac & 0x0002)
                except (TypeError, ValueError):
                    is_enabled = True

            key = dn.casefold()
            if key in seen_dns:
                continue
            seen_dns.add(key)
            records.append(
                LDAPAnonymousUserRecord(
                    distinguished_name=dn,
                    common_name=cn,
                    samaccountname=samaccountname,
                    description=description,
                    object_classes=object_classes,
                    is_enabled=is_enabled,
                    raw_attributes=attrs,
                )
            )

        return records

    def _parse_netexec_computers_output(self, output: str) -> List[LDAPComputer]:
        """Parse NetExec --computers output.

        Args:
            output: NetExec stdout

        Returns:
            List of LDAPComputer objects
        """
        computers = []

        # NetExec LDAP --computers output format similar to --users
        # LDAP  10.0.0.1  389    DC01  [+] example.local\DC01$
        # LDAP  10.0.0.1  389    DC01      CN=DC01,OU=Domain Controllers,DC=example,DC=local
        # LDAP  10.0.0.1  389    DC01      operatingSystem: Windows Server 2019

        lines = output.splitlines()
        current_computer = None

        for line in lines:
            line = line.strip()
            if not line or "LDAP" not in line:
                continue

            # Check if this is a computer line (ends with $)
            if "[+]" in line and "\\" in line:
                # Extract computer name
                parts = line.split("\\")
                if len(parts) >= 2:
                    computer_name = parts[-1].strip()
                    # Remove trailing $ if present
                    hostname = computer_name.rstrip("$")
                    current_computer = LDAPComputer(
                        hostname=hostname,
                        samaccountname=computer_name,
                    )
                    computers.append(current_computer)

            # Parse additional attributes
            elif current_computer:
                if "CN=" in line and "DC=" in line:
                    current_computer.distinguished_name = line.split("DC01")[-1].strip()
                elif "operatingSystem:" in line:
                    current_computer.operating_system = line.split("operatingSystem:")[
                        -1
                    ].strip()
                elif "operatingSystemVersion:" in line:
                    current_computer.os_version = line.split("operatingSystemVersion:")[
                        -1
                    ].strip()
                elif "dNSHostName:" in line:
                    current_computer.dns_hostname = line.split("dNSHostName:")[
                        -1
                    ].strip()

        return computers

