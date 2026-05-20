"""Unified per-host collector for ADscan.

Single SMB session per host that runs SAMR (sessions, builtin groups) and
SRVSVC (share enumeration with security descriptors) on the same authenticated
``aiosmb`` machine.  Replaces the legacy two-phase flow that opened two
separate SMB sessions per host.

All Computer nodes in the CollectionResult are processed concurrently up to
``concurrency`` simultaneous SMB sessions.  IP resolution must have happened
upstream via ``dns_resolver.resolve_computer_nodes``.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import time
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, TYPE_CHECKING

from adscan_core import telemetry
from adscan_core.rich_output import print_info_debug, print_info_verbose

if TYPE_CHECKING:
    pass  # DomainPosture, PostureSink used in Tasks 4-5 host-phase logic

from adscan_internal.services.collector.models import (
    CollectionResult,
    CollectorEdge,
    is_collectable_computer_host,
)

from adscan_internal.services.collector.share_collector import (
    ShareCollectorConfig,
    _ShareInfo,
    mask_to_edge_kinds,
)
from adscan_internal.services.collector.smb_collector import (
    SMBCollectorConfig,
    sid_to_object_id,
)


_HOST_CONCURRENCY_DEFAULT = 20
_HOST_TIMEOUT_DEFAULT = 20


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
        return value if value > 0 else default
    except ValueError:
        return default


@dataclass
class HostCollectorConfig:
    """Combined credentials + tuning for the unified host phase."""

    smb: SMBCollectorConfig
    share: ShareCollectorConfig
    concurrency: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_HOST_CONCURRENCY", _HOST_CONCURRENCY_DEFAULT
        )
    )
    per_host_timeout: int = field(
        default_factory=lambda: _env_int(
            "ADSCAN_COLLECTOR_PER_HOST_TIMEOUT", _HOST_TIMEOUT_DEFAULT
        )
    )  # seconds; applied per SMB host operation (negotiate + SAMR + shares combined)
    collect_samr: bool = True  # gates _do_samr per host (sessions + builtin groups)
    collect_shares: bool = True  # gates _do_shares per host


@dataclass
class HostCollectionResult:
    """Per-host raw output. Edge construction happens at the domain level."""

    smb_props: dict[str, Any] = field(default_factory=dict)
    session_usernames: list[tuple[str, str]] = field(
        default_factory=list
    )  # (username, ip_address) from SAMR NetSessEnum
    builtin_groups: dict[str, list[str]] = field(default_factory=dict)
    shares: list[_ShareInfo] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)


@dataclass
class HostPhaseTiming:
    """Aggregated timing for the unified host phase across all hosts."""

    negotiate: float = 0.0
    samr: float = 0.0
    shares: float = 0.0

    @property
    def total(self) -> float:
        return self.negotiate + self.samr + self.shares


async def _do_negotiate(
    target_ip: str,
    smb_cfg: SMBCollectorConfig,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
) -> None:
    from adscan_internal.services.collector.smb_collector import negotiate_only

    t = time.monotonic()
    try:
        props = await negotiate_only(target_ip, smb_cfg.port, smb_cfg.per_host_timeout)
        if props:
            out.smb_props.update(props)
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["negotiate"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.negotiate += time.monotonic() - t


async def _do_samr(
    machine: Any,
    per_host_timeout: int,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
) -> None:
    from adscan_internal.services.collector.smb_collector import (
        collect_builtin_group_members,
        collect_sessions,
    )

    t = time.monotonic()
    try:
        try:
            sessions = await asyncio.wait_for(
                collect_sessions(machine), timeout=per_host_timeout
            )
            out.session_usernames = sessions
        except asyncio.TimeoutError:
            out.errors["sessions"] = "timeout"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            out.errors["sessions"] = f"{type(exc).__name__}: {exc}"

        try:
            builtin_groups = await asyncio.wait_for(
                collect_builtin_group_members(machine), timeout=per_host_timeout
            )
            out.builtin_groups = builtin_groups
        except asyncio.TimeoutError:
            out.errors["builtin_groups"] = "timeout"
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            out.errors["builtin_groups"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.samr += time.monotonic() - t


async def _do_shares(
    machine: Any,
    target_ip: str,
    share_cfg: ShareCollectorConfig,
    per_host_timeout: int,
    out: HostCollectionResult,
    timing: HostPhaseTiming,
) -> None:
    from adscan_internal.services.collector.share_collector import (
        collect_shares_for_host,
    )

    t = time.monotonic()
    try:
        shares = await asyncio.wait_for(
            collect_shares_for_host(machine, share_cfg, target_ip),
            timeout=per_host_timeout * 2,
        )
        out.shares = shares
    except asyncio.TimeoutError:
        out.errors["shares"] = "timeout"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["shares"] = f"{type(exc).__name__}: {exc}"
    finally:
        timing.shares += time.monotonic() - t


async def collect_one_host(
    target_ip: str,
    target_hostname: str | None,
    config: HostCollectorConfig,
    timing: HostPhaseTiming,
) -> HostCollectionResult:
    """Run negotiate + SAMR + SRVSVC against a single host on ONE SMB session."""
    from adscan_internal.services.smb_transport import (
        SMBAccessDeniedError,
        SMBAuthError,
        SMBConfig,
        SMBConnectionError,
        smb_machine_with_fallback,
    )

    out = HostCollectionResult()

    await _do_negotiate(target_ip, config.smb, out, timing)

    smb_config = SMBConfig(
        target_ip=target_ip,
        target_hostname=target_hostname,
        domain=config.smb.domain,
        auth_domain=config.smb.auth_domain,
        username=config.smb.username,
        password=config.smb.password,
        nt_hash=config.smb.nt_hash,
        aes_key=config.smb.aes_key,
        ccache_path=config.smb.ccache_path,
        use_kerberos=config.smb.use_kerberos,
        kdc_ip=config.smb.kdc_ip or config.smb.dc_address,
        port=config.smb.port,
        timeout=config.per_host_timeout,
        posture_sink=config.smb.posture_sink,
        posture_snapshot=config.smb.posture_snapshot,
    )

    try:
        async with smb_machine_with_fallback(smb_config) as machine:
            if config.collect_samr:
                await _do_samr(machine, config.per_host_timeout, out, timing)
            if config.collect_shares:
                await _do_shares(
                    machine,
                    target_ip,
                    config.share,
                    config.per_host_timeout,
                    out,
                    timing,
                )
    except SMBAuthError as exc:
        out.errors["auth"] = f"{type(exc).__name__}: {exc}"
        if "AP_REP" in str(exc) or "asn1_structs" in str(exc):
            telemetry.capture_exception(exc)
            print_info_debug(
                f"[host-collector] suspected minikerberos AP_REP parse bug on {target_ip}"
            )
    except SMBAccessDeniedError as exc:
        out.errors["auth"] = f"access_denied: {exc}"
    except (SMBConnectionError, asyncio.TimeoutError) as exc:
        out.errors["connect"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        telemetry.capture_exception(exc)
        out.errors["unexpected"] = f"{type(exc).__name__}: {exc}"

    return out


def _build_sid_to_node(result: CollectionResult) -> dict[str, Any]:
    sid_to_node: dict[str, Any] = {}
    for node in result.nodes.values():
        oid = str(node.object_id or "").strip().upper()
        if oid:
            sid_to_node[oid] = node
    return sid_to_node


def _merge_host_into_graph(
    node: Any,
    host_data: HostCollectionResult,
    sid_to_node: dict[str, Any],
    samaccount_to_node: dict[str, Any],
    result: CollectionResult,
) -> tuple[int, int, int, dict[str, int]]:
    """Merge per-host raw data into the CollectionResult.

    Returns (n_has_session, n_admin_to_like, n_share_edges, sd_source_counts).
    """
    for k, v in host_data.smb_props.items():
        node.properties[k] = v

    computer_oid = str(node.object_id or "").strip().upper()
    n_session = 0
    n_admin = 0
    n_share = 0
    sd_source_counts: dict[str, int] = {}

    # HasSession edges — O(1) lookup via pre-built samaccount_to_node index
    for username, _ip in host_data.session_usernames:
        uname_lower = username.lower()
        matched_user = samaccount_to_node.get(uname_lower) or samaccount_to_node.get(
            uname_lower.split("@")[0]
        )
        if matched_user is None:
            continue
        result.add_edge(
            CollectorEdge(
                source_object_id=computer_oid,
                target_object_id=str(matched_user.object_id or "").upper(),
                relation="HasSession",
                source="smb",
                method="srvsvc",
            )
        )
        n_session += 1

    # AdminTo / CanRDP / CanPSRemote edges
    for relation, sids in host_data.builtin_groups.items():
        for sid_str in sids:
            member_oid = sid_to_object_id(sid_str)
            member_node = sid_to_node.get(member_oid)
            if member_node is None or member_node.kind not in (
                "User",
                "Group",
                "Computer",
            ):
                continue
            result.add_edge(
                CollectorEdge(
                    source_object_id=member_oid,
                    target_object_id=computer_oid,
                    relation=relation,
                    source="smb",
                    method="samr",
                )
            )
            n_admin += 1

    # Share edges + names
    if host_data.shares:
        node.properties["smb_shares"] = [s.name for s in host_data.shares]
        for share in host_data.shares:
            sd_source_counts[share.sd_source] = (
                sd_source_counts.get(share.sd_source, 0) + 1
            )
            for sid_str, mask in share.aces:
                sid_upper = sid_str.strip().upper()
                principal = sid_to_node.get(sid_upper)
                if principal is None or principal.kind not in (
                    "User",
                    "Group",
                    "Computer",
                ):
                    continue
                for relation in mask_to_edge_kinds(mask):
                    result.add_edge(
                        CollectorEdge(
                            source_object_id=sid_upper,
                            target_object_id=computer_oid,
                            relation=relation,
                            source="smb",
                            method=f"share_acl:{share.name}",
                            notes={
                                "share_name": share.name,
                                "sd_source": share.sd_source,
                            },
                        )
                    )
                    n_share += 1

    return n_session, n_admin, n_share, sd_source_counts


async def _collect_domain_hosts_async(
    result: CollectionResult,
    config: HostCollectorConfig,
) -> HostPhaseTiming:
    from adscan_internal.services.collector.smb_collector import (
        resolve_target_hostname,
        resolve_target_ip,
    )

    timing = HostPhaseTiming()
    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    if not computers:
        return timing

    sid_to_node = _build_sid_to_node(result)

    # Build SAM-account lookup once before fan-out — O(1) per session in _merge_host_into_graph
    samaccount_to_node: dict[str, Any] = {}
    for n in result.nodes.values():
        if n.kind not in ("User", "Computer"):
            continue
        sam = str(getattr(n, "samaccountname", "") or "").strip().lower()
        if sam:
            samaccount_to_node[sam] = n

    sem = asyncio.Semaphore(config.concurrency)

    totals = {"session": 0, "admin": 0, "share": 0}
    sd_source_counts: dict[str, int] = {}

    async def _run(node: Any) -> None:
        target_ip = resolve_target_ip(node)
        if not target_ip:
            return
        target_hostname = resolve_target_hostname(node)
        async with sem:
            host_data = await collect_one_host(
                target_ip, target_hostname, config, timing
            )
        n_s, n_a, n_sh, src_counts = _merge_host_into_graph(
            node, host_data, sid_to_node, samaccount_to_node, result
        )
        # Safe under asyncio: no await between the merge above and these updates,
        # so cooperative scheduling guarantees no preemption inside the read-modify-write.
        totals["session"] += n_s
        totals["admin"] += n_a
        totals["share"] += n_sh
        for k, v in src_counts.items():
            sd_source_counts[k] = sd_source_counts.get(k, 0) + v

    tasks = [asyncio.create_task(_run(node)) for node in computers]
    results: list = []
    if tasks:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, Exception):
            telemetry.capture_exception(r)
            print_info_debug(f"[host-collector] task raised: {type(r).__name__}: {r}")

    relation_counts = Counter(e.relation for e in result.edges)
    signing_required = sum(
        1 for n in computers if n.properties.get("smb_signing_required")
    )
    print_info_verbose(
        f"[host-collector] HasSession={relation_counts['HasSession']} "
        f"AdminTo={relation_counts['AdminTo']} CanRDP={relation_counts['CanRDP']} "
        f"CanPSRemote={relation_counts['CanPSRemote']} "
        f"signing_required={signing_required}/{len(computers)}"
    )
    read_e = relation_counts["ReadShare"]
    write_e = relation_counts["WriteShare"]
    full_e = relation_counts["FullControlShare"]
    src_summary = (
        ", ".join(f"{k}={v}" for k, v in sorted(sd_source_counts.items())) or "none"
    )
    print_info_verbose(
        f"[host-collector] shares={sum(len(n.properties.get('smb_shares', [])) for n in computers)} "
        f"edges={totals['share']} (Read={read_e} Write={write_e} FullControl={full_e}) "
        f"sd_sources=({src_summary})"
    )
    return timing


def collect_domain_hosts(
    result: CollectionResult,
    config: HostCollectorConfig,
) -> HostPhaseTiming:
    """Synchronous entry point.

    Creates a fresh event loop in a worker thread (matches the legacy SMB/Share
    collectors' pattern so the orchestrator can keep being synchronous).
    """
    timing_holder: dict[str, HostPhaseTiming] = {}

    def _run_in_thread() -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            timing_holder["t"] = loop.run_until_complete(
                _collect_domain_hosts_async(result, config)
            )
        finally:
            loop.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        fut = pool.submit(_run_in_thread)
        fut.result()

    return timing_holder.get("t", HostPhaseTiming())
