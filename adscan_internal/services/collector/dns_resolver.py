"""Bulk DNS resolution for Computer nodes using massdns.

Uses the DC IP as the sole resolver — in a lab or customer engagement the DC
always knows its own A records, so we avoid dependency on external DNS.

massdns is a C binary included in the ADscan runtime. If it is not found the
function falls back gracefully (caller uses ``dnshostname`` directly instead).
"""

from __future__ import annotations

import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
from typing import TYPE_CHECKING

from adscan_internal import print_info_debug, print_info_verbose
from adscan_internal.services.collector.models import is_collectable_computer_host

if TYPE_CHECKING:
    from adscan_internal.services.collector.models import CollectionResult


def _find_massdns() -> str | None:
    """Return the massdns binary path or None if not found."""
    found = shutil.which("massdns")
    if found:
        return found
    adscan_home = os.getenv("ADSCAN_HOME") or ""
    for candidate in (
        os.path.join(adscan_home, "bin", "massdns"),
        os.path.join(adscan_home, "tools", "massdns", "bin", "massdns"),
    ):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def _parse_ndjson_a_map(path: str) -> dict[str, str]:
    """Parse massdns NDJSON output → hostname (lowered, no trailing dot) → first IPv4."""
    result: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                raw = line.strip()
                if not raw:
                    continue
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                hostname = str(rec.get("name") or "").strip().rstrip(".").lower()
                data = rec.get("data")
                if not isinstance(data, dict):
                    continue
                for item in data.get("answers") or []:
                    if not isinstance(item, dict):
                        continue
                    if str(item.get("type") or "").upper() != "A":
                        continue
                    ip = str(item.get("data") or "").strip()
                    if ip and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
                        if hostname and hostname not in result:
                            result[hostname] = ip
                        break
    except OSError:
        pass
    return result


def resolve_computer_nodes(
    result: "CollectionResult",
    dc_ip: str,
    *,
    timeout: int = 60,
) -> int:
    """Resolve Computer node hostnames to IPs via massdns.

    Writes ``ip_address`` into each resolved Computer node's properties.
    Returns the number of nodes that received an IP.
    """
    computers = [n for n in result.nodes.values() if is_collectable_computer_host(n)]
    hostnames = [
        str(n.properties.get("dnshostname") or "").strip().lower() for n in computers
    ]
    hostnames = [h for h in hostnames if h]
    if not hostnames:
        return 0

    massdns_bin = _find_massdns()
    if not massdns_bin:
        print_info_debug("[dns-resolver] massdns not found — skipping IP resolution")
        return 0

    resolved = 0
    with tempfile.TemporaryDirectory(prefix="adscan_dns_") as tmpdir:
        hosts_file = os.path.join(tmpdir, "hosts.txt")
        output_file = os.path.join(tmpdir, "out.jsonl")
        resolver_file = os.path.join(tmpdir, "resolvers.txt")

        with open(hosts_file, "w") as fh:
            fh.write("\n".join(hostnames) + "\n")
        with open(resolver_file, "w") as fh:
            fh.write(dc_ip + "\n")

        cmd = (
            f"{shlex.quote(massdns_bin)} -r {shlex.quote(resolver_file)} "
            f"-t A -o J -w {shlex.quote(output_file)} {shlex.quote(hosts_file)}"
        )
        print_info_verbose(f"[dns-resolver] resolving {len(hostnames)} hostnames")
        try:
            subprocess.run(
                cmd,
                shell=True,
                timeout=timeout,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except subprocess.TimeoutExpired:
            print_info_debug("[dns-resolver] massdns timed out")
            return 0
        except OSError as exc:
            print_info_debug(f"[dns-resolver] massdns execution error: {exc}")
            return 0

        host_to_ip = _parse_ndjson_a_map(output_file)

    for node in computers:
        dns = str(node.properties.get("dnshostname") or "").strip().lower()
        if not dns:
            continue
        ip = host_to_ip.get(dns)
        if ip:
            node.properties["ip_address"] = ip
            resolved += 1

    print_info_debug(f"[dns-resolver] resolved {resolved}/{len(computers)} computers")
    return resolved
