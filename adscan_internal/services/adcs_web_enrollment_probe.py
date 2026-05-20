"""ADCS CA HTTP web enrollment probe (ESC8).

Detects whether the CA host has a ``/certsrv/`` web enrollment endpoint
exposed by checking TCP reachability on ports 80 and 443. We deliberately
avoid pulling in an HTTP client dependency (no aiohttp / httpx); a TCP
probe is sufficient and the operator can confirm the banner separately.

False-negative biased: any failure -> ``web_enrollment_enabled=False``.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass

from adscan_core.rich_output import print_info_debug
from adscan_internal import telemetry
from adscan_internal.rich_output import mark_sensitive


@dataclass
class WebEnrollmentProbeResult:
    target_host: str
    web_enrollment_enabled: bool
    https_enabled: bool
    http_enabled: bool
    error_message: str | None = None


class ADCSWebEnrollmentProbe:
    """Detect HTTP(S) ``/certsrv/`` endpoint exposure on a CA host."""

    async def probe(
        self, *, host: str, timeout: float = 5.0
    ) -> WebEnrollmentProbeResult:
        if not host:
            return WebEnrollmentProbeResult(
                target_host="",
                web_enrollment_enabled=False,
                https_enabled=False,
                http_enabled=False,
                error_message="missing host",
            )

        https_open = await self._tcp_open(host, 443, timeout)
        http_open = await self._tcp_open(host, 80, timeout)
        enabled = https_open or http_open
        if enabled:
            print_info_debug(
                "[adcs-web-probe] enrollment endpoint present: "
                f"host={mark_sensitive(host, 'host')} "
                f"https={https_open} http={http_open}"
            )
        else:
            print_info_debug(
                "[adcs-web-probe] no enrollment endpoint reachable: "
                f"host={mark_sensitive(host, 'host')}"
            )
        return WebEnrollmentProbeResult(
            target_host=host,
            web_enrollment_enabled=enabled,
            https_enabled=https_open,
            http_enabled=http_open,
        )

    @staticmethod
    async def _tcp_open(host: str, port: int, timeout: float) -> bool:
        try:
            fut = asyncio.open_connection(host, port)
            _reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            try:
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:  # noqa: BLE001
                    pass
            except Exception:  # noqa: BLE001
                pass
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror):
            return False
        except Exception as exc:  # noqa: BLE001
            telemetry.capture_exception(exc)
            return False
