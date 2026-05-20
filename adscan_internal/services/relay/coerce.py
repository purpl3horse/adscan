"""Composition helpers for native coercion plus native relay."""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

from adscan_internal.rich_output import mark_sensitive, print_info_debug
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)
from adscan_internal.services.relay.core import RelayRunResult, RelayTarget
from adscan_internal.services.relay.runner import NativeRelayRunConfig, run_native_relay


@dataclass(frozen=True)
class NativeCoerceRelayConfig:
    """Configuration for a native coerce-and-relay chain."""

    listener_host: str
    relay: NativeRelayRunConfig
    coercion: NativeCoercionRunConfig
    listener_ready_delay_seconds: float = 1.0


@dataclass(frozen=True)
class NativeCoerceRelayResult:
    """Aggregate result for one native coerce-and-relay chain."""

    relay_result: RelayRunResult
    coercion_success: bool
    coercion_attempts: int

    @property
    def success(self) -> bool:
        """Return whether the relay target succeeded."""

        return self.relay_result.success


async def run_native_coerce_and_relay(
    *,
    targets: list[RelayTarget],
    coercion_connection_factory,
    coercion_target_host: str,
    config: NativeCoerceRelayConfig,
    coercion_target_name: str | None = None,
) -> NativeCoerceRelayResult:
    """Start native relay, trigger native coercion, and await relay completion."""

    print_info_debug(
        "[relay] starting native coerce-and-relay "
        f"coercion_target={mark_sensitive(coercion_target_name or coercion_target_host, 'hostname')} "
        f"listener={mark_sensitive(config.listener_host, 'hostname')} "
        f"relay_source={mark_sensitive(config.relay.source, 'text')}"
    )

    relay_task = asyncio.create_task(
        run_native_relay(targets=targets, config=config.relay)
    )
    coercion_task: asyncio.Task | None = None
    try:
        await asyncio.sleep(max(config.listener_ready_delay_seconds, 0.0))
        coercion_task = asyncio.create_task(
            run_native_coercion(
                connection_factory=coercion_connection_factory,
                target_host=coercion_target_host,
                target_name=coercion_target_name,
                config=config.coercion,
            )
        )

        done, _pending = await asyncio.wait(
            {relay_task, coercion_task},
            return_when=asyncio.FIRST_COMPLETED,
        )
        if relay_task in done:
            relay_result = await relay_task
            coercion_result = await _cancel_or_collect_coercion(coercion_task)
            return NativeCoerceRelayResult(
                relay_result=relay_result,
                coercion_success=coercion_result.success
                or relay_result.authentications_seen > 0,
                coercion_attempts=max(
                    coercion_result.attempts,
                    relay_result.authentications_seen,
                ),
            )

        coercion_result = await coercion_task
        relay_result = await relay_task
        return NativeCoerceRelayResult(
            relay_result=relay_result,
            coercion_success=coercion_result.success,
            coercion_attempts=coercion_result.attempts,
        )
    except Exception:
        if not relay_task.done():
            relay_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await relay_task
        if coercion_task is not None and not coercion_task.done():
            coercion_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await coercion_task
        raise


async def _cancel_or_collect_coercion(coercion_task: asyncio.Task):
    """Return coercion result, cancelling it if relay finished first."""

    if coercion_task.done():
        return await coercion_task
    coercion_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        return await coercion_task
    from adscan_internal.services.coercion.core import (
        CoercionRunResult,
        CoercionTarget,
    )

    return CoercionRunResult(
        target=CoercionTarget(host="cancelled-after-relay"),
        results=(),
        timed_out=False,
        attempts=0,
    )
