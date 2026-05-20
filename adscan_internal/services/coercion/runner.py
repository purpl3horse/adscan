"""High-level native coercion runner."""

from __future__ import annotations

from dataclasses import dataclass, field

from adscan_internal.rich_output import mark_sensitive, print_info_debug, print_success_debug
from adscan_internal.services.coercion.aiosmb_adapter import AiosmbRpcAdapter
from adscan_internal.services.coercion.core import (
    CoercionAuthType,
    CoercionEngine,
    CoercionListener,
    CoercionMethod,
    CoercionRunConfig,
    CoercionRunResult,
    CoercionTarget,
    RpcTransport,
)
from adscan_internal.services.coercion.display import print_coercion_summary
from adscan_internal.services.coercion.registry import default_coercion_methods

@dataclass(frozen=True)
class NativeCoercionRunConfig:
    """Runtime configuration for native coercion."""

    listener_host: str
    listener_auth_type: CoercionAuthType = "smb"
    listener_port: int | None = None
    timeout_seconds: float = 60.0
    delay_seconds: float = 0.05
    stop_on_first_success: bool = True
    protocols: tuple[str, ...] = ("EFSR", "RPRN")
    transports: tuple[RpcTransport, ...] = ("ncan_np",)
    method_names: tuple[str, ...] = ()
    methods: tuple[CoercionMethod, ...] = field(
        default_factory=default_coercion_methods
    )
    show_summary: bool = True


async def run_native_coercion(
    *,
    connection_factory,
    target_host: str,
    config: NativeCoercionRunConfig,
    target_name: str | None = None,
) -> CoercionRunResult:
    """Run native async coercion against one target using an aiosmb factory."""

    target = CoercionTarget(host=target_host, display_name=target_name)
    listener = CoercionListener(
        auth_type=config.listener_auth_type,
        host=config.listener_host,
        port=config.listener_port,
    )
    print_info_debug(
        "[coercion] starting native coercion "
        f"target={mark_sensitive(target.label, 'hostname')} "
        f"listener={mark_sensitive(listener.host, 'hostname')} "
        f"auth_type={mark_sensitive(listener.auth_type, 'text')} "
        f"protocols={mark_sensitive(','.join(config.protocols) or 'all', 'text')}"
    )

    engine = CoercionEngine(
        target=target,
        rpc_adapter=AiosmbRpcAdapter(connection_factory=connection_factory),
        config=CoercionRunConfig(
            listeners=(listener,),
            methods=config.methods,
            timeout_seconds=config.timeout_seconds,
            delay_seconds=config.delay_seconds,
            stop_on_first_success=config.stop_on_first_success,
            protocols=config.protocols,
            transports=config.transports,
            method_names=config.method_names,
            auth_types=(config.listener_auth_type,),
        ),
    )
    result = await engine.run()
    print_success_debug(
        f"[coercion] completed target={mark_sensitive(target.label, 'hostname')} "
        f"success={result.success} attempts={result.attempts} timed_out={result.timed_out}"
    )
    if config.show_summary:
        print_coercion_summary(result)
    return result
