"""aiosmb-backed RPC adapter for native coercion."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from adscan_internal.services.coercion.core import (
    CoercionTarget,
    RpcEndpoint,
    RpcProtocolAdapter,
    RpcSession,
)


@dataclass
class AiosmbRpcAdapter(RpcProtocolAdapter):
    """RPC adapter that uses ADscan's async SMB/DCERPC stack."""

    connection_factory: Any

    async def iter_endpoints(
        self,
        *,
        target: CoercionTarget,
        protocol: str,
    ) -> list[RpcEndpoint]:
        protocol_class = _protocol_class(protocol)
        endpoints = []
        for endpoint in protocol_class.endpoints():
            endpoints.append(
                RpcEndpoint(
                    transport=endpoint.etype,
                    protocol=protocol.upper(),
                    uuid=endpoint.uuid,
                    version=endpoint.version,
                    pipe=endpoint.pipename,
                )
            )
        return endpoints

    async def connect(
        self,
        *,
        target: CoercionTarget,
        endpoint: RpcEndpoint,
    ) -> RpcSession:
        protocol_class = _protocol_class(endpoint.protocol)
        native_endpoint = _find_native_endpoint(protocol_class, endpoint)
        connection = self.connection_factory.create_connection_newtarget(target.host)
        rpc, err = await protocol_class.from_smbconnection(
            connection, endpoint=native_endpoint
        )
        if err is not None:
            raise err
        return rpc


def _protocol_class(protocol: str) -> Any:
    protocol_upper = protocol.upper()
    if protocol_upper == "EFSR":
        from aiosmb.dcerpc.v5.interfaces.efsrmgr import EFSRRPC  # pylint: disable=import-error,no-name-in-module

        return EFSRRPC
    if protocol_upper == "RPRN":
        from aiosmb.dcerpc.v5.interfaces.rprnmgr import RPRNRPC

        return RPRNRPC
    if protocol_upper == "FSRVP":
        from aiosmb.dcerpc.v5.interfaces.fsrvpmgr import FSRVPRPC  # pylint: disable=import-error,no-name-in-module

        return FSRVPRPC
    if protocol_upper == "EVEN":
        from aiosmb.dcerpc.v5.interfaces.evenmgr import EVENRPC  # pylint: disable=import-error,no-name-in-module

        return EVENRPC
    if protocol_upper == "DFSNM":
        from aiosmb.dcerpc.v5.interfaces.dfsnmmgr import DFSNMRPC  # pylint: disable=import-error,no-name-in-module

        return DFSNMRPC
    raise ValueError(f"Unsupported coercion protocol: {protocol}")


def _find_native_endpoint(protocol_class: Any, endpoint: RpcEndpoint) -> Any:
    for candidate in protocol_class.endpoints():
        if (
            candidate.etype == endpoint.transport
            and candidate.uuid.lower() == endpoint.uuid.lower()
            and candidate.version == endpoint.version
            and candidate.pipename == endpoint.pipe
        ):
            return candidate
    raise ValueError(f"Endpoint is not valid for {endpoint.protocol}: {endpoint.label}")
