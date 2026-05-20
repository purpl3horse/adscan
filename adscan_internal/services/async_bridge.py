"""Helpers for calling async service code from synchronous ADscan entry points."""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Awaitable
from typing import TypeVar

T = TypeVar("T")


def run_async_sync(awaitable: Awaitable[T]) -> T:
    """Run an awaitable from sync code, even if the caller already owns a loop."""
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(awaitable)

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(lambda: asyncio.run(awaitable)).result()
