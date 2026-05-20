from __future__ import annotations

import json
import time
from typing import Any


def read_json_file(path: str) -> dict[str, Any]:
    """Read a JSON file and return its parsed dictionary.

    Resilient to corrupted state: when parsing fails (truncated/malformed JSON
    left by a buggy prior run), the corrupted file is backed up to
    ``<path>.corrupted.<timestamp>.bak`` and an empty dict is returned, instead
    of propagating ``JSONDecodeError`` and breaking workspace load.
    """
    with open(path, "r", encoding="utf-8") as handle:
        try:
            data = json.load(handle)
        except json.JSONDecodeError as exc:
            try:
                handle.seek(0)
                _content = handle.read()
            except Exception:  # noqa: BLE001
                _content = ""
            _backup = f"{path}.corrupted.{int(time.time())}.bak"
            try:
                with open(_backup, "w", encoding="utf-8") as _bh:
                    _bh.write(_content)
            except OSError:
                _backup = ""
            try:
                from adscan_core.rich_output import print_warning
                _msg = f"variables JSON at {path} was corrupted ({exc}); recovered with empty state."
                if _backup:
                    _msg += f" Original backed up to {_backup}."
                print_warning(_msg)
            except Exception:  # noqa: BLE001
                pass
            return {}
    if isinstance(data, dict):
        return data
    return {}


def write_json_file(path: str, data: dict[str, Any]) -> None:
    """Write a JSON dict to disk with stable formatting."""
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=4, sort_keys=True)


__all__ = [
    "read_json_file",
    "write_json_file",
]
