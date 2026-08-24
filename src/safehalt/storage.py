"""Root-owned JSON storage helpers."""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from .errors import SafeHaltError


def verify_root_file(path: Path, mode: int = 0o600) -> None:
    try:
        file_stat = path.stat()
    except FileNotFoundError as exc:
        raise SafeHaltError(f"Required file does not exist: {path}") from exc
    if file_stat.st_uid != 0:
        raise SafeHaltError(f"File is not owned by root: {path}")
    if stat.S_IMODE(file_stat.st_mode) != mode:
        raise SafeHaltError(f"File must have mode {mode:04o}: {path}")


def load_root_json(path: Path) -> dict[str, Any]:
    verify_root_file(path)
    try:
        with path.open("r", encoding="utf-8") as handle:
            value = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise SafeHaltError(f"Invalid JSON file: {path}") from exc
    if not isinstance(value, dict):
        raise SafeHaltError(f"JSON root must be an object: {path}")
    return value


def atomic_root_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise
