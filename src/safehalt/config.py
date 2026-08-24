"""Allowlisted path configuration."""

from __future__ import annotations

import os
from pathlib import Path
import pwd
import stat
from typing import Any

from .errors import SafeHaltError
from .storage import atomic_root_json, load_root_json


def _is_inside(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


class PathConfig:
    def __init__(
        self,
        path: Path,
        home_root: Path | None = None,
        privileged_uid: int = 0,
    ) -> None:
        self.path = path
        self.home_root = home_root
        self.privileged_uid = privileged_uid

    def home_for_path(self, candidate: Path) -> Path:
        """Return the owning non-root account home for a resolved target."""
        if self.home_root is not None:
            try:
                root = self.home_root.resolve(strict=True)
            except OSError as exc:
                raise SafeHaltError("Configured home root cannot be resolved.") from exc
            if not _is_inside(candidate, root) or candidate == root:
                raise SafeHaltError("The path is outside the configured home root.")
            relative = candidate.relative_to(root)
            home = root / relative.parts[0]
            if home.exists():
                return home
            raise SafeHaltError("The candidate user home does not exist.")

        matches: list[tuple[int, Path, int]] = []
        for account in pwd.getpwall():
            if account.pw_uid == self.privileged_uid or not account.pw_dir.startswith("/"):
                continue
            try:
                home = Path(account.pw_dir).resolve(strict=True)
            except OSError:
                continue
            if candidate != home and _is_inside(candidate, home):
                matches.append((len(home.parts), home, account.pw_uid))
        if not matches:
            raise SafeHaltError(
                "The path is not below a non-root home declared by the account database."
            )
        _, home, owner_uid = max(matches, key=lambda item: item[0])
        try:
            home_stat = home.stat()
        except OSError as exc:
            raise SafeHaltError(f"User home cannot be inspected: {home}") from exc
        if home_stat.st_uid != owner_uid:
            raise SafeHaltError(f"User home has an unexpected owner: {home}")
        return home

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return {"format": 1, "paths": []}
        payload = load_root_json(self.path)
        if payload.get("format") != 1 or not isinstance(payload.get("paths"), list):
            raise SafeHaltError("Unsupported or damaged path configuration.")
        if not all(isinstance(item, str) for item in payload["paths"]):
            raise SafeHaltError("Configured paths must be strings.")
        return payload

    def save_paths(self, paths: list[str]) -> None:
        atomic_root_json(self.path, {"format": 1, "paths": sorted(set(paths))})

    @staticmethod
    def _expand_operator_home(raw: str) -> str:
        if raw == "~" or raw.startswith("~/"):
            operator = os.environ.get("SUDO_USER")
            if operator and operator != "root":
                try:
                    operator_home = pwd.getpwnam(operator).pw_dir
                except KeyError:
                    operator_home = ""
                if operator_home:
                    return operator_home + raw[1:]
        return str(Path(raw).expanduser())

    def validate_candidate(self, raw: str) -> Path:
        expanded = self._expand_operator_home(raw)
        lexical = Path(os.path.abspath(expanded))
        try:
            resolved = lexical.resolve(strict=True)
        except OSError as exc:
            raise SafeHaltError(f"Path does not exist or cannot be resolved: {raw}") from exc

        if lexical != resolved:
            raise SafeHaltError("Symbolic links and aliased paths are not allowed.")
        home = self.home_for_path(resolved)
        relative = resolved.relative_to(home)
        if not relative.parts:
            raise SafeHaltError(
                "A complete user home cannot be quarantined; choose its sensitive subdirectories."
            )
        if ".safehalt-quarantine" in resolved.parts:
            raise SafeHaltError("SafeHalt's quarantine area cannot be configured as a target.")
        if os.path.ismount(resolved):
            raise SafeHaltError("Mount points cannot be quarantined.")

        path_stat = resolved.lstat()
        if stat.S_ISLNK(path_stat.st_mode):
            raise SafeHaltError("Symbolic links are not allowed.")
        home_uid = home.stat().st_uid
        if path_stat.st_uid != home_uid:
            raise SafeHaltError("Targets must be owned by the account that owns the home.")
        return resolved

    @staticmethod
    def _overlap(first: Path, second: Path) -> bool:
        return first == second or first in second.parents or second in first.parents

    def add(self, raw: str) -> Path:
        candidate = self.validate_candidate(raw)
        payload = self.load()
        existing = [Path(item) for item in payload["paths"]]
        if any(self._overlap(candidate, item) for item in existing):
            raise SafeHaltError("The target duplicates or overlaps a configured path.")
        self.save_paths([*payload["paths"], str(candidate)])
        return candidate

    def remove(self, raw: str) -> Path:
        expanded = self._expand_operator_home(raw)
        candidate = Path(os.path.abspath(expanded))
        payload = self.load()
        if str(candidate) not in payload["paths"]:
            raise SafeHaltError("That exact path is not configured.")
        self.save_paths([item for item in payload["paths"] if item != str(candidate)])
        return candidate

    def validated_paths(self) -> list[Path]:
        payload = self.load()
        paths = [self.validate_candidate(item) for item in payload["paths"]]
        for index, first in enumerate(paths):
            for second in paths[index + 1 :]:
                if self._overlap(first, second):
                    raise SafeHaltError("Configured paths overlap.")
        return paths
