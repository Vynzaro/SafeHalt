"""Reversible, same-filesystem path quarantine."""

from __future__ import annotations

import os
from pathlib import Path
import re
import secrets
import stat
import time
from typing import Any

from .config import PathConfig, _is_inside
from .errors import SafeHaltError
from .storage import atomic_root_json, load_root_json


ACTIVATION_PATTERN = re.compile(r"^[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}$")


class QuarantineManager:
    def __init__(
        self,
        config: PathConfig,
        manifest_dir: Path = Path("/var/lib/safehalt/manifests"),
        quarantine_base: Path | None = None,
        trusted_uid: int = 0,
    ) -> None:
        self.config = config
        self.manifest_dir = manifest_dir
        self.quarantine_base = quarantine_base
        self.trusted_uid = trusted_uid

    def _base_for_home(self, home: Path) -> Path:
        if self.quarantine_base is not None:
            return self.quarantine_base
        return home.parent / ".safehalt-quarantine"

    def _secure_directory(self, path: Path) -> None:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(path, 0o700)
        path_stat = path.stat()
        if path_stat.st_uid != self.trusted_uid or stat.S_IMODE(path_stat.st_mode) != 0o700:
            raise SafeHaltError(f"Unsafe quarantine directory: {path}")

    def _prepare_roots(self, paths: list[Path]) -> None:
        bases: set[Path] = set()
        for source in paths:
            home = self.config.home_for_path(source)
            parent = home.parent
            parent_stat = parent.stat()
            if parent_stat.st_uid != self.trusted_uid or parent_stat.st_mode & 0o022:
                raise SafeHaltError(
                    f"Home parent must be root-owned and not group/world writable: {parent}"
                )
            base = self._base_for_home(home)
            if base.is_symlink():
                raise SafeHaltError(f"Quarantine base cannot be a symbolic link: {base}")
            bases.add(base)
        for base in bases:
            self._secure_directory(base)
        self._secure_directory(self.manifest_dir)

    def _manifest_path(self, activation_id: str) -> Path:
        if not ACTIVATION_PATTERN.fullmatch(activation_id):
            raise SafeHaltError("Invalid activation identifier.")
        return self.manifest_dir / f"{activation_id}.json"

    def _write_manifest(self, manifest: dict[str, Any]) -> None:
        atomic_root_json(self._manifest_path(str(manifest["activation_id"])), manifest)

    def activate(self) -> str:
        paths = self.config.validated_paths()
        if not paths:
            raise SafeHaltError("The quarantine password has no configured target paths.")

        self._prepare_roots(paths)
        activation_id = (
            time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-" + secrets.token_hex(4)
        )
        items: list[dict[str, Any]] = []
        activation_roots: dict[Path, Path] = {}
        for source in paths:
            home = self.config.home_for_path(source)
            base = self._base_for_home(home)
            activation_root = activation_roots.get(base)
            if activation_root is None:
                activation_root = base / activation_id
                self._secure_directory(activation_root)
                activation_roots[base] = activation_root
            activation_device = activation_root.stat().st_dev
            source_stat = source.lstat()
            if source_stat.st_dev != activation_device:
                raise SafeHaltError(
                    f"Target is on another filesystem and cannot be moved atomically: {source}"
                )
            relative = source.relative_to(home)
            destination = activation_root / home.name / relative
            if destination.exists():
                raise SafeHaltError(f"Unexpected quarantine collision: {destination}")
            items.append(
                {
                    "source": str(source),
                    "destination": str(destination),
                    "home": str(home),
                    "quarantine_base": str(base),
                    "device": source_stat.st_dev,
                    "inode": source_stat.st_ino,
                    "state": "pending",
                }
            )

        manifest: dict[str, Any] = {
            "format": 1,
            "activation_id": activation_id,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "moving",
            "items": items,
        }
        self._write_manifest(manifest)

        moved: list[dict[str, Any]] = []
        try:
            for item in items:
                source = Path(item["source"])
                destination = Path(item["destination"])
                current = source.lstat()
                if current.st_dev != item["device"] or current.st_ino != item["inode"]:
                    raise SafeHaltError(f"Target changed during activation: {source}")
                self._secure_directory(destination.parent)
                os.rename(source, destination)
                item["state"] = "quarantined"
                moved.append(item)
                self._write_manifest(manifest)
        except Exception as exc:
            rollback_errors: list[str] = []
            for item in reversed(moved):
                source = Path(item["source"])
                destination = Path(item["destination"])
                try:
                    if source.exists():
                        raise SafeHaltError(f"Rollback source already exists: {source}")
                    os.rename(destination, source)
                    item["state"] = "rolled_back"
                except Exception as rollback_exc:
                    rollback_errors.append(str(rollback_exc))
            manifest["status"] = "rollback_failed" if rollback_errors else "rolled_back"
            self._write_manifest(manifest)
            message = f"Quarantine failed; activation {activation_id} was recorded."
            if rollback_errors:
                message += " Manual recovery is required: " + "; ".join(rollback_errors)
            raise SafeHaltError(message) from exc

        manifest["status"] = "quarantined"
        self._write_manifest(manifest)
        return activation_id

    def list_manifests(self) -> list[dict[str, Any]]:
        if not self.manifest_dir.exists():
            return []
        result: list[dict[str, Any]] = []
        for path in sorted(self.manifest_dir.glob("*.json")):
            try:
                manifest = load_root_json(path)
            except SafeHaltError:
                continue
            result.append(
                {
                    "activation_id": manifest.get("activation_id", path.stem),
                    "status": manifest.get("status", "unknown"),
                    "created_utc": manifest.get("created_utc", "unknown"),
                    "items": len(manifest.get("items", [])),
                }
            )
        return result

    def recover(self, activation_id: str) -> int:
        manifest = load_root_json(self._manifest_path(activation_id))
        if manifest.get("activation_id") != activation_id:
            raise SafeHaltError("Manifest identifier mismatch.")
        items = manifest.get("items")
        if not isinstance(items, list):
            raise SafeHaltError("Damaged recovery manifest.")

        paths_to_prepare = [
            Path(str(item.get("source", "")))
            for item in items
            if isinstance(item, dict)
        ]
        self._prepare_roots(paths_to_prepare)
        recovered = 0
        for item in items:
            if not isinstance(item, dict) or item.get("state") not in {
                "quarantined",
                "recovery_failed",
            }:
                continue
            source = Path(str(item.get("source", "")))
            destination = Path(str(item.get("destination", "")))
            try:
                home = Path(str(item.get("home", ""))).resolve(strict=True)
                expected_base = self._base_for_home(home).resolve(strict=True)
                recorded_base = Path(
                    str(item.get("quarantine_base", expected_base))
                ).resolve(strict=True)
                if recorded_base != expected_base:
                    raise SafeHaltError("Recovery quarantine base mismatch.")
                activation_root = (expected_base / activation_id).resolve(strict=True)
                resolved_destination = destination.resolve(strict=True)
                lexical_source = Path(os.path.abspath(source))
                if not _is_inside(resolved_destination, activation_root):
                    raise SafeHaltError("Recovery destination escaped quarantine root.")
                if not _is_inside(lexical_source, home) or lexical_source == home:
                    raise SafeHaltError("Recovery source escaped its recorded user home.")
                if source.exists():
                    raise SafeHaltError(f"Recovery source already exists: {source}")
                if not source.parent.exists():
                    raise SafeHaltError(f"Recovery parent does not exist: {source.parent}")
                os.rename(resolved_destination, source)
                item["state"] = "recovered"
                recovered += 1
            except Exception as exc:
                item["state"] = "recovery_failed"
                item["error"] = str(exc)
                manifest["status"] = "recovery_failed"
                self._write_manifest(manifest)
                raise SafeHaltError(
                    f"Recovery stopped at {source}; review activation {activation_id}."
                ) from exc
            self._write_manifest(manifest)

        manifest["status"] = "recovered"
        manifest["recovered_utc"] = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ", time.gmtime()
        )
        self._write_manifest(manifest)
        return recovered
