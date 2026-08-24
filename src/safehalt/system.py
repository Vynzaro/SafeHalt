"""Conservative host actions selected from detected Linux capabilities."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
from typing import Sequence

from .platform import SystemProfile, detect_system


ACTION_TIMEOUT_SECONDS = 8
NFT_FAMILY = "inet"
NFT_TABLE = "safehalt_lockdown"
RUNTIME_DIR = Path("/run/safehalt")
NFT_MARKER = RUNTIME_DIR / "nft-backend-active"


def run_action(argv: Sequence[str]) -> tuple[bool, str]:
    executable = argv[0]
    if shutil.which(executable) is None:
        return False, f"{executable} was not found"
    try:
        result = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            timeout=ACTION_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{executable}: {exc}"
    if result.returncode != 0:
        detail = result.stderr.strip() or f"exit code {result.returncode}"
        return False, f"{executable}: {detail}"
    return True, "ok"


def _nft_table_exists() -> bool:
    ok, _ = run_action(["nft", "list", "table", NFT_FAMILY, NFT_TABLE])
    return ok


def _nft_delete_table() -> tuple[bool, str]:
    if not _nft_table_exists():
        NFT_MARKER.unlink(missing_ok=True)
        return True, "already inactive"
    ok, detail = run_action(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE])
    if ok:
        NFT_MARKER.unlink(missing_ok=True)
    return ok, detail


def _nft_isolate() -> tuple[bool, str]:
    if _nft_table_exists():
        if NFT_MARKER.exists():
            return True, "already active"
        return False, f"nft table {NFT_FAMILY} {NFT_TABLE} already exists"

    commands = (
        ["nft", "add", "table", NFT_FAMILY, NFT_TABLE],
        [
            "nft", "add", "chain", NFT_FAMILY, NFT_TABLE, "input", "{",
            "type", "filter", "hook", "input", "priority", "-300", ";",
            "policy", "drop", ";", "}",
        ],
        [
            "nft", "add", "rule", NFT_FAMILY, NFT_TABLE, "input",
            "iifname", "lo", "accept",
        ],
        [
            "nft", "add", "chain", NFT_FAMILY, NFT_TABLE, "output", "{",
            "type", "filter", "hook", "output", "priority", "-300", ";",
            "policy", "drop", ";", "}",
        ],
        [
            "nft", "add", "rule", NFT_FAMILY, NFT_TABLE, "output",
            "oifname", "lo", "accept",
        ],
    )
    created = False
    for command in commands:
        ok, detail = run_action(command)
        if not ok:
            if created:
                run_action(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE])
            return False, detail
        created = True
    try:
        RUNTIME_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
        NFT_MARKER.touch(mode=0o600, exist_ok=True)
    except OSError as exc:
        run_action(["nft", "delete", "table", NFT_FAMILY, NFT_TABLE])
        return False, f"could not record nft activation: {exc}"
    return True, "ok"


def network_off(profile: SystemProfile | None = None) -> tuple[bool, str]:
    selected = profile or detect_system()
    if selected.network_backend == "networkmanager":
        ok, detail = run_action(["nmcli", "networking", "off"])
        if ok or selected.network_fallback != "nftables":
            return ok, detail
        fallback_ok, fallback_detail = _nft_isolate()
        if fallback_ok:
            return True, "NetworkManager failed; nftables fallback activated"
        return False, f"{detail}; nftables fallback: {fallback_detail}"
    if selected.network_backend == "nftables":
        return _nft_isolate()
    return False, "no supported network isolation backend"


def network_on(profile: SystemProfile | None = None) -> tuple[bool, str]:
    selected = profile or detect_system()
    failures: list[str] = []
    attempted = False
    if NFT_MARKER.exists():
        attempted = True
        ok, detail = _nft_delete_table()
        if not ok:
            failures.append(detail)
    if selected.network_backend == "networkmanager":
        attempted = True
        ok, detail = run_action(["nmcli", "networking", "on"])
        if not ok:
            failures.append(detail)
    if failures:
        return False, "; ".join(failures)
    if not attempted:
        return False, "no SafeHalt network state or recovery backend was found"
    return True, "ok"


def lock_sessions(profile: SystemProfile | None = None) -> tuple[bool, str]:
    selected = profile or detect_system()
    if selected.session_backend == "login1":
        return run_action(["loginctl", "lock-sessions"])
    return False, "no supported session locking backend"


def poweroff(profile: SystemProfile | None = None) -> tuple[bool, str]:
    selected = profile or detect_system()
    commands: dict[str, list[str]] = {
        "systemd": ["systemctl", "poweroff", "--no-wall"],
        "login1": ["loginctl", "poweroff"],
        "openrc": ["openrc-shutdown", "-p", "now"],
        "runit": ["runit-init", "0"],
        "dinit": ["dinitctl", "shutdown"],
        "shutdown": ["shutdown", "-h", "now"],
    }
    command = commands.get(selected.power_backend or "")
    if command is None:
        return False, "no supported clean power-off backend"
    return run_action(command)


def root_luks_state() -> str:
    if shutil.which("findmnt") is None or shutil.which("lsblk") is None:
        return "unknown"
    try:
        source = subprocess.check_output(
            ["findmnt", "-no", "SOURCE", "/"], text=True, timeout=3
        ).strip()
        source = source.split("[", 1)[0]
        if not source.startswith("/dev/"):
            return "unknown"
        output = subprocess.check_output(
            ["lsblk", "-s", "-n", "-o", "FSTYPE", source],
            text=True,
            timeout=3,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    return "yes" if "crypto_LUKS" in output.split() else "no"
