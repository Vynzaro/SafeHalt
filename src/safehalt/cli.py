"""SafeHalt command-line interface."""

from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
from typing import Sequence

from . import __version__
from .config import PathConfig
from .credentials import CredentialStore, Mode
from .errors import SafeHaltError
from .quarantine import QuarantineManager
from . import system


PROGRAM = "safehalt"
CONFIG_DIR = Path("/etc/safehalt")
CREDENTIAL_FILE = CONFIG_DIR / "credentials.json"
PATH_FILE = CONFIG_DIR / "paths.json"
MANIFEST_DIR = Path("/var/lib/safehalt/manifests")


def stores() -> tuple[CredentialStore, PathConfig, QuarantineManager]:
    credentials = CredentialStore(CREDENTIAL_FILE)
    path_config = PathConfig(PATH_FILE)
    quarantine = QuarantineManager(path_config, MANIFEST_DIR)
    return credentials, path_config, quarantine


def require_root() -> None:
    if os.geteuid() != 0:
        raise SafeHaltError("Run this command as root with sudo.")


def require_local_tty() -> None:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise SafeHaltError("An interactive local terminal is required.")
    if os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"):
        raise SafeHaltError("Remote activation over SSH is disabled.")


def read_new_password(label: str) -> str:
    first = getpass.getpass(f"New {label} password: ")
    second = getpass.getpass("Repeat it: ")
    if first != second:
        raise SafeHaltError("Passwords do not match.")
    if len(first) < 8:
        raise SafeHaltError("Each emergency password must have at least 8 characters.")
    if first.isspace():
        raise SafeHaltError("A password cannot contain only spaces.")
    return first


def identify_password(credentials: CredentialStore) -> Mode:
    require_local_tty()
    secret = getpass.getpass("Emergency password: ")
    mode = credentials.identify(secret)
    if mode is None:
        time.sleep(1.5)
        raise SafeHaltError("Incorrect emergency password.")
    return mode


def authenticate_quarantine(credentials: CredentialStore) -> None:
    require_local_tty()
    secret = getpass.getpass("Quarantine recovery password: ")
    if not credentials.matches(secret, "quarantine"):
        time.sleep(1.5)
        raise SafeHaltError("Incorrect quarantine password.")


def journal(message: str) -> None:
    if not shutil.which("logger"):
        return
    try:
        subprocess.run(
            ["logger", "-t", PROGRAM, "--", message],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
    except subprocess.SubprocessError:
        pass


def command_setup(force: bool) -> None:
    require_root()
    require_local_tty()
    credentials, _, _ = stores()
    if credentials.exists() and not force:
        raise SafeHaltError("Credentials already exist; use setup --force to replace them.")
    lockdown = read_new_password("lockdown")
    quarantine = read_new_password("quarantine")
    credentials.save(lockdown, quarantine)
    print("Both emergency passwords were configured.")


def command_test() -> None:
    require_root()
    credentials, _, _ = stores()
    mode = identify_password(credentials)
    print(f"Credential accepted. Selected mode: {mode}. No action was performed.")


def command_paths(action: str, path: str | None) -> None:
    require_root()
    _, config, _ = stores()
    if action == "list":
        configured = config.load()["paths"]
        if not configured:
            print("No quarantine paths are configured.")
        for item in configured:
            print(item)
        return
    if path is None:
        raise SafeHaltError("A path is required.")
    if action == "add":
        added = config.add(path)
        print(f"Added: {added}")
    elif action == "remove":
        removed = config.remove(path)
        print(f"Removed: {removed}")


def command_status() -> None:
    require_root()
    credentials, config, quarantine = stores()
    configured_paths = config.load()["paths"]
    profile = system.detect_system()
    print(f"SafeHalt version: {__version__}")
    print(f"Emergency credentials configured: {'yes' if credentials.exists() else 'no'}")
    print(f"Quarantine paths configured: {len(configured_paths)}")
    print(f"Recorded activations: {len(quarantine.list_manifests())}")
    print(f"Distribution: {profile.distribution.name}")
    print(f"Distribution family: {profile.distribution.family}")
    print(f"Init system: {profile.init}")
    print(f"Network backend: {profile.network_backend or 'unsupported'}")
    print(f"Session backend: {profile.session_backend or 'unsupported'}")
    print(f"Power backend: {profile.power_backend or 'unsupported'}")
    print(f"Lockdown supported: {'yes' if profile.lockdown_supported else 'no'}")
    print(f"Root storage chain includes LUKS: {system.root_luks_state()}")


def command_doctor(as_json: bool) -> None:
    profile = system.detect_system()
    if as_json:
        print(json.dumps(profile.to_dict(), indent=2, sort_keys=True))
        return
    distro = profile.distribution
    print(f"Distribution: {distro.name} ({distro.id})")
    print(f"Family: {distro.family}")
    print(f"Package ecosystem: {distro.package_ecosystem}")
    print(f"Kernel: Linux {profile.kernel} ({profile.architecture})")
    print(f"Init: {profile.init}")
    print(f"Network isolation: {profile.network_backend or 'unsupported'}")
    print(f"Network fallback: {profile.network_fallback or 'none'}")
    print(f"Session locking: {profile.session_backend or 'unsupported'}")
    print(f"Clean power-off: {profile.power_backend or 'unsupported'}")
    print(f"Ready for lockdown: {'yes' if profile.lockdown_supported else 'no'}")
    for warning in profile.warnings:
        print(f"Warning: {warning}")


def command_trigger() -> None:
    require_root()
    profile = system.detect_system()
    if not profile.lockdown_supported:
        details = "; ".join(profile.warnings) or "required backend unavailable"
        raise SafeHaltError(
            "This host cannot perform the complete lockdown sequence safely. "
            f"Run 'safehalt doctor' for details: {details}"
        )
    credentials, _, quarantine = stores()
    mode = identify_password(credentials)
    print(f"Authenticated {mode} mode. Starting emergency response…", flush=True)
    journal(f"Authenticated local activation: {mode}")

    warnings: list[str] = []
    ok, detail = system.network_off(profile)
    if not ok:
        raise SafeHaltError("Network isolation failed before any file move: " + detail)

    activation_id: str | None = None
    if mode == "quarantine":
        try:
            activation_id = quarantine.activate()
            journal(f"Reversible quarantine completed: {activation_id}")
        except SafeHaltError as exc:
            warnings.append(str(exc))
            journal(f"Quarantine warning: {exc}")

    ok, detail = system.lock_sessions(profile)
    if not ok:
        warnings.append(detail)

    if warnings:
        journal("Activation warnings: " + "; ".join(warnings))
    ok, detail = system.poweroff(profile)
    if not ok:
        warnings.append(detail)
        extra = f" Quarantine activation: {activation_id}." if activation_id else ""
        raise SafeHaltError(
            "Power-off failed; the machine may remain locked and offline."
            + extra
            + " Details: "
            + "; ".join(warnings)
        )


def command_network_recover() -> None:
    require_root()
    credentials, _, _ = stores()
    authenticate_quarantine(credentials)
    ok, detail = system.network_on(system.detect_system())
    if not ok:
        raise SafeHaltError("Could not restore networking: " + detail)
    journal("Authenticated local network recovery")
    print("SafeHalt network isolation was removed.")


def command_recovery_list() -> None:
    require_root()
    _, _, quarantine = stores()
    manifests = quarantine.list_manifests()
    if not manifests:
        print("No activation manifests were found.")
        return
    for item in manifests:
        print(
            f"{item['activation_id']}  {item['status']}  "
            f"{item['items']} item(s)  {item['created_utc']}"
        )


def command_recovery_run(activation_id: str) -> None:
    require_root()
    credentials, _, quarantine = stores()
    authenticate_quarantine(credentials)
    recovered = quarantine.recover(activation_id)
    journal(f"Recovered quarantine activation: {activation_id}")
    print(f"Recovered {recovered} path(s) from activation {activation_id}.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=PROGRAM,
        description="Emergency isolation and reversible file quarantine for Linux.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    setup_parser = commands.add_parser("setup", help="configure both passwords")
    setup_parser.add_argument("--force", action="store_true")
    commands.add_parser("test", help="identify a password without taking action")
    commands.add_parser("status", help="audit the local configuration")
    doctor_parser = commands.add_parser(
        "doctor", help="detect the distribution and usable host backends"
    )
    doctor_parser.add_argument("--json", action="store_true", dest="as_json")
    commands.add_parser("trigger", help="select an emergency mode by password")
    commands.add_parser("network-recover", help="remove SafeHalt network isolation")

    paths_parser = commands.add_parser("paths", help="manage quarantine targets")
    path_commands = paths_parser.add_subparsers(dest="paths_action", required=True)
    add_parser = path_commands.add_parser("add")
    add_parser.add_argument("path")
    remove_parser = path_commands.add_parser("remove")
    remove_parser.add_argument("path")
    path_commands.add_parser("list")

    recovery_parser = commands.add_parser("recovery", help="recover quarantined paths")
    recovery_commands = recovery_parser.add_subparsers(
        dest="recovery_action", required=True
    )
    recovery_commands.add_parser("list")
    recovery_run = recovery_commands.add_parser("run")
    recovery_run.add_argument("activation_id")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "setup":
            command_setup(args.force)
        elif args.command == "test":
            command_test()
        elif args.command == "status":
            command_status()
        elif args.command == "doctor":
            command_doctor(args.as_json)
        elif args.command == "trigger":
            command_trigger()
        elif args.command == "network-recover":
            command_network_recover()
        elif args.command == "paths":
            command_paths(args.paths_action, getattr(args, "path", None))
        elif args.command == "recovery" and args.recovery_action == "list":
            command_recovery_list()
        elif args.command == "recovery" and args.recovery_action == "run":
            command_recovery_run(args.activation_id)
        else:
            parser.error("unknown command")
    except SafeHaltError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
