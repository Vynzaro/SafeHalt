"""Capability-based Linux platform detection.

Distribution metadata is intentionally descriptive.  Mutating actions are
selected from detected host capabilities instead of distro names.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import platform as stdlib_platform
import shutil
import subprocess
from typing import Callable, Mapping, Sequence


Which = Callable[[str], str | None]
Probe = Callable[[Sequence[str]], bool]


@dataclass(frozen=True)
class Distribution:
    id: str
    name: str
    version_id: str
    id_like: tuple[str, ...]
    family: str
    package_ecosystem: str


@dataclass(frozen=True)
class SystemProfile:
    distribution: Distribution
    kernel: str
    architecture: str
    init: str
    network_backend: str | None
    network_fallback: str | None
    session_backend: str | None
    power_backend: str | None
    lockdown_supported: bool
    warnings: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


FAMILIES: tuple[tuple[str, frozenset[str], str], ...] = (
    (
        "rhel",
        frozenset({"fedora", "rhel", "centos", "rocky", "almalinux"}),
        "rpm",
    ),
    (
        "suse",
        frozenset({"suse", "opensuse", "opensuse-leap", "opensuse-tumbleweed", "sles"}),
        "rpm",
    ),
    (
        "debian",
        frozenset({"debian", "ubuntu", "linuxmint", "pop", "kali", "raspbian"}),
        "deb",
    ),
    (
        "arch",
        frozenset({"arch", "manjaro", "endeavouros", "artix"}),
        "pacman",
    ),
    ("alpine", frozenset({"alpine"}), "apk"),
    ("gentoo", frozenset({"gentoo"}), "portage"),
    ("void", frozenset({"void"}), "xbps"),
    ("nixos", frozenset({"nixos"}), "nix"),
)


def parse_os_release(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value.replace(r"\$", "$").replace(r'\"', '"').replace(r"\\", "\\")
    return values


def classify_distribution(values: Mapping[str, str]) -> Distribution:
    distro_id = values.get("ID", "unknown").lower()
    id_like = tuple(item.lower() for item in values.get("ID_LIKE", "").split())
    candidates = (distro_id, *id_like)
    family = "unknown"
    package_ecosystem = "unknown"
    for family_name, members, ecosystem in FAMILIES:
        if any(candidate in members for candidate in candidates):
            family = family_name
            package_ecosystem = ecosystem
            break
    return Distribution(
        id=distro_id,
        name=values.get("PRETTY_NAME", values.get("NAME", distro_id)),
        version_id=values.get("VERSION_ID", "unknown"),
        id_like=id_like,
        family=family,
        package_ecosystem=package_ecosystem,
    )


def read_distribution(path: Path = Path("/etc/os-release")) -> Distribution:
    try:
        values = parse_os_release(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError):
        values = {}
    return classify_distribution(values)


def _read_init_comm(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8").strip().lower()
    except (OSError, UnicodeError):
        return "unknown"


def detect_init(
    *,
    init_comm: str,
    which: Which,
    systemd_booted: bool,
) -> str:
    known = {
        "systemd": "systemd",
        "openrc-init": "openrc",
        "runit": "runit",
        "runit-init": "runit",
        "s6-svscan": "s6",
        "dinit": "dinit",
    }
    if init_comm in known:
        return known[init_comm]
    if systemd_booted and which("systemctl"):
        return "systemd"
    if which("rc-service") and which("openrc-shutdown"):
        return "openrc"
    if which("runit-init"):
        return "runit"
    if which("dinitctl"):
        return "dinit"
    if which("s6-rc"):
        return "s6"
    return "unknown"


def _select_power_backend(init: str, which: Which) -> str | None:
    if init == "systemd" and which("systemctl"):
        return "systemd"
    if init == "openrc" and which("openrc-shutdown"):
        return "openrc"
    if init == "runit" and which("runit-init"):
        return "runit"
    if init == "dinit" and which("dinitctl"):
        return "dinit"
    if which("shutdown"):
        return "shutdown"
    return None


def probe_command(argv: Sequence[str]) -> bool:
    try:
        result = subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def detect_system(
    *,
    os_release_path: Path = Path("/etc/os-release"),
    init_comm_path: Path = Path("/proc/1/comm"),
    systemd_marker: Path = Path("/run/systemd/system"),
    which: Which = shutil.which,
    probe: Probe = probe_command,
) -> SystemProfile:
    distribution = read_distribution(os_release_path)
    init = detect_init(
        init_comm=_read_init_comm(init_comm_path),
        which=which,
        systemd_booted=systemd_marker.is_dir(),
    )

    networkmanager_ready = bool(which("nmcli")) and probe(
        ["nmcli", "-t", "-f", "RUNNING", "general"]
    )
    if networkmanager_ready:
        network_backend = "networkmanager"
        network_fallback = "nftables" if which("nft") else None
    elif which("nft"):
        network_backend = "nftables"
        network_fallback = None
    else:
        network_backend = None
        network_fallback = None

    login1_ready = bool(which("loginctl")) and probe(
        ["loginctl", "list-sessions", "--no-legend"]
    )
    session_backend = "login1" if login1_ready else None
    power_backend = _select_power_backend(init, which)
    if power_backend is None and login1_ready:
        power_backend = "login1"

    warnings: list[str] = []
    if distribution.family == "unknown":
        warnings.append("unknown distribution family; generic packaging guidance only")
    if init == "unknown":
        warnings.append("unknown init system")
    if network_backend is None:
        warnings.append("no supported network isolation backend (nmcli or nft)")
    if session_backend is None:
        warnings.append("no login1-compatible session locking backend")
    if power_backend is None:
        warnings.append("no supported clean power-off backend")

    return SystemProfile(
        distribution=distribution,
        kernel=stdlib_platform.release(),
        architecture=stdlib_platform.machine() or "unknown",
        init=init,
        network_backend=network_backend,
        network_fallback=network_fallback,
        session_backend=session_backend,
        power_backend=power_backend,
        lockdown_supported=all(
            (network_backend, session_backend, power_backend)
        ),
        warnings=tuple(warnings),
    )
