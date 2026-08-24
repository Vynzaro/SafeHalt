"""Independent lockdown and quarantine credentials."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import secrets
import time
from typing import Any, Literal

from .errors import SafeHaltError
from .storage import atomic_root_json, load_root_json


Mode = Literal["lockdown", "quarantine"]
KDF_NAME = "scrypt"
KDF_N = 2**14
KDF_R = 8
KDF_P = 1
KDF_LENGTH = 32


def _derive(secret: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        secret.encode("utf-8"),
        salt=salt,
        n=KDF_N,
        r=KDF_R,
        p=KDF_P,
        dklen=KDF_LENGTH,
    )


def create_record(secret: str) -> dict[str, Any]:
    salt = secrets.token_bytes(16)
    return {
        "kdf": KDF_NAME,
        "n": KDF_N,
        "r": KDF_R,
        "p": KDF_P,
        "length": KDF_LENGTH,
        "salt": salt.hex(),
        "digest": _derive(secret, salt).hex(),
    }


def verify_record(secret: str, record: dict[str, Any]) -> bool:
    expected_parameters = {
        "kdf": KDF_NAME,
        "n": KDF_N,
        "r": KDF_R,
        "p": KDF_P,
        "length": KDF_LENGTH,
    }
    if any(record.get(key) != value for key, value in expected_parameters.items()):
        raise SafeHaltError("Unsupported or damaged credential record.")
    try:
        salt = bytes.fromhex(str(record["salt"]))
        expected = bytes.fromhex(str(record["digest"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise SafeHaltError("Damaged credential record.") from exc
    return hmac.compare_digest(_derive(secret, salt), expected)


class CredentialStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    def exists(self) -> bool:
        return self.path.exists()

    def save(self, lockdown_secret: str, quarantine_secret: str) -> None:
        if lockdown_secret == quarantine_secret:
            raise SafeHaltError("The two emergency passwords must be different.")
        payload = {
            "format": 2,
            "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "lockdown": create_record(lockdown_secret),
            "quarantine": create_record(quarantine_secret),
        }
        atomic_root_json(self.path, payload)

    def load(self) -> dict[str, Any]:
        payload = load_root_json(self.path)
        if payload.get("format") != 2:
            raise SafeHaltError("Unsupported credential file format.")
        if not isinstance(payload.get("lockdown"), dict) or not isinstance(
            payload.get("quarantine"), dict
        ):
            raise SafeHaltError("Damaged credential file.")
        return payload

    def identify(self, secret: str) -> Mode | None:
        payload = self.load()
        # Always evaluate both records to avoid revealing the selected mode by timing.
        lockdown_match = verify_record(secret, payload["lockdown"])
        quarantine_match = verify_record(secret, payload["quarantine"])
        if lockdown_match:
            return "lockdown"
        if quarantine_match:
            return "quarantine"
        return None

    def matches(self, secret: str, expected_mode: Mode) -> bool:
        payload = self.load()
        return verify_record(secret, payload[expected_mode])
