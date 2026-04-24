from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path


class AuthManager:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.config_path = data_dir / "auth.json"

    def exists(self) -> bool:
        return self.config_path.exists()

    def initialize(self, password: str) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        salt = os.urandom(16)
        payload = {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "password_hash": self._password_hash(password, salt),
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def verify(self, password: str) -> bool:
        config = self._load()
        salt = base64.b64decode(config["salt"])
        expected = config["password_hash"]
        return self._password_hash(password, salt) == expected

    def update_password(self, old_password: str, new_password: str) -> None:
        if not self.verify(old_password):
            raise ValueError("Current password is incorrect.")
        new_salt = os.urandom(16)
        payload = {
            "salt": base64.b64encode(new_salt).decode("utf-8"),
            "password_hash": self._password_hash(new_password, new_salt),
        }
        self.config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def _load(self) -> dict:
        if not self.config_path.exists():
            raise FileNotFoundError("Auth configuration does not exist.")
        return json.loads(self.config_path.read_text(encoding="utf-8"))

    @staticmethod
    def _password_hash(password: str, salt: bytes) -> str:
        digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return base64.b64encode(digest).decode("utf-8")
