from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet


class KeyVault:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.vault_path = data_dir / "keys.json"

    def list_keys(self, app_password: str) -> list[dict[str, Any]]:
        records = self._load_records()
        keys: list[dict[str, Any]] = []
        for record in records:
            keys.append(self._decrypt_record(record, app_password))
        return keys

    def add_key(
        self,
        app_password: str,
        nickname: str,
        public_key: str,
        private_key: str,
        key_passphrase: str = "",
    ) -> None:
        records = self._load_records()
        existing = [self._decrypt_record(record, app_password)["nickname"] for record in records]
        if nickname in existing:
            raise ValueError(f'Key nickname "{nickname}" is already used.')
        payload = {
            "nickname": nickname,
            "public_key": public_key,
            "private_key": private_key,
            "key_passphrase": key_passphrase,
        }
        records.append(self._encrypt_record(payload, app_password))
        self._save_records(records)

    def reencrypt_all_keys(self, old_password: str, new_password: str) -> None:
        records = self._load_records()
        decrypted = [self._decrypt_record(record, old_password) for record in records]
        reencrypted = [self._encrypt_record(record, new_password) for record in decrypted]
        self._save_records(reencrypted)

    def delete_key(self, app_password: str, nickname: str) -> bool:
        records = self._load_records()
        remaining: list[dict[str, str]] = []
        deleted = False
        for record in records:
            decrypted = self._decrypt_record(record, app_password)
            if decrypted.get("nickname") == nickname:
                deleted = True
                continue
            remaining.append(record)
        if deleted:
            self._save_records(remaining)
        return deleted

    def _load_records(self) -> list[dict[str, str]]:
        if not self.vault_path.exists():
            return []
        return json.loads(self.vault_path.read_text(encoding="utf-8"))

    def _save_records(self, records: list[dict[str, str]]) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.vault_path.write_text(json.dumps(records, indent=2), encoding="utf-8")

    def _derive_fernet(self, password: str, salt: bytes) -> Fernet:
        key = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**14,
            r=8,
            p=1,
            dklen=32,
        )
        return Fernet(base64.urlsafe_b64encode(key))

    def _encrypt_record(self, record: dict[str, Any], app_password: str) -> dict[str, str]:
        salt = os.urandom(16)
        fernet = self._derive_fernet(app_password, salt)
        token = fernet.encrypt(json.dumps(record).encode("utf-8"))
        return {
            "salt": base64.b64encode(salt).decode("utf-8"),
            "token": token.decode("utf-8"),
        }

    def _decrypt_record(self, encrypted: dict[str, str], app_password: str) -> dict[str, Any]:
        salt = base64.b64decode(encrypted["salt"])
        fernet = self._derive_fernet(app_password, salt)
        try:
            decrypted = fernet.decrypt(encrypted["token"].encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise ValueError("Failed to unlock stored keys. Password may be incorrect.") from exc
        return json.loads(decrypted.decode("utf-8"))
