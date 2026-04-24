from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path


class GpgAdapter:
    def validate_keypair(self, public_key: str, private_key: str) -> bool:
        with tempfile.TemporaryDirectory() as tmp:
            gnupg_home = Path(tmp) / "gnupg"
            gnupg_home.mkdir(parents=True, exist_ok=True)
            pub_ok = self._import_key(gnupg_home, public_key)
            sec_ok = self._import_key(gnupg_home, private_key)
            if not pub_ok or not sec_ok:
                return False
            fingerprints = self._list_secret_fingerprints(gnupg_home)
            return len(fingerprints) > 0

    def generate_keypair(self, nickname: str) -> tuple[str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            gnupg_home = Path(tmp) / "gnupg"
            gnupg_home.mkdir(parents=True, exist_ok=True)

            batch = f"""
            %no-protection
            Key-Type: RSA
            Key-Length: 2048
            Name-Real: {nickname}
            Name-Email: {nickname.replace(' ', '_').lower()}@local.invalid
            Expire-Date: 0
            %commit
            """
            batch_path = Path(tmp) / "batch.conf"
            batch_path.write_text(batch.strip() + "\n", encoding="utf-8")

            self._run(
                [
                    "gpg",
                    "--batch",
                    "--homedir",
                    str(gnupg_home),
                    "--generate-key",
                    str(batch_path),
                ]
            )
            fingerprint = self._list_secret_fingerprints(gnupg_home)[0]
            public_key = self._run(
                ["gpg", "--batch", "--homedir", str(gnupg_home), "--armor", "--export", fingerprint]
            ).stdout
            private_key = self._run(
                ["gpg", "--batch", "--homedir", str(gnupg_home), "--armor", "--export-secret-keys", fingerprint]
            ).stdout
            return public_key, private_key

    def decrypt(self, ciphertext: str, private_key: str, key_passphrase: str = "") -> str:
        with tempfile.TemporaryDirectory() as tmp:
            gnupg_home = Path(tmp) / "gnupg"
            gnupg_home.mkdir(parents=True, exist_ok=True)
            self._import_key(gnupg_home, private_key)
            command = ["gpg", "--batch", "--yes", "--homedir", str(gnupg_home), "--decrypt"]
            if key_passphrase:
                command.extend(["--pinentry-mode", "loopback", "--passphrase", key_passphrase])
            completed = self._run(command, input_text=ciphertext)
            return completed.stdout

    def _import_key(self, gnupg_home: Path, key_value: str) -> bool:
        try:
            self._run(
                ["gpg", "--batch", "--yes", "--homedir", str(gnupg_home), "--import"],
                input_text=key_value,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _list_secret_fingerprints(self, gnupg_home: Path) -> list[str]:
        completed = self._run(
            [
                "gpg",
                "--batch",
                "--homedir",
                str(gnupg_home),
                "--with-colons",
                "--list-secret-keys",
            ]
        )
        fingerprints: list[str] = []
        for line in completed.stdout.splitlines():
            parts = line.split(":")
            if parts and parts[0] == "fpr" and len(parts) > 9:
                fingerprints.append(parts[9])
        return fingerprints

    @staticmethod
    def _run(command: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
