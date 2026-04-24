from __future__ import annotations

import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path


class GpgAdapter:
    def __init__(self) -> None:
        self.gpg_executable = self._resolve_gpg_executable()

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
                    self.gpg_executable,
                    "--batch",
                    "--homedir",
                    str(gnupg_home),
                    "--generate-key",
                    str(batch_path),
                ]
            )
            fingerprint = self._list_secret_fingerprints(gnupg_home)[0]
            public_key = self._run(
                [self.gpg_executable, "--batch", "--homedir", str(gnupg_home), "--armor", "--export", fingerprint]
            ).stdout
            private_key = self._run(
                [self.gpg_executable, "--batch", "--homedir", str(gnupg_home), "--armor", "--export-secret-keys", fingerprint]
            ).stdout
            return public_key, private_key

    def decrypt(self, ciphertext: str, private_key: str, key_passphrase: str = "") -> str:
        with tempfile.TemporaryDirectory() as tmp:
            gnupg_home = Path(tmp) / "gnupg"
            gnupg_home.mkdir(parents=True, exist_ok=True)
            self._import_key(gnupg_home, private_key)
            command = [self.gpg_executable, "--batch", "--yes", "--homedir", str(gnupg_home), "--decrypt"]
            if key_passphrase:
                command.extend(["--pinentry-mode", "loopback", "--passphrase", key_passphrase])
            completed = self._run(command, input_text=ciphertext)
            return completed.stdout

    def _import_key(self, gnupg_home: Path, key_value: str) -> bool:
        try:
            self._run(
                [self.gpg_executable, "--batch", "--yes", "--homedir", str(gnupg_home), "--import"],
                input_text=key_value,
            )
            return True
        except subprocess.CalledProcessError:
            return False

    def _list_secret_fingerprints(self, gnupg_home: Path) -> list[str]:
        completed = self._run(
            [
                self.gpg_executable,
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
    def _resolve_gpg_executable() -> str:
        env_path = os.getenv("CDM_GPG_PATH")
        if env_path and Path(env_path).exists():
            return env_path

        for name in ("gpg", "gpg.exe"):
            resolved = shutil.which(name)
            if resolved:
                return resolved

        if os.name == "nt":
            common_windows_paths = [
                Path(r"C:\Program Files\GnuPG\bin\gpg.exe"),
                Path(r"C:\Program Files (x86)\GnuPG\bin\gpg.exe"),
            ]
            for path in common_windows_paths:
                if path.exists():
                    return str(path)

            raise RuntimeError(
                "GPG executable not found. Install Gpg4win (https://gpg4win.org/) "
                "or set CDM_GPG_PATH to gpg.exe."
            )

        raise RuntimeError(
            "GPG executable not found. Install GnuPG (gpg) or set CDM_GPG_PATH to the gpg binary path."
        )

    @staticmethod
    def _run(command: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603
            command,
            input=input_text,
            text=True,
            capture_output=True,
            check=True,
        )
