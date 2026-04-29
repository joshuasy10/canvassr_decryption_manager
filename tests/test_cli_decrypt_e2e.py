import csv
from datetime import datetime as real_datetime
from pathlib import Path

import decryption_manager.cli as cli


class FixedDateTime:
    @staticmethod
    def now() -> real_datetime:
        return real_datetime(2026, 1, 2, 3, 4, 5)


def test_handle_decrypt_expands_json_into_columns(monkeypatch, tmp_path: Path) -> None:
    source_csv = tmp_path / "input.csv"
    with source_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["row_id", "encrypted_response"])
        writer.writeheader()
        writer.writerow({"row_id": "1", "encrypted_response": "cipher-1"})
        writer.writerow({"row_id": "2", "encrypted_response": "cipher-2"})

    class Vault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return [{"nickname": "key1", "private_key": "priv", "key_passphrase": ""}]

    class Gpg:
        def decrypt(self, ciphertext: str, _private_key: str, _key_passphrase: str) -> str:
            if ciphertext == "cipher-1":
                return '{"first_name":"Jane","age":31}'
            return '[{"name":"first_name","answer":"John"},{"name":"city","answer":"London"}]'

    output_dir = tmp_path / "output"
    inputs = iter([str(source_csv), "encrypted_response", str(output_dir)])
    opened: list[Path] = []

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(cli, "open_folder", lambda path: opened.append(path) or True)
    monkeypatch.setattr(cli, "datetime", FixedDateTime)

    cli.handle_decrypt(Vault(), Gpg(), "app-pass")

    expected_output = output_dir / "decrypted_input_20260102_030405.csv"
    assert expected_output.exists()
    assert opened and opened[0] == output_dir.resolve()

    with expected_output.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["row_id"] == "1"
    assert rows[0]["first_name"] == "Jane"
    assert rows[0]["age"] == "31"
    assert rows[1]["first_name"] == "John"
    assert rows[1]["city"] == "London"


def test_handle_decrypt_writes_list_answer_as_json_text(monkeypatch, tmp_path: Path) -> None:
    source_csv = tmp_path / "input_lists.csv"
    with source_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["row_id", "encrypted_response"])
        writer.writeheader()
        writer.writerow({"row_id": "1", "encrypted_response": "cipher-list"})

    class Vault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return [{"nickname": "key1", "private_key": "priv", "key_passphrase": ""}]

    class Gpg:
        def decrypt(self, ciphertext: str, _private_key: str, _key_passphrase: str) -> str:
            assert ciphertext == "cipher-list"
            return '[{"name":"communication_methods","answer":["email","sms"]}]'

    output_dir = tmp_path / "output"
    inputs = iter([str(source_csv), "encrypted_response", str(output_dir)])

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(cli, "open_folder", lambda _path: True)
    monkeypatch.setattr(cli, "datetime", FixedDateTime)

    cli.handle_decrypt(Vault(), Gpg(), "app-pass")

    expected_output = output_dir / "decrypted_input_lists_20260102_030405.csv"
    with expected_output.open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))

    assert rows[0]["communication_methods"] == '["email", "sms"]'


def test_handle_decrypt_extracts_signature_png_files(monkeypatch, tmp_path: Path) -> None:
    source_csv = tmp_path / "input_signatures.csv"
    with source_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["row_id", "encrypted_response"])
        writer.writeheader()
        writer.writerow({"row_id": "1", "encrypted_response": "cipher-1"})
        writer.writerow({"row_id": "2", "encrypted_response": "cipher-2"})

    signature_data_url = (
        "data:image/png;base64,"
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVQIHWP4////fwAJ+wP9KobjigAAAABJRU5ErkJggg=="
    )
    signature_data_url_with_whitespace = (
        "data:image/png;base64, "
        "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlE "
        "QVQIHWP4////fwAJ+wP9KobjigAAAABJRU5ErkJggg=="
    )

    class Vault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return [{"nickname": "key1", "private_key": "priv", "key_passphrase": ""}]

    class Gpg:
        def decrypt(self, ciphertext: str, _private_key: str, _key_passphrase: str) -> str:
            if ciphertext == "cipher-1":
                return (
                    '[{"name":"donor_signature","answer":"'
                    + signature_data_url_with_whitespace
                    + '"},{"name":"final_signature","answer":"'
                    + signature_data_url
                    + '"}]'
                )
            return '[{"name":"disclosure_signature","answer":"' + signature_data_url + '"}]'

    output_dir = tmp_path / "output"
    inputs = iter([str(source_csv), "encrypted_response", str(output_dir)])

    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(cli, "open_folder", lambda _path: True)
    monkeypatch.setattr(cli, "datetime", FixedDateTime)

    cli.handle_decrypt(Vault(), Gpg(), "app-pass")

    signatures_dir = output_dir / "decrypted_input_signatures_20260102_030405_signatures"
    assert signatures_dir.exists()
    assert (signatures_dir / "1_1.png").exists()
    assert (signatures_dir / "1_2.png").exists()
    assert (signatures_dir / "2_1.png").exists()
