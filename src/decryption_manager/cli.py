from __future__ import annotations

import getpass
import os
import re
from datetime import datetime
from pathlib import Path

from .auth import AuthManager
from .gpg_adapter import GpgAdapter
from .io_utils import read_csv_rows, write_csv_rows
from .key_vault import KeyVault
from .platform_open import open_folder
from .transform import flatten_value, payload_to_dict

DELETE_CONFIRMATION_TEXT = "I understand these keys will be deleted forever and won't be recoverable."

ASCII_BANNER = r"""
  ____                                    _____  __  __
 / ___|__ _ _ ____   ____ _ ___ ___ _ __ |  __ \|  \/  | 
| |   / _` | '_ \ \ / / _` / __/ __| '__/| |  \ | \  / |
| |__| (_| | | | \ V / (_| \__ \__ \ |   | |__/ | |\/| |
 \____\__,_|_| |_|\_/ \__,_|___/___/_|   |_____/|_|  |_|
 
"""


def print_error(message: str) -> None:
    print(f"\033[41;97m {message} \033[0m")


def print_success(message: str) -> None:
    print(f"\033[42;97m {message} \033[0m")

def print_banner() -> None:
    print(ASCII_BANNER)


def normalize_input_path(raw_path: str) -> str:
    cleaned = raw_path.strip().strip('"').strip("'")
    if os.name == "nt":
        return cleaned

    windows_path_match = re.match(r"^([a-zA-Z]):\\", cleaned)
    if not windows_path_match:
        return cleaned

    drive = windows_path_match.group(1).lower()
    remainder = cleaned[2:].lstrip("\\").replace("\\", "/")
    return f"/mnt/{drive}/{remainder}"


def data_dir() -> Path:
    env_path = os.getenv("CDM_DATA_DIR")
    if env_path:
        return Path(env_path)
    return Path.home() / ".canvassr_decryption_manager"


def run() -> None:
    print_banner()
    base_dir = data_dir()
    auth = AuthManager(base_dir)
    vault = KeyVault(base_dir)
    gpg = GpgAdapter()

    if not auth.exists():
        print("No password configured. Create one now.")
        new_password = prompt_new_password()
        auth.initialize(new_password)
        print_success("Password initialized.")

    app_password = login(auth)

    while True:
        print("\nStart menu:")
        print("1. Manage keys")
        print("2. Decrypt Canvassr file")
        print("3. Change password")
        print("4. Exit")
        choice = input("Select option: ").strip()

        if choice == "1":
            handle_manage_keys(vault, gpg, app_password)
        elif choice == "2":
            handle_decrypt(vault, gpg, app_password)
        elif choice == "3":
            app_password = handle_change_password(auth, vault, app_password)
        elif choice == "4":
            print("Goodbye.")
            return
        else:
            print_error("Invalid option.")


def prompt_new_password() -> str:
    while True:
        p1 = getpass.getpass("New password: ")
        p2 = getpass.getpass("Confirm password: ")
        if len(p1) < 8:
            print("Password must be at least 8 characters.")
            continue
        if p1 != p2:
            print("Passwords do not match.")
            continue
        return p1


def login(auth: AuthManager) -> str:
    while True:
        password = getpass.getpass("Password: ")
        if auth.verify(password):
            return password
        print("Incorrect password.")


def handle_change_password(auth: AuthManager, vault: KeyVault, app_password: str) -> str:
    current = getpass.getpass("Enter current password: ")
    if current != app_password:
        print_error("Current password is incorrect.")
        return app_password
    new_password = prompt_new_password()
    try:
        vault.reencrypt_all_keys(app_password, new_password)
        auth.update_password(app_password, new_password)
        print_success("Password changed successfully.")
        return new_password
    except Exception as exc:  # noqa: BLE001
        print_error(f"Failed to change password: {exc}")
        return app_password


def handle_manage_keys(vault: KeyVault, gpg: GpgAdapter, app_password: str) -> None:
    while True:
        print("\nManage keys:")
        print("1. View keys")
        print("2. Import existing keys")
        print("3. Create new keys")
        print("4. Back")
        choice = input("Select option: ").strip()
        if choice == "1":
            action = handle_view_keys(vault, app_password)
            if action == "start_menu":
                return
        elif choice == "2":
            handle_import_key(vault, gpg, app_password)
            return
        elif choice == "3":
            handle_create_key(vault, gpg, app_password)
            return
        elif choice == "4":
            return
        else:
            print_error("Invalid option.")


def handle_view_keys(vault: KeyVault, app_password: str) -> str | None:
    while True:
        keys = vault.list_keys(app_password)
        if not keys:
            print_error("No keys to view")
            return None
        print("\nView keys:")
        for idx, key in enumerate(keys, start=1):
            print(f"{idx}. {key['nickname']}")
        back_option = len(keys) + 1
        menu_option = len(keys) + 2
        print(f"{back_option}. Back")
        print(f"{menu_option}. Start menu")
        choice = input("Select option: ").strip()
        if not choice.isdigit():
            print_error("Invalid option.")
            continue
        selected = int(choice)
        if selected == back_option:
            return None
        if selected == menu_option:
            return "start_menu"
        if 1 <= selected <= len(keys):
            action = show_selected_key(vault, app_password, keys[selected - 1])
            if action == "start_menu":
                return "start_menu"
        else:
            print_error("Invalid option.")


def show_selected_key(vault: KeyVault, app_password: str, key: dict) -> str | None:
    while True:
        print(f"\nSelected key: {key['nickname']}")
        print("1. View public key")
        print("2. View private key")
        print("3. Delete key pair")
        print("4. Back")
        print("5. Start menu")
        choice = input("Select option: ").strip()
        if choice == "1":
            print(key["public_key"])
        elif choice == "2":
            print(key["private_key"])
        elif choice == "3":
            if delete_key_pair_flow(vault, app_password, key["nickname"]):
                return None
        elif choice in {"4", "5"}:
            if choice == "5":
                return "start_menu"
            return None
        else:
            print_error("Invalid option.")


def delete_key_pair_flow(vault: KeyVault, app_password: str, nickname: str) -> bool:
    print_error(
        "Are you absolutely sure you want to continue, these keys will be deleted forever and won't be recoverable."
    )
    print("1. Yes Delete them")
    print("2. No go back")
    first_choice = input("Select option: ").strip()
    if first_choice != "1":
        return False

    print("Type the exact message below to confirm deletion:")
    print(DELETE_CONFIRMATION_TEXT)
    typed = input("Confirmation: ").strip()
    if typed != DELETE_CONFIRMATION_TEXT:
        print_error("Exact confirmation text did not match. Key pair was not deleted.")
        return False

    deleted = vault.delete_key(app_password, nickname)
    if deleted:
        print_success(f'Key pair "{nickname}" deleted successfully.')
        return True
    print_error("Key pair could not be deleted.")
    return False


def read_multiline(prompt: str) -> str:
    print(prompt)
    print("Paste the full key block, then press Enter.")
    print("Finish by pasting the PGP END line or typing END on its own line.")
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == "END":
            break
        lines.append(line)
        if "-----END PGP" in line:
            break
    if not lines:
        return ""
    return "\n".join(lines).strip() + "\n"


def handle_import_key(vault: KeyVault, gpg: GpgAdapter, app_password: str) -> None:
    nickname = input("Enter key nickname: ").strip()
    if not nickname:
        print_error("Key nickname cannot be empty.")
        return
    public_key = read_multiline("Enter public key value:")
    private_key = read_multiline("Enter private key value:")
    if not public_key or not private_key:
        print_error("Public and private key values are required.")
        return
    key_passphrase = getpass.getpass("Enter key passphrase (leave blank if none): ")
    if not gpg.validate_keypair(public_key, private_key):
        print_error("Key pair validation failed.")
        return
    try:
        vault.add_key(app_password, nickname, public_key, private_key, key_passphrase)
    except Exception as exc:  # noqa: BLE001
        print_error(f"Failed to import key: {exc}")
        return
    print_success("Key added successfully.")


def handle_create_key(vault: KeyVault, gpg: GpgAdapter, app_password: str) -> None:
    nickname = input("Enter nickname of new key: ").strip()
    try:
        existing = [k["nickname"] for k in vault.list_keys(app_password)]
        if nickname in existing:
            print_error("Nickname already in use.")
            return
        public_key, private_key = gpg.generate_keypair(nickname)
        vault.add_key(app_password, nickname, public_key, private_key, "")
        print_success(f"Key ({nickname}) created successfully.")
    except Exception as exc:  # noqa: BLE001
        print_error(f"Failed to create key: {exc}")


def select_key(keys: list[dict]) -> dict | None:
    if not keys:
        return None
    if len(keys) == 1:
        return keys[0]
    print("Select key to use for decryption:")
    for idx, key in enumerate(keys, start=1):
        print(f"{idx}. {key['nickname']}")
    while True:
        choice = input("Select key number: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(keys):
            return keys[int(choice) - 1]
        print_error("Invalid option.")


def handle_decrypt(vault: KeyVault, gpg: GpgAdapter, app_password: str) -> None:
    keys = vault.list_keys(app_password)
    if not keys:
        print_error("No keys available. Import or create a key first.")
        return
    selected_key = select_key(keys)
    if selected_key is None:
        print_error("No key selected.")
        return

    file_location = input("Enter file location: ").strip()
    normalized_input = normalize_input_path(file_location)
    csv_path = Path(normalized_input).expanduser()

    if not normalized_input:
        print_error("CSV path is empty.")
        return

    if normalized_input != file_location:
        print(f"Detected wrapped quotes. Normalized path: {normalized_input}")

    if not csv_path.exists():
        print_error("CSV file not found.")
        print(f"Resolved path: {csv_path.resolve()}")
        print(f"Current working directory: {Path.cwd()}")
        return

    if not csv_path.is_file():
        print_error("Path exists but is not a file.")
        print(f"Resolved path: {csv_path.resolve()}")
        return

    if csv_path.suffix.lower() != ".csv":
        print_error("Path is not a .csv file.")
        print(f"Resolved path: {csv_path.resolve()}")
        print(f"Detected extension: {csv_path.suffix or '(none)'}")
        return

    encrypted_column = input("Encrypted column name [encrypted_response]: ").strip() or "encrypted_response"
    output_dir_input = input("Output folder [./output]: ").strip() or "./output"
    output_dir = Path(output_dir_input).expanduser().resolve()

    rows = read_csv_rows(csv_path)
    if not rows:
        print_error("CSV has no rows.")
        return

    decrypted_dicts: list[dict] = []
    failed_count = 0
    expanded_headers: set[str] = set()
    for row in rows:
        cipher = row.get(encrypted_column, "")
        if not cipher:
            failed_count += 1
            decrypted_dicts.append({})
            continue
        try:
            decrypted = gpg.decrypt(cipher, selected_key["private_key"], selected_key.get("key_passphrase", ""))
            mapped = payload_to_dict(decrypted)
            expanded_headers.update(mapped.keys())
            decrypted_dicts.append(mapped)
        except Exception:  # noqa: BLE001
            failed_count += 1
            decrypted_dicts.append({})

    output_rows: list[dict[str, str]] = []
    original_headers = [h for h in rows[0].keys() if h != encrypted_column]
    sorted_expanded = sorted(expanded_headers)
    for row, expanded in zip(rows, decrypted_dicts, strict=False):
        out: dict[str, str] = {}
        for key in original_headers:
            out[key] = flatten_value(row.get(key))
        for key in sorted_expanded:
            out[key] = flatten_value(expanded.get(key))
        output_rows.append(out)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"decrypted_{timestamp}.csv"
    write_csv_rows(output_file, original_headers + sorted_expanded, output_rows)

    resolved_output = output_file.resolve()
    print_success(f"Output written to: {resolved_output}")
    if str(resolved_output).startswith("/workspace/"):
        host_equivalent = Path.cwd() / resolved_output.relative_to("/workspace")
        print(f"Host-equivalent path: {host_equivalent}")

    opened = open_folder(output_dir)
    if not opened:
        if str(Path.cwd()) == "/workspace":
            print_error("Could not open folder automatically inside container environment.")
            print("Open the output folder from host using the path shown above.")
        else:
            print_error("Could not open folder automatically on this system.")
    print_success(f"Processed: {len(rows)} | Succeeded: {len(rows) - failed_count} | Failed: {failed_count}")


if __name__ == "__main__":
    run()
