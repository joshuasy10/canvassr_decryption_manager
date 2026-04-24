from pathlib import Path

from decryption_manager.auth import AuthManager
from decryption_manager.key_vault import KeyVault


def test_auth_initialize_verify_and_change_password(tmp_path: Path) -> None:
    auth = AuthManager(tmp_path)
    auth.initialize("old-password")
    assert auth.verify("old-password")
    assert not auth.verify("bad-password")
    auth.update_password("old-password", "new-password")
    assert auth.verify("new-password")
    assert not auth.verify("old-password")


def test_key_vault_reencrypt_all_keys(tmp_path: Path) -> None:
    vault = KeyVault(tmp_path)
    vault.add_key("pass1", "key1", "pub", "priv", "")
    assert vault.list_keys("pass1")[0]["nickname"] == "key1"
    vault.reencrypt_all_keys("pass1", "pass2")
    assert vault.list_keys("pass2")[0]["nickname"] == "key1"


def test_key_vault_delete_key(tmp_path: Path) -> None:
    vault = KeyVault(tmp_path)
    vault.add_key("pass1", "key1", "pub1", "priv1", "")
    vault.add_key("pass1", "key2", "pub2", "priv2", "")
    assert vault.delete_key("pass1", "key1")
    names = [entry["nickname"] for entry in vault.list_keys("pass1")]
    assert names == ["key2"]
