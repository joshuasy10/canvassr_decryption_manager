from pathlib import Path

import decryption_manager.cli as cli


def test_run_routes_main_menu_options(monkeypatch, tmp_path: Path) -> None:
    calls: list[str] = []

    class FakeAuth:
        def __init__(self, _base_dir: Path) -> None:
            pass

        def exists(self) -> bool:
            return True

        def verify(self, password: str) -> bool:
            return password == "app-pass"

    class FakeVault:
        def __init__(self, _base_dir: Path) -> None:
            pass

    class FakeGpg:
        pass

    inputs = iter(["1", "2", "3", "4"])
    passwords = iter(["app-pass", "old-pass", "new-pass-1", "new-pass-1"])

    monkeypatch.setattr(cli, "AuthManager", FakeAuth)
    monkeypatch.setattr(cli, "KeyVault", FakeVault)
    monkeypatch.setattr(cli, "GpgAdapter", FakeGpg)
    monkeypatch.setattr(cli, "data_dir", lambda: tmp_path)
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(cli.getpass, "getpass", lambda _prompt="": next(passwords))
    monkeypatch.setattr(cli, "handle_manage_keys", lambda *_args: calls.append("manage"))
    monkeypatch.setattr(cli, "handle_decrypt", lambda *_args: calls.append("decrypt"))
    monkeypatch.setattr(cli, "handle_change_password", lambda *_args: (calls.append("change"), "app-pass")[1])

    cli.run()
    assert calls == ["manage", "decrypt", "change"]


def test_handle_decrypt_requires_existing_keys(monkeypatch, capsys) -> None:
    class EmptyVault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return []

    cli.handle_decrypt(EmptyVault(), object(), "app-pass")
    captured = capsys.readouterr()
    assert "No keys available" in captured.out


def test_handle_view_keys_no_keys_message(capsys) -> None:
    class EmptyVault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return []

    cli.handle_view_keys(EmptyVault(), "app-pass")
    captured = capsys.readouterr()
    assert "No keys to view" in captured.out


def test_read_multiline_accepts_end_sentinel(monkeypatch) -> None:
    values = iter(["line-1", "line-2", "END"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(values))
    text = cli.read_multiline("Enter value")
    assert text == "line-1\nline-2\n"


def test_delete_key_pair_flow_success(monkeypatch, capsys) -> None:
    class Vault:
        def __init__(self) -> None:
            self.deleted: list[str] = []

        def delete_key(self, _app_password: str, nickname: str) -> bool:
            self.deleted.append(nickname)
            return True

    vault = Vault()
    values = iter(["1", cli.DELETE_CONFIRMATION_TEXT])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(values))

    result = cli.delete_key_pair_flow(vault, "app-pass", "key-1")
    captured = capsys.readouterr()
    assert result is True
    assert vault.deleted == ["key-1"]
    assert "deleted successfully" in captured.out


def test_delete_key_pair_flow_wrong_confirmation(monkeypatch, capsys) -> None:
    class Vault:
        def delete_key(self, _app_password: str, _nickname: str) -> bool:
            return True

    values = iter(["1", "wrong text"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(values))

    result = cli.delete_key_pair_flow(Vault(), "app-pass", "key-1")
    captured = capsys.readouterr()
    assert result is False
    assert "did not match" in captured.out


def test_show_selected_key_start_menu_returns_flag(monkeypatch) -> None:
    class Vault:
        def delete_key(self, _app_password: str, _nickname: str) -> bool:
            return False

    values = iter(["5"])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(values))
    out = cli.show_selected_key(Vault(), "app-pass", {"nickname": "k", "public_key": "p", "private_key": "s"})
    assert out == "start_menu"
