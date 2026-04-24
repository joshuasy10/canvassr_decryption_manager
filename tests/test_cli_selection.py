from decryption_manager.cli import select_key


def test_select_key_single_key_returns_immediately() -> None:
    key = {"nickname": "only-one"}
    assert select_key([key]) == key
