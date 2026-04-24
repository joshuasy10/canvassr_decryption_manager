from decryption_manager.transform import flatten_value, payload_to_dict


def test_payload_to_dict_from_dict() -> None:
    out = payload_to_dict('{"first_name":"Jane","active":true}')
    assert out["first_name"] == "Jane"
    assert out["active"] is True


def test_payload_to_dict_from_name_answer_list() -> None:
    out = payload_to_dict('[{"name":"email","answer":"x@y.com"},{"name":"age","answer":30}]')
    assert out == {"email": "x@y.com", "age": 30}


def test_flatten_value_handles_nested() -> None:
    assert flatten_value({"a": 1}).startswith("{")


def test_payload_to_dict_preserves_list_answer() -> None:
    out = payload_to_dict(
        '[{"name":"communication_methods","answer":["email","sms"]}]'
    )
    assert out == {"communication_methods": ["email", "sms"]}


def test_flatten_value_handles_list() -> None:
    assert flatten_value(["email", "sms"]) == '["email", "sms"]'
