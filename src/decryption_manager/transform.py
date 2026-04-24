from __future__ import annotations

import json
from typing import Any


def payload_to_dict(payload_text: str) -> dict[str, Any]:
    parsed = json.loads(payload_text)
    if isinstance(parsed, dict):
        return parsed
    if isinstance(parsed, list):
        out: dict[str, Any] = {}
        for item in parsed:
            if isinstance(item, dict) and "name" in item:
                out[str(item["name"])] = item.get("answer")
        return out
    raise ValueError("Unsupported decrypted payload format.")


def flatten_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=True)
    return str(value)
