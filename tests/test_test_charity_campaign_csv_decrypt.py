from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import decryption_manager.cli as cli
from decryption_manager.gpg_adapter import GpgAdapter
from decryption_manager.io_utils import read_csv_rows
from decryption_manager.transform import payload_to_dict

TEST_CHARITY_PRIVATE_KEY = """-----BEGIN PGP PRIVATE KEY BLOCK-----

lQOXBGnyO+UBCADs7xfAgvEXXC7iZ4NVzD42uQjV71Vvk/70AYOOSWCtkGlHSJVa
McyUO/vg13ZHQw/1+JPpV1D0S/F9J1gv2IHKE03bFmYpZwMjRaFe3oUc7dxVkx47
iHK3dPEKL92v6jGZIh6F07qbVKMJyL/K6NI0KE5BSYhvpYzKUjOEqDmtjl32JKOd
XQgCgDd/HVn67GxCjllSgZS8cKRAWD+Ndcmo3vxd75uuHQd/4wkjR3UXKh1Wufq7
zD+K/VdDk6s4R81xWoEn0JTq2ZiZ4LHx3W0KcAZyIy8oet2Qvk94eg7BC7biMHwk
7AsY5OtTvG/OSPPaMlIP19ELB3PktCdqYlttABEBAAEAB/j2Ahnd2aqmA5k4SfYZ
fEnAEDQcZW9w0nWqV5Dp8Cs7MbaLIaaU3zXzIO2c7rM32G9YC6Fc7X19cXK5SblR
/2ArOrnX7Q1XbQsLeVE1CbX71lom13m4KxWU+dyIe1ZGEAVO6nrchGfFbgtt9ykB
X+16hqtSsaTyymmgxEaj6SMKfJdse6IXAApeDfrdSHbZmPOkJ0yehmz8QhTLUemK
Z1vAYs6IseXvPKVZkhk45bt9OIU26M9NsMW80pJIoVRZenqTqX99iQPD114X1uCr
2u0SsUtkytsOWiKqVbGur89U3504+Fl0glRWoyD3FPAUq2Odq5TcgX7RpZ5Pvgvk
OVUEAPXSfz7zlM9Mxu4cTzhbAFAC31575GxslnUoKiOhx99mHTlOd6wLl1m4giwc
VbTOiSZ7nZOyr6ffMLG0U2M7C3hrZWjAIqYnI5HsD8qGo2CJk4SCQbnQu15I6Gm6
6gJvzzcw0DpkskawsNZwuPIoRJDCPY2lOVFvd94wvlNrBA8jBAD2vmMxIPcfuaDF
ruxzF/ahB29+OR8h8HDqpLvtJl611mX0iuB064FzrHLqMphZeXwMyvrlYsrXIXZT
bguPcSgRRCghB0voJLvCTPVdshPE6fCqYtYM4TWr6irBOorR62QpP9LD/rerXq+/
nYd3puMbcmjoQaJQjcbHBmX7SLFcLwQAvYlhrInV7UT5BZKcmCeFC4Pw3clJGwAL
zcy0XNeCP+dyvTsIFPHDU8g9zSGSxO6SUDNinQ2KeGqtac1YuoWKBYVYxI/r1erD
se1IU6DjVU8xRJG9SPxTFFSgXA5DnnflRBu4iKyFdK60LfpE5AD9+HDpT3De0Tt/
MYefIxev1FVGPrQpY2VyZWJyYS10ZXN0IDxjZXJlYnJhLXRlc3RAbG9jYWwuaW52
YWxpZD6JAW4EEwEIAFgWIQR7JNLXsVoLm/Oll46NBJK/8LwduAUCafI75RsUgAAA
AAAEAA5tYW51MiwyLjUrMS4xMiwyLDEDGy8EBQsJCAcCAiICBhUKCQgLAgQWAgMB
Ah4HAheAAAoJEI0Ekr/wvB24QpAIAM3T2mV9JALfc6nd8J89EIxGzlputrOWwSqh
ggYbM0DfoDVMf3f49k04zYJPpJQqaZoSYRPYtAUGOLzUViEHWcPsUvuWWN7MzOCO
8BUPiyDQaK2BDftLLvmdY+w1h4KiWDjqalMZ8sg/Z8Sdkb4anK5mORzO3tgAtBoA
OSRMn/+NqIfFfQodriusbdPI7bLjjxA9xakVA8rJ2MniujDc23+dPe2Nro+cLlek
VGDEHxz4uXsiqnUNAGuiq/Nul2C1YgmV2fiQLfatKoxq0AQ+n45ByKdF+3pgTIVs
HJOqImT6X8oigD6L0rdl3x9YEdZ4Zdne1sLkQAiz/LM3eI57INo=
=/PA+
-----END PGP PRIVATE KEY BLOCK-----
"""


def test_charity_campaign_csv_can_be_decrypted_with_provided_private_key() -> None:
    if shutil.which("gpg") is None:
        pytest.skip("gpg executable not available")

    csv_matches = sorted(Path(__file__).parent.glob("campaign_*_export_*.csv"))
    assert csv_matches, "Expected a campaign export CSV fixture in tests directory."
    csv_path = csv_matches[0]

    rows = read_csv_rows(csv_path)
    assert rows, "Expected at least one row in test CSV."

    ciphertext = rows[0]["encrypted_response"]
    decrypted = GpgAdapter().decrypt(ciphertext, TEST_CHARITY_PRIVATE_KEY, "")
    mapped = payload_to_dict(decrypted)

    assert isinstance(mapped.get("first_name"), str)
    assert mapped.get("first_name")
    assert isinstance(mapped.get("last_name"), str)
    assert mapped.get("last_name")


def test_handle_decrypt_prints_general_error_in_red(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    class Vault:
        def list_keys(self, _app_password: str) -> list[dict]:
            return [{"nickname": "key1", "private_key": "priv", "key_passphrase": ""}]

    class Gpg:
        def decrypt(self, ciphertext: str, _private_key: str, _key_passphrase: str) -> str:
            return ciphertext

    csv_path = tmp_path / "input.csv"
    csv_path.write_text("encrypted_response\nfoo\n", encoding="utf-8")
    inputs = iter([str(csv_path), "encrypted_response", str(tmp_path / "output")])
    monkeypatch.setattr("builtins.input", lambda _prompt="": next(inputs))
    monkeypatch.setattr(cli, "read_csv_rows", lambda _path: (_ for _ in ()).throw(RuntimeError("boom")))

    cli.handle_decrypt(Vault(), Gpg(), "app-pass")

    captured = capsys.readouterr()
    assert "\033[31mGeneral error while decrypting file: boom\033[0m" in captured.out
