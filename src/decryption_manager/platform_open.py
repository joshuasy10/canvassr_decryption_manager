from __future__ import annotations

import platform
import subprocess
from pathlib import Path


def open_folder(path: Path) -> bool:
    try:
        system = platform.system().lower()
        if "windows" in system:
            subprocess.run(["explorer.exe", str(path)], check=False)  # noqa: S603,S607
        elif "darwin" in system:
            subprocess.run(["open", str(path)], check=False)  # noqa: S603,S607
        else:
            subprocess.run(["xdg-open", str(path)], check=False)  # noqa: S603,S607
        return True
    except Exception:  # noqa: BLE001
        return False
