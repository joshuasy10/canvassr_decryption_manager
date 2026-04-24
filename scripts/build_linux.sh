#!/usr/bin/env bash
set -euo pipefail

python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install . pyinstaller
pyinstaller --clean --noconfirm decryption_manager.spec
sha256sum dist/canvassr-decryption-manager > dist/SHA256SUMS
echo "Built: dist/canvassr-decryption-manager"
