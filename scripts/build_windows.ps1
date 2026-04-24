$ErrorActionPreference = "Stop"

python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install . pyinstaller
pyinstaller --clean --noconfirm decryption_manager.spec
Get-FileHash .\dist\canvassr-decryption-manager.exe -Algorithm SHA256 | ForEach-Object {
  "$($_.Hash)  canvassr-decryption-manager.exe"
} | Out-File -Encoding ascii .\dist\SHA256SUMS
Write-Host "Built: dist/canvassr-decryption-manager.exe"
