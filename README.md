# Canvassr Decryption Manager

Python CLI for decrypting Canvassr encrypted CSV payloads into user-friendly expanded CSV output.

## Quick Start (Non-Technical)

If you just want to download and run it like a normal app:

1. Open the latest release page: [Download Latest Release](https://github.com/joshuasy10/canvassr_decryption_manager/releases/latest)
2. Under **Assets**, download:
   - `canvassr-decryption-manager.exe` (Windows)
3. **Windows only:** install Gpg4win (includes Kleopatra) from [gpg4win.org/download](https://www.gpg4win.org/download.html).
4. Double-click the `.exe` file to run.

If Windows SmartScreen appears, click **More info** -> **Run anyway**.

## Features

- First-launch password setup and login gate.
- Menu-driven workflow:
  - Manage keys
  - Decrypt Canvassr file
  - Change password
  - Exit
- Key management:
  - View keys
  - Import existing keypair
  - Create new keypair
- CSV decrypt pipeline:
  - reads encrypted CSV
  - decrypts each row
  - expands decrypted JSON into separate output columns
  - extracts signature `data:image/png;base64,...` values to PNG files
  - replaces signature values in CSV with PNG filenames
  - writes timestamped output CSV
  - attempts to open output folder automatically
- Docker-first dependency/runtime management.
- Packaging scripts for Linux binary and Windows `.exe`.

## Requirements

- Docker + Docker Compose (for containerized run)
- OR Python 3.11+ and `gpg` installed (for local run)

## Run with Docker

```bash
docker compose build
docker compose run --rm decryption-manager
```

Data is stored in `./data` via mounted volume.

## Run with Docker (dev mode, no rebuild for code changes)

Use this for faster local iteration when editing Python code:

```bash
docker compose -f docker-compose.dev.yml build
docker compose -f docker-compose.dev.yml run --rm decryption-manager-dev
```

Notes:

- Source is mounted from your host, so code edits apply on next run without image rebuild.
- Dependencies are preinstalled in a cached dev image, so startup is much faster after the initial build.
- Rebuild only when dependency definitions change (for example `pyproject.toml` changes).

## Local development setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
pytest
```

## Menu flow

Main menu:

1. Manage keys
2. Decrypt Canvassr file
3. Change password
4. Exit

If multiple keys exist, decrypt flow requires key selection.  
If no keys exist, user is prompted to import/create key first.

## Decryption output format

Given an input file:

- `campaign_some-charity_export_20260429_194234.csv`

The decrypt flow writes:

- CSV: `decrypted_campaign_some-charity_export_20260429_194234_<timestamp>.csv`
- Signatures folder: `decrypted_campaign_some-charity_export_20260429_194234_<timestamp>_signatures/`

Signature behavior:

- Any decrypted field value matching `data:image/png;base64,...` is saved as a PNG.
- PNG files are named per record/signature order: `<record_number>_<signature_number>.png` (for example `1_1.png`, `1_2.png`, `2_1.png`).
- The corresponding CSV field value is replaced with the PNG filename (for example `1_1.png`) instead of the full base64 payload.
- Non-signature fields remain flattened as normal CSV values.

## Packaging

### Linux

```bash
bash scripts/build_linux.sh
```

Artifacts:

- `dist/canvassr-decryption-manager`
- `dist/SHA256SUMS`

### Windows

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\build_windows.ps1
```

Artifacts:

- `dist/canvassr-decryption-manager.exe`
- `dist/SHA256SUMS`

## Install from packaged binaries

### Windows (.exe)

1. Download `canvassr-decryption-manager.exe` from the [Latest Release](https://github.com/joshuasy10/canvassr_decryption_manager/releases/latest).
2. Install Gpg4win (Kleopatra package) from [gpg4win.org/download](https://www.gpg4win.org/download.html).
3. (Recommended) Verify checksum against `SHA256SUMS`.
4. Save the `.exe` somewhere permanent, for example:
   - `C:\Program Files\CanvassrDecryptionManager\`
5. Double-click the `.exe` to run, or run it from PowerShell:

```powershell
.\canvassr-decryption-manager.exe
```

Notes:

- On first run, Windows SmartScreen may warn because the binary is unsigned.
- Click `More info` -> `Run anyway` (or code-sign the executable for production distribution).
- The tool stores local data in its configured data directory and will prompt for first-time password setup.
- Gpg4win/Kleopatra is required on Windows because this build uses the system `gpg.exe`.

### Linux (binary)

1. Download `canvassr-decryption-manager` and `SHA256SUMS` from the [Releases page](https://github.com/joshuasy10/canvassr_decryption_manager/releases).
2. Verify checksum.
3. Mark executable and run:

```bash
chmod +x canvassr-decryption-manager
./canvassr-decryption-manager
```

Optional install to PATH:

```bash
sudo mv canvassr-decryption-manager /usr/local/bin/
canvassr-decryption-manager
```

### Optional: verify checksum

Windows (PowerShell):

```powershell
Get-FileHash .\canvassr-decryption-manager.exe -Algorithm SHA256
```

Linux:

```bash
sha256sum canvassr-decryption-manager
```

## Publish public binaries on GitHub

This repository includes a release workflow at `.github/workflows/release-binaries.yml` that:

- builds Linux and Windows binaries
- creates a GitHub Release
- uploads binaries + checksums as Release assets

To trigger a public release (for a public repo), push a version tag:

```bash
git tag v0.1.0
git push origin v0.1.0
```

After CI completes, binaries will be available publicly under the repository's Releases page.

Release links:

- [Releases page](https://github.com/joshuasy10/canvassr_decryption_manager/releases)
- [Latest release](https://github.com/joshuasy10/canvassr_decryption_manager/releases/latest)

## Security notes

- Private keys are stored encrypted at rest in the local vault.
- App password is hashed and verified locally.
- Password changes re-encrypt stored key material; keys are not regenerated.
- Decrypted payloads are not persisted to logs.
