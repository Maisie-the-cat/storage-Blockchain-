# BlockVault — Local Immutable Blockchain File Vault

**Installer script:** `install.sh`

A single-script installer that scaffolds and installs BlockVault — a local, AES‑encrypted file vault backed by a simple Proof‑of‑Work blockchain and MySQL persistence. The repository currently contains the installer (Shell) which writes the full Python application into an install directory (default: `/opt/blockchain_vault`).

## Features

- AES‑256‑CBC encryption at rest (PBKDF2-HMAC-SHA256, 600k iterations).
- Proof‑of‑Work (configurable difficulty) used as a simple tamper-evidence mechanism.
- MySQL backend for block metadata and chain-level metadata.
- Web UI (Flask) + small REST API for browsing, upload, verify, and download.
- Systemd service and logrotate configuration for production-style runs.

## Quick start (recommended)

1. Review the installer (`install.sh`) to understand all actions it will perform — it requires root and will modify system configuration (MySQL, systemd, /etc/*).

2. Make installer executable and run it as root on a Debian/Ubuntu-style host:

```bash
chmod +x install.sh
sudo ./install.sh
```

The script will:
- Install system packages (python3, MySQL, build tools).
- Create a Python virtual environment and install dependencies.
- Configure MySQL and create the `blockchain_vault` database and required tables.
- Generate strong random credentials and save them to `/opt/blockchain_vault/.vault_credentials` (mode 600).
- Write the Python application into `/opt/blockchain_vault` and install a systemd unit at `/etc/systemd/system/blockvault.service`.

3. Start the service:

```bash
sudo systemctl enable --now blockvault
sudo systemctl status blockvault
```

4. Visit the web UI (default):

```
http://127.0.0.1:5050
```

Health check:

```
curl http://127.0.0.1:5050/health
```

## What the installer creates

Top-level layout (under the install dir, default `/opt/blockchain_vault`):

```
blockchain/           # Python package (core, encryption, storage, database)
web/                  # Flask app, templates, and static assets
venv/                 # Python virtualenv used to run the app
data/                 # uploads/ and encrypted_store/ directories
run.sh                # convenience script to start the app via venv
requirements.txt      # Python dependencies
UNINSTALL.sh          # helper to remove systemd/logrotate entries (data preserved)
.vault_credentials    # generated credentials (mode 600)
```

Runtime shape: the Flask app instantiates DatabaseBackend → Blockchain → FileVault. Uploading a file triggers Blockchain.mine(...) which encrypts the file, writes an encrypted blob to `data/encrypted_store`, and records block metadata in MySQL (`blocks` table). Verification recomputes hashes and attempts decryption to validate file integrity.

## Configuration

- Default install dir: `/opt/blockchain_vault` (change in `install.sh` before running if you need a different location).
- Web host/port default: `127.0.0.1:5050`.
- Generated credentials (MySQL root, app user, and VAULT_PASSWORD) are written to `.vault_credentials`. Back this up securely — losing VAULT_PASSWORD means you cannot decrypt stored files.

## Security & operational notes

- The installer runs as root and writes systemd and logrotate files. Audit the script before running on production systems.
- The installer sets the MySQL root password and user authentication method (`mysql_native_password`). If your host uses a different MySQL configuration, review/adjust the SQL section in the installer.
- The vault password and MySQL credentials are generated randomly and saved to `.vault_credentials`. Treat this file as a secret (mode 600) and back it up to a secure secret store.
- AES keys are derived with PBKDF2 (600k iterations) and a salt stored in the database (`chain_meta.encryption_salt`). Do not change the salt on an existing deployment unless you export/rotate keys correctly.
- The app uses a basic PoW mechanism for tamper evidence — it is not a production blockchain consensus layer. The design is intended for local immutability checks and provenance tracking only.

## Development

If you want this project under version control as the Python app (instead of distributing it as a single installer script), extract the files written by `install.sh` (they live under the install directory after running). I can also help split the generated files into repo-tracked `blockchain/` and `web/` directories and add a development Makefile/README for local runs without system modifications.

## License

See LICENSE in the repository root.

---

If you want, I can now:
- Add the app files (blockchain/, web/) into this repo as regular files so the project is version-controlled, or
- Produce a minimal CONTRIBUTING.md and SECURITY.md, or
- Run a quick security review of `install.sh` and the generated Python sources.

Tell me which of those you'd like next.
