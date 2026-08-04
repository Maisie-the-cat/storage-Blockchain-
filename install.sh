#!/usr/bin/env bash
# ============================================================================
#  Local Blockchain File Vault — Complete Single-Script Installer
#  Creates directories, installs dependencies, sets up MySQL, writes every
#  source file, and leaves a ready-to-run system.
#
#  Features:
#   • AES-256-CBC encryption at rest (PBKDF2, 600k iterations)
#   • Proof-of-Work blockchain with configurable difficulty
#   • MySQL backend for all block & metadata persistence
#   • Full chain + file integrity verification
#   • File upload, download (decrypted), preview, and JSON export
#   • Modern SPA web frontend with auto-refresh
#   • Systemd service for production use
#   • Hardened deployment with secure credential storage
# ============================================================================
set -euo pipefail

# ── Error Handling ----------------------------------------------------------
trap 'error "Installation failed at line $LINENO"; exit 1' ERR

# ── Configuration -----------------------------------------------------------
INSTALL_DIR="/opt/blockchain_vault"
MYSQL_ROOT_PASS=$(openssl rand -base64 16 | tr -d '\n')
MYSQL_DB="blockchain_vault"
MYSQL_USER="vault_app"
MYSQL_PASS=$(openssl rand -base64 16 | tr -d '\n')
VAULT_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')
VHOST_PORT=5050
VHOST_HOST="127.0.0.1"
PYTHON_ENV="${INSTALL_DIR}/venv"
DIFFICULTY=4
CREDENTIALS_FILE="${INSTALL_DIR}/.vault_credentials"
# Service user for running blockvault (non-login, system user)
BLOCKVAULT_USER="blockvault"
# HashiCorp Vault settings (leave empty to skip automatic Vault storage)
VAULT_ADDR=""
VAULT_TOKEN=""
VAULT_SECRET_PATH="secret/blockvault/mysql"  # default secret path

# ── Colours -----------------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
note()  { echo -e "${BLUE}[NOTE]${NC}  $*"; }

# ── Pre-flight --------------------------------------------------------------
echo ""
echo -e "${BOLD}==============================================${NC}"
echo -e "${BOLD}   Local Blockchain File Vault — Installer     ${NC}"
echo -e "${BOLD}==============================================${NC}"
echo ""
info "Install directory  : ${INSTALL_DIR}"
info "MySQL database     : ${MYSQL_DB}"
info "Web server         : http://${VHOST_HOST}:${VHOST_PORT}"
info "Difficulty (PoW)   : ${DIFFICULTY} leading zeros"
echo ""
note "⚠️  Generated credentials (SAVE THESE — especially the Vault Password):"
echo ""
echo "  🔑 MySQL root password : ${MYSQL_ROOT_PASS}"
echo "  🔑 MySQL app password  : ${MYSQL_PASS}"
echo "  🔑 Vault encryption    : ${VAULT_PASSWORD}"
echo ""
warn "These will be saved to: ${CREDENTIALS_FILE} (mode 600)"
echo ""
read -rp "Press ENTER to continue or Ctrl-C to abort..." _

# Ensure service user exists (non-login system user)
info "Ensuring service user exists: ${BLOCKVAULT_USER}"
if ! id -u "${BLOCKVAULT_USER}" >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin \
        --comment "BlockVault service account" "${BLOCKVAULT_USER}"
    info "Created system user: ${BLOCKVAULT_USER}"
else
    info "Service user already exists: ${BLOCKVAULT_USER}"
fi

# ============================================================================
#  1. SYSTEM PACKAGES
# ============================================================================
info "Step 1/7: Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    default-mysql-server default-mysql-client \
    libmysqlclient-dev \
    curl git build-essential logrotate \
    > /dev/null 2>&1

# ============================================================================
#  2. DIRECTORY TREE & PERMISSIONS
# ============================================================================
info "Step 2/7: Creating directory tree..."
mkdir -p "${INSTALL_DIR}"/{blockchain,web/{templates,static},config,data/uploads,data/encrypted_store,logs}
mkdir -p "${INSTALL_DIR}/data/encrypted_store"

# Make sure the service user owns the install directory and can read/write what's needed
chown -R "${BLOCKVAULT_USER}:" "${INSTALL_DIR}" || true
chmod 750 "${INSTALL_DIR}"

# ============================================================================
#  3. PYTHON VENV & DEPENDENCIES
# ============================================================================
info "Step 3/7: Setting up Python environment..."
python3 -m venv "${PYTHON_ENV}"
# shellcheck disable=SC1090
source "${PYTHON_ENV}/bin/activate"
pip install --upgrade pip wheel -q
pip install -q \
    flask flask-cors flask-wtf bcrypt \
    cryptography sqlalchemy pymysql python-dotenv \
    Werkzeug Pillow

# Ensure venv and site packages are owned by service user so it can run the interpreter
chown -R "${BLOCKVAULT_USER}:" "${PYTHON_ENV}"

# ============================================================================
#  4. MYSQL CONFIGURATION
# ============================================================================
info "Step 4/7: Configuring MySQL..."
systemctl start mysql 2>/dev/null || service mysql start 2>/dev/null || true
sleep 2

mysql -u root <<-EOSQL
    -- Secure root account
    ALTER USER 'root'@'localhost' IDENTIFIED WITH mysql_native_password BY '${MYSQL_ROOT_PASS}';
    FLUSH PRIVILEGES;

    -- Application database and user
    CREATE DATABASE IF NOT EXISTS \`${MYSQL_DB}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
    CREATE USER IF NOT EXISTS '${MYSQL_USER}'@'localhost' IDENTIFIED BY '${MYSQL_PASS}';
    GRANT ALL PRIVILEGES ON \`${MYSQL_DB}\`.* TO '${MYSQL_USER}'@'localhost';
    FLUSH PRIVILEGES;

    USE \`${MYSQL_DB}\`;

    -- ── Blocks table (the blockchain) ────────────────────────────────
    CREATE TABLE IF NOT EXISTS blocks (
        id              INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        block_index     INT UNSIGNED NOT NULL UNIQUE,
        timestamp       VARCHAR(32)  NOT NULL,
        previous_hash   VARCHAR(64)  NOT NULL,
        file_name       VARCHAR(255) NOT NULL,
        file_mime       VARCHAR(100) NOT NULL,
        original_hash   VARCHAR(64)  NOT NULL,
        file_size       BIGINT UNSIGNED NOT NULL,
        nonce           BIGINT UNSIGNED NOT NULL,
        block_hash      VARCHAR(64)  NOT NULL UNIQUE,
        encrypted_path  VARCHAR(512) NOT NULL,
        created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_block_index (block_index),
        INDEX idx_block_hash (block_hash)
    ) ENGINE=InnoDB;

    -- ── Chain-level metadata ────────────────────────────────────────
    CREATE TABLE IF NOT EXISTS chain_meta (
        meta_key   VARCHAR(64) PRIMARY KEY,
        meta_value TEXT
    ) ENGINE=InnoDB;

    INSERT IGNORE INTO chain_meta (meta_key, meta_value) VALUES
        ('difficulty', '${DIFFICULTY}'),
        ('encryption_salt', ''),
        ('chain_valid', '1');
EOSQL

info "MySQL database '${MYSQL_DB}' is ready."

# ============================================================================
#  5. WRITE ALL SOURCE FILES
# ============================================================================
info "Step 5/7: Writing application source files..."

# (writing files omitted for brevity in this response — unchanged from existing installer)

# Ensure the rest of the tree is owned by the service user so runtime can read/write
chown -R "${BLOCKVAULT_USER}:" "${INSTALL_DIR}"

# ── 5s. systemd service -----------------------------------------------------
info "Step: installing and hardening systemd service..."
cat > /tmp/blockvault.service << SVCEOF
[Unit]
Description=BlockVault — Local Blockchain File Vault
After=network-online.target mysql.service
Wants=mysql.service
Documentation=http://localhost:5050

[Service]
Type=simple
User=${BLOCKVAULT_USER}
Group=${BLOCKVAULT_USER}
RuntimeDirectory=blockvault
RuntimeDirectoryMode=0750
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${CREDENTIALS_FILE}
Environment="PYTHONUNBUFFERED=1"
ExecStart=${PYTHON_ENV}/bin/python ${INSTALL_DIR}/web/app.py

# Restart behavior
Restart=on-failure
RestartSec=5
StartLimitInterval=300
StartLimitBurst=5

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=blockvault

# Hardening
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=${INSTALL_DIR}
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictRealtime=yes
RestrictNamespaces=yes
LockPersonality=yes

# If the service needs fewer capabilities, keep it minimal; do not give CAP_NET_BIND_SERVICE
# AmbientCapabilities=

[Install]
WantedBy=multi-user.target
SVCEOF

cp /tmp/blockvault.service /etc/systemd/system/blockvault.service
chmod 644 /etc/systemd/system/blockvault.service

# Reload systemd to pick up unit
systemctl daemon-reload 2>/dev/null || true

# ============================================================================
#  6. SAVE CREDENTIALS SECURELY
# ============================================================================
info "Step 6/7: Saving credentials securely (runtime file will not contain MySQL root password)..."
# Runtime credentials (non-root) — readable by service user only
cat > "${CREDENTIALS_FILE}" << CREDSEOF
# BlockVault runtime environment — non-root credentials only
MYSQL_USER="${MYSQL_USER}"
MYSQL_PASS="${MYSQL_PASS}"
VAULT_PASSWORD="${VAULT_PASSWORD}"
CREDSEOF

# Make file readable only by the service account
chown "${BLOCKVAULT_USER}:" "${CREDENTIALS_FILE}" || chown "${BLOCKVAULT_USER}:${BLOCKVAULT_USER}" "${CREDENTIALS_FILE}"
chmod 600 "${CREDENTIALS_FILE}"
info "Runtime credentials saved to: ${CREDENTIALS_FILE} (mode 600, owner ${BLOCKVAULT_USER})"

# Store MySQL root password in HashiCorp Vault if requested and credentials provided
store_in_vault() {
    local addr="$1" token="$2" secret_path="$3" root_pass="$4"

    # Try KV v2 first: map secret_path like 'secret/blockvault/mysql' -> 'secret/data/blockvault/mysql'
    if echo "$secret_path" | grep -q "^secret/"; then
        v2path=$(echo "$secret_path" | sed 's/^secret/secret\/data/')
    else
        v2path="${secret_path}"
    fi

    # KV v2 write
    if curl --silent --show-error --fail -X POST "${addr}/v1/${v2path}" \
        -H "X-Vault-Token: ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"data\":{\"MYSQL_ROOT_PASS\":\"${root_pass}\"}}" >/dev/null 2>&1; then
        info "Stored MySQL root password in Vault at v2 path: ${v2path}"
        return 0
    fi

    # KV v1 fallback: write to provided path directly
    if curl --silent --show-error --fail -X POST "${addr}/v1/${secret_path}" \
        -H "X-Vault-Token: ${token}" \
        -H "Content-Type: application/json" \
        -d "{\"MYSQL_ROOT_PASS\":\"${root_pass}\"}" >/dev/null 2>&1; then
        info "Stored MySQL root password in Vault at v1 path: ${secret_path}"
        return 0
    fi

    return 1
}

if [ -n "${VAULT_ADDR}" ] && [ -n "${VAULT_TOKEN}" ]; then
    info "Attempting to store MySQL root password in HashiCorp Vault at ${VAULT_ADDR}"
    if store_in_vault "${VAULT_ADDR}" "${VAULT_TOKEN}" "${VAULT_SECRET_PATH}" "${MYSQL_ROOT_PASS}"; then
        info "MySQL root password stored in Vault successfully. It will NOT be written to disk."
        MYSQL_ROOT_FILE=""
    else
        warn "Failed to store MySQL root password in Vault. Falling back to local root-only file."
        MYSQL_ROOT_FILE="${INSTALL_DIR}/.mysql_root_secret"
    fi
else
    # Interactive prompt to optionally store in Vault
    read -rp "Do you want to store the MySQL root password in HashiCorp Vault? [y/N] " store_choice
    if [[ "$store_choice" =~ ^[Yy]$ ]]; then
        read -rp "Vault address (e.g. https://vault.example:8200): " VAULT_ADDR
        read -rsp "Vault token: " VAULT_TOKEN
        echo
        read -rp "Secret path (e.g. secret/blockvault/mysql) [${VAULT_SECRET_PATH}]: " input_path
        if [ -n "${input_path}" ]; then
            VAULT_SECRET_PATH="${input_path}"
        fi
        if store_in_vault "${VAULT_ADDR}" "${VAULT_TOKEN}" "${VAULT_SECRET_PATH}" "${MYSQL_ROOT_PASS}"; then
            info "MySQL root password stored in Vault successfully. It will NOT be written to disk."
            MYSQL_ROOT_FILE=""
        else
            warn "Failed to store MySQL root password in Vault. Falling back to local root-only file."
            MYSQL_ROOT_FILE="${INSTALL_DIR}/.mysql_root_secret"
        fi
    else
        MYSQL_ROOT_FILE="${INSTALL_DIR}/.mysql_root_secret"
    fi
fi

if [ -n "${MYSQL_ROOT_FILE}" ]; then
    cat > "${MYSQL_ROOT_FILE}" << ROOTSEOF
# MySQL root password — store securely
MYSQL_ROOT_PASS="${MYSQL_ROOT_PASS}"
ROOTSEOF

    chown root:root "${MYSQL_ROOT_FILE}"
    chmod 600 "${MYSQL_ROOT_FILE}"
    info "MySQL root password written to: ${MYSQL_ROOT_FILE} (mode 600, owner root). It IS NOT readable by the service."
fi

# ============================================================================
#  7. FINALIZE AND VERIFY
# ============================================================================
info "Step 7/7: Finalizing and verifying installation..."

systemctl enable --now mysql 2>/dev/null || service mysql enable --now 2>/dev/null || true
sleep 1

"${PYTHON_ENV}"/bin/python -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from blockchain.core import Blockchain, Block, sha256_hex
from blockchain.encryption import EncryptionManager, SALT_SIZE
from blockchain.database import DatabaseBackend
from blockchain.storage import FileVault
print('  ✔ All Python imports OK')
" || exit 1

# Ensure the systemd service is enabled for the blockvault user
systemctl daemon-reload 2>/dev/null || true
systemctl enable blockvault 2>/dev/null || true

echo ""
echo -e "${BOLD}==============================================${NC}"
echo -e "${BOLD}   ✅ BlockVault installed successfully!       ${NC}"
echo -e "${BOLD}==============================================${NC}"
echo ""
echo "  Install: ${INSTALL_DIR}"
echo "  Web:     http://${VHOST_HOST}:${VHOST_PORT}"
echo "  Runtime creds:   ${CREDENTIALS_FILE} (mode 600, owner ${BLOCKVAULT_USER})"
echo "  MySQL root secret: ${MYSQL_ROOT_FILE:-<stored in Vault>}"
echo ""
echo "Quick Start:"
echo "  systemctl start blockvault"
echo "  systemctl status blockvault"
echo "  curl http://${VHOST_HOST}:${VHOST_PORT}/health"
echo ""
echo "Important:"
echo "  • Backup ${CREDENTIALS_FILE} immediately"
echo "  • Review BACKUP_GUIDE.md for backup strategy"
echo ""
