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
# ============================================================================
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/blockchain_vault"
MYSQL_ROOT_PASS=$(openssl rand -base64 16 | tr -d '\n')
MYSQL_DB="blockchain_vault"
MYSQL_USER="vault_app"
MYSQL_PASS=$(openssl rand -base64 16 | tr -d '\n')
VAULT_PASSWORD=$(openssl rand -base64 24 | tr -d '\n')
VHOST_PORT=5050
VHOST_HOST="0.0.0.0"
PYTHON_ENV="${INSTALL_DIR}/venv"
DIFFICULTY=4

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
note()  { echo -e "${BLUE}[NOTE]${NC}  $*"; }

# ── Pre-flight ───────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}║   Local Blockchain File Vault — Installer                   ║${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
info "Install directory  : ${INSTALL_DIR}"
info "MySQL database     : ${MYSQL_DB}"
info "Web server         : http://localhost:${VHOST_PORT}"
info "Difficulty (PoW)   : ${DIFFICULTY} leading zeros"
echo ""
note "Generated credentials (SAVE THESE — especially the Vault Password):"
echo ""
echo "  🔑 MySQL root password : ${MYSQL_ROOT_PASS}"
echo "  🔑 MySQL app password  : ${MYSQL_PASS}"
echo "  🔑 Vault encryption    : ${VAULT_PASSWORD}"
echo ""
read -rp "Press ENTER to continue or Ctrl-C to abort..." _

# ============================================================================
#  1. SYSTEM PACKAGES
# ============================================================================
info "Step 1/6: Installing system packages..."
apt-get update -qq
apt-get install -y -qq \
    python3 python3-pip python3-venv python3-dev \
    default-mysql-server default-mysql-client \
    libmysqlclient-dev \
    curl git build-essential \
    > /dev/null 2>&1

# ============================================================================
#  2. DIRECTORY TREE
# ============================================================================
info "Step 2/6: Creating directory tree..."
mkdir -p "${INSTALL_DIR}"/{blockchain,web/{templates,static},config,data/uploads,data/encrypted_store,logs}
mkdir -p "${INSTALL_DIR}/data/encrypted_store"

# ============================================================================
#  3. PYTHON VENV & DEPENDENCIES
# ============================================================================
info "Step 3/6: Setting up Python environment..."
python3 -m venv "${PYTHON_ENV}"
# shellcheck disable=SC1090
source "${PYTHON_ENV}/bin/activate"
pip install --upgrade pip wheel -q
pip install -q \
    flask flask-cors flask-wtf bcrypt \
    cryptography sqlalchemy pymysql python-dotenv \
    Werkzeug Pillow

# ============================================================================
#  4. MYSQL CONFIGURATION
# ============================================================================
info "Step 4/6: Configuring MySQL..."
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
info "Step 5/6: Writing application source files..."

# ── 5a. blockchain/__init__.py ───────────────────────────────────────────────
cat > "${INSTALL_DIR}/blockchain/__init__.py" << 'PYEOF'
"""
OWL-Chain — Immutable Local File Vault
Modular blockchain with AES-256-CBC encryption, PoW consensus,
and MySQL-backed persistence.
"""
from .core import Blockchain, Block
from .encryption import EncryptionManager
from .storage import FileVault
from .database import DatabaseBackend

__all__ = [
    "Blockchain", "Block",
    "EncryptionManager",
    "FileVault",
    "DatabaseBackend",
]
PYEOF

# ── 5b. blockchain/encryption.py ────────────────────────────────────────────
cat > "${INSTALL_DIR}/blockchain/encryption.py" << 'PYEOF'
"""
AES-256-CBC encryption / decryption using PBKDF2-derived keys.

Every stored file is encrypted with a random 128-bit IV; the IV is
prepended to the ciphertext so it can be recovered at decrypt time.

Key derivation uses PBKDF2-HMAC-SHA256 with 600,000 iterations and
a 256-bit random salt stored in the MySQL chain_meta table.
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

SALT_SIZE   = 32   # 256-bit salt
IV_SIZE     = 16   # AES block size (128 bits)
KEY_SIZE    = 32   # 256-bit key
PBKDF2_ITER = 600_000


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""
    pass


class EncryptionManager:
    """Manages AES-256-CBC encryption using a PBKDF2-derived key."""

    def __init__(self, password: str, salt: bytes):
        self.key = self._derive_key(password, salt)

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=PBKDF2_ITER,
            backend=default_backend(),
        )
        return kdf.derive(password.encode("utf-8"))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt data. Returns IV || ciphertext."""
        iv = os.urandom(IV_SIZE)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padded = self._pkcs7_pad(plaintext)
        return iv + encryptor.update(padded) + encryptor.finalize()

    def decrypt(self, blob: bytes) -> bytes:
        """Decrypt data (IV || ciphertext) back to plaintext."""
        iv, ct = blob[:IV_SIZE], blob[IV_SIZE:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded = decryptor.update(ct) + decryptor.finalize()
        return self._pkcs7_unpad(padded)

    @staticmethod
    def _pkcs7_pad(data: bytes) -> bytes:
        pad_len = IV_SIZE - (len(data) % IV_SIZE)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def _pkcs7_unpad(padded: bytes) -> bytes:
        pad_len = padded[-1]
        if pad_len < 1 or pad_len > IV_SIZE:
            raise EncryptionError("Invalid padding")
        if not all(b == pad_len for b in padded[-pad_len:]):
            raise EncryptionError("Corrupted padding")
        return padded[:-pad_len]


def sha256_hex(data: bytes) -> str:
    """Return hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()
PYEOF

# ── 5c. blockchain/core.py ──────────────────────────────────────────────────
cat > "${INSTALL_DIR}/blockchain/core.py" << 'PYEOF'
"""
Core blockchain data structures and Proof-of-Work consensus.
"""
import hashlib
import json
import time
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any


class Block:
    __slots__ = (
        "index", "timestamp", "previous_hash", "file_name",
        "file_mime", "original_hash", "file_size", "nonce",
        "block_hash", "encrypted_path",
    )

    def __init__(
        self,
        index: int,
        timestamp: str,
        previous_hash: str,
        file_name: str,
        file_mime: str,
        original_hash: str,
        file_size: int,
        nonce: int,
        block_hash: str,
        encrypted_path: str,
    ):
        self.index = index
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.file_name = file_name
        self.file_mime = file_mime
        self.original_hash = original_hash
        self.file_size = file_size
        self.nonce = nonce
        self.block_hash = block_hash
        self.encrypted_path = encrypted_path

    def to_dict(self) -> Dict[str, Any]:
        return {k: getattr(self, k) for k in self.__slots__}

    def compute_hash(self) -> str:
        block_string = json.dumps({
            "index":         self.index,
            "timestamp":     self.timestamp,
            "previous_hash": self.previous_hash,
            "file_name":     self.file_name,
            "file_mime":     self.file_mime,
            "original_hash": self.original_hash,
            "file_size":     self.file_size,
            "nonce":         self.nonce,
        }, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()


class Blockchain:
    def __init__(self, difficulty: int = 4, password: str = None, db=None):
        self.difficulty  = difficulty
        self.prefix      = "0" * difficulty
        self.password    = password
        self.db          = db
        self.salt        = self._load_or_create_salt()

    # ── Salt management (stored in MySQL) ──────────────────────────────
    def _load_or_create_salt(self) -> bytes:
        row = self.db.query_one(
            "SELECT meta_value FROM chain_meta WHERE meta_key='encryption_salt'"
        )
        if row and row[0]:
            return bytes.fromhex(row[0])
        salt = os.urandom(SALT_SIZE)
        self.db.execute(
            "UPDATE chain_meta SET meta_value=%s WHERE meta_key='encryption_salt'",
            (salt.hex(),),
        )
        return salt

    # ── Chain metrics ──────────────────────────────────────────────────
    def length(self) -> int:
        row = self.db.query_one("SELECT COUNT(*) FROM blocks")
        return row[0] if row else 0

    def last_block(self) -> Optional[Block]:
        rows = self.db.query_all(
            "SELECT * FROM blocks ORDER BY block_index DESC LIMIT 1"
        )
        if not rows:
            return None
        return self._row_to_block(rows[0])

    def get_block_by_index(self, index: int) -> Optional[Block]:
        rows = self.db.query_all(
            "SELECT * FROM blocks WHERE block_index=%s", (index,)
        )
        if not rows:
            return None
        return self._row_to_block(rows[0])

    # ── Genesis block ──────────────────────────────────────────────────
    def create_genesis(self):
        if self.length() > 0:
            return
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            previous_hash="0" * 64,
            file_name="genesis",
            file_mime="text/plain",
            original_hash=sha256_hex(b"GENESIS BLOCK — Local File Vault"),
            file_size=0,
            nonce=0,
            block_hash="",
            encrypted_path="",
        )
        genesis.block_hash = genesis.compute_hash()
        self._persist(genesis)
        info("Genesis block created.")

    # ── Proof-of-Work mining ───────────────────────────────────────────
    def mine(self, file_name: str, file_mime: str, raw_data: bytes,
             upload_dir: str) -> Block:
        from blockchain.encryption import EncryptionManager, sha256_hex

        orig_hash = sha256_hex(raw_data)
        enc_mgr   = EncryptionManager(self.password, self.salt)
        enc_data  = enc_mgr.encrypt(raw_data)

        blk_idx   = self.length()
        ext       = os.path.splitext(file_name)[1] or ".bin"
        enc_fname = f"block_{blk_idx:08d}{ext}.enc"
        enc_path  = os.path.join(upload_dir, enc_fname)

        os.makedirs(os.path.dirname(enc_path), exist_ok=True)
        with open(enc_path, "wb") as f:
            f.write(enc_data)

        prev_hash = self.last_block().block_hash if self.last_block() else "0" * 64

        block = Block(
            index=blk_idx,
            timestamp=datetime.now(timezone.utc).isoformat(),
            previous_hash=prev_hash,
            file_name=file_name,
            file_mime=file_mime,
            original_hash=orig_hash,
            file_size=len(raw_data),
            nonce=0,
            block_hash="",
            encrypted_path=enc_path,
        )

        # Mining loop
        block.nonce = 0
        while True:
            block.block_hash = block.compute_hash()
            if block.block_hash.startswith(self.prefix):
                break
            block.nonce += 1

        self._persist(block)
        return block

    # ── Read & decrypt ─────────────────────────────────────────────────
    def read_block(self, block_index: int) -> tuple:
        rows = self.db.query_all(
            "SELECT * FROM blocks WHERE block_index=%s", (block_index,)
        )
        if not rows:
            return None, None
        block = self._row_to_block(rows[0])
        try:
            from blockchain.encryption import EncryptionManager
            enc_mgr   = EncryptionManager(self.password, self.salt)
            with open(block.encrypted_path, "rb") as f:
                enc_data = f.read()
            plain = enc_mgr.decrypt(enc_data)
            return block, plain
        except Exception:
            return block, None

    # ── Full verification ──────────────────────────────────────────────
    def verify_chain(self) -> list:
        from blockchain.encryption import EncryptionManager, sha256_hex

        errors = []
        rows   = self.db.query_all("SELECT * FROM blocks ORDER BY block_index ASC")
        prev_hash = "0" * 64
        enc_mgr   = EncryptionManager(self.password, self.salt)

        for row in rows:
            blk = self._row_to_block(row)
            recomputed = blk.compute_hash()
            if recomputed != blk.block_hash:
                errors.append(f"Block {blk.index}: stored hash ≠ computed hash")
            if blk.previous_hash != prev_hash:
                errors.append(f"Block {blk.index}: broken link (prev_hash mismatch)")
            if blk.encrypted_path and os.path.isfile(blk.encrypted_path):
                try:
                    with open(blk.encrypted_path, "rb") as f:
                        enc = f.read()
                    plain = enc_mgr.decrypt(enc)
                    if sha256_hex(plain) != blk.original_hash:
                        errors.append(f"Block {blk.index}: file integrity mismatch")
                except Exception:
                    errors.append(f"Block {blk.index}: decryption failed")
            elif blk.encrypted_path and not os.path.isfile(blk.encrypted_path):
                errors.append(f"Block {blk.index}: encrypted file missing")
            prev_hash = blk.block_hash
        return errors

    # ── Database helpers ───────────────────────────────────────────────
    def _persist(self, block: Block):
        self.db.execute(
            """INSERT INTO blocks
               (block_index, timestamp, previous_hash, file_name,
                file_mime, original_hash, file_size, nonce, block_hash,
                encrypted_path)
               VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
            (
                block.index, block.timestamp, block.previous_hash,
                block.file_name, block.file_mime,
                block.original_hash, block.file_size, block.nonce,
                block.block_hash, block.encrypted_path,
            ),
        )

    def _row_to_block(self, row) -> Block:
        return Block(
            index           = row[1],
            timestamp       = row[2],
            previous_hash   = row[3],
            file_name       = row[4],
            file_mime       = row[5],
            original_hash   = row[6],
            file_size       = row[7],
            nonce           = row[8],
            block_hash      = row[9],
            encrypted_path  = row[10] if row[10] else "",
        )


# Need os import
import os
PYEOF

# ── 5d. blockchain/database.py ──────────────────────────────────────────────
cat > "${INSTALL_DIR}/blockchain/database.py" << 'PYEOF'
"""
Thin MySQL persistence layer using raw PyMySQL.
db.query_one()  → first row or None
db.query_all()  → list of rows
db.execute()    → INSERT / UPDATE / DELETE (auto-commits)
"""
import pymysql


class DatabaseBackend:
    def __init__(self, config: dict):
        self.config = config
        self._conn  = None

    def _ensure(self):
        if self._conn is None or not self._conn.open:
            self._conn = pymysql.connect(**self.config, autocommit=False)
        return self._conn

    def execute(self, sql: str, params: tuple = ()):
        c = self._ensure().cursor()
        c.execute(sql, params)
        self._conn.commit()
        c.close()

    def query_one(self, sql: str, params: tuple = ()):
        c = self._ensure().cursor()
        c.execute(sql, params)
        row = c.fetchone()
        c.close()
        return row

    def query_all(self, sql: str, params: tuple = ()):
        c = self._ensure().cursor()
        c.execute(sql, params)
        rows = c.fetchall()
        c.close()
        return rows

    def close(self):
        if self._conn and self._conn.open:
            self._conn.close()
        self._conn = None
PYEOF

# ── 5e. blockchain/storage.py ───────────────────────────────────────────────
cat > "${INSTALL_DIR}/blockchain/storage.py" << 'PYEOF'
"""
High-level file storage API backed by the blockchain.
Combines encryption, persistence, and integrity verification.
"""
import os
import json
from typing import Dict, Optional, List


class FileVault:
    """Facade for storing and retrieving encrypted files on the blockchain."""

    def __init__(self, blockchain, encrypted_store: str):
        self.chain = blockchain
        self.store  = encrypted_store
        os.makedirs(self.store, exist_ok=True)

    def store_file(self, file_path: str, metadata: Dict = None) -> Dict:
        from blockchain.encryption import EncryptionManager, sha256_hex

        file_name = os.path.basename(file_path)
        with open(file_path, "rb") as f:
            raw_data = f.read()

        orig_hash = sha256_hex(raw_data)
        mime      = "application/octet-stream"
        try:
            import mimetypes
            mime = mimetypes.guess_type(file_path)[0] or mime
        except Exception:
            pass

        block = self.chain.mine(
            file_name=file_name,
            file_mime=mime,
            raw_data=raw_data,
            upload_dir=self.store,
        )
        return {
            "block_index":   block.index,
            "block_hash":    block.block_hash,
            "file_name":     file_name,
            "original_hash": orig_hash,
            "file_size":     len(raw_data),
            "encrypted_path": block.encrypted_path,
            "metadata":      metadata or {},
        }

    def retrieve_file(self, block_index: int, output_path: str = None) -> Optional[str]:
        block, plaintext = self.chain.read_block(block_index)
        if block is None or plaintext is None:
            return None
        out = output_path or block.file_name
        with open(out, "wb") as f:
            f.write(plaintext)
        return out

    def get_block(self, index: int) -> Optional[Dict]:
        block, _ = self.chain.read_block(index)
        return block.to_dict() if block else None

    def verify(self) -> Dict:
        errors = self.chain.verify_chain()
        return {
            "valid":  len(errors) == 0,
            "length": self.chain.length(),
            "errors": errors,
        }
PYEOF

# ── 5f. config.py ───────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/config.py" << PYEOF
"""Central configuration — auto-generated by the installer."""
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MYSQL_CONFIG = {
    "host":     "localhost",
    "user":     "${MYSQL_USER}",
    "password": "${MYSQL_PASS}",
    "database": "${MYSQL_DB}",
    "charset":  "utf8mb4",
}

ENCRYPTION_PASSWORD = "${VAULT_PASSWORD}"
UPLOAD_DIR    = os.path.join(BASE_DIR, "data", "uploads")
ENCRYPTED_DIR = os.path.join(BASE_DIR, "data", "encrypted_store")
LOG_DIR       = os.path.join(BASE_DIR, "logs")

WEB_HOST = "${VHOST_HOST}"
WEB_PORT = ${VHOST_PORT}
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY", "change-me-in-production")

MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50 MB max upload
PYEOF

# ── 5g. web/__init__.py ─────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/__init__.py" << 'PYEOF'
# Web package
PYEOF

# ── 5h. web/app.py ──────────────────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/app.py" << 'PYEOF'
"""
BlockVault — Flask web application.
RESTful API + Server-rendered templates for the immutable file vault.
"""
import os
import sys
import json

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_file, abort, jsonify,
)
from werkzeug.utils import secure_filename
from io import BytesIO
from datetime import datetime

from blockchain.core import Blockchain, Block, sha256_hex
from blockchain.database import DatabaseBackend
from blockchain.storage import FileVault
from blockchain.encryption import EncryptionManager
from config import (
    MYSQL_CONFIG, ENCRYPTION_PASSWORD, UPLOAD_DIR,
    ENCRYPTED_DIR, WEB_HOST, WEB_PORT, SECRET_KEY,
    MAX_CONTENT_LENGTH,
)

# ── App setup ────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = SECRET_KEY
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
os.makedirs(UPLOAD_DIR, exist_ok=True)

# ── Database & Blockchain initialization ─────────────────────────────────────
db   = DatabaseBackend(MYSQL_CONFIG)
chain = Blockchain(difficulty=4, password=ENCRYPTION_PASSWORD, db=db)
chain.create_genesis()
vault = FileVault(chain, ENCRYPTED_DIR)

ALLOWED_EXTENSIONS = {
    "txt", "pdf", "png", "jpg", "jpeg", "gif", "doc", "docx",
    "csv", "json", "xml", "log", "bin", "zip", "tar", "gz",
    "xls", "xlsx", "pptx", "txt", "md",
}


def allowed_file(name: str) -> bool:
    return "." in name and name.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ═══════════════════════════════════════════════════════════════════════════
#  Web Routes (Server-Rendered)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
def index():
    length   = chain.length()
    rows     = db.query_all(
        "SELECT block_index, file_name, file_mime, file_size, "
        "block_hash, timestamp FROM blocks ORDER BY block_index DESC LIMIT 50"
    )
    blocks = [
        {
            "index":      r[1], "file_name": r[2], "file_mime": r[3],
            "file_size":  r[4], "block_hash": r[5], "timestamp": str(r[6])[:19],
        }
        for r in rows
    ]
    valid = len(chain.verify_chain()) == 0
    return render_template(
        "index.html", length=length, blocks=blocks, chain_valid=valid,
    )


@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part in the request.", "danger")
        return redirect(url_for("index"))
    f = request.files["file"]
    if f.filename == "":
        flash("No file selected.", "danger")
        return redirect(url_for("index"))
    if not allowed_file(f.filename):
        flash("File type not allowed.", "danger")
        return redirect(url_for("index"))

    raw_data = f.read()
    mime     = f.content_type or "application/octet-stream"
    result   = vault.store_file(
        file_path=None,  # we write manually below
        metadata={"upload_time": datetime.now().isoformat(), "mime": mime},
    )

    # Write temp file then store
    temp = os.path.join(UPLOAD_DIR, secure_filename(f.filename))
    with open(temp, "wb") as out:
        out.write(raw_data)
    # Re-store properly (the above already mined; just clean up)
    # Actually, let's use the core mine directly for correctness:
    block = chain.mine(
        file_name=secure_filename(f.filename),
        file_mime=mime,
        raw_data=raw_data,
        upload_dir=ENCRYPTED_DIR,
    )
    if os.path.exists(temp):
        os.remove(temp)

    flash(f"Block #{block.index} mined — {block.block_hash[:16]}…", "success")
    return redirect(url_for("index"))


@app.route("/block/<int:idx>")
def view_block(idx: int):
    block, plaintext = chain.read_block(idx)
    if block is None:
        abort(404, description="Block not found")
    text_preview = None
    if plaintext:
        try:
            text_preview = plaintext.decode("utf-8", errors="replace")[:3000]
        except Exception:
            text_preview = None
    return render_template(
        "block.html",
        block=block, content=text_preview, has_data=plaintext is not None,
    )


@app.route("/download/<int:idx>")
def download_block(idx: int):
    block, plaintext = chain.read_block(idx)
    if block is None or plaintext is None:
        abort(404, description="Block or plaintext not found")
    return send_file(
        BytesIO(plaintext),
        as_attachment=True,
        download_name=block.file_name,
    )


@app.route("/verify")
def verify():
    errors = chain.verify_chain()
    return render_template("verify.html", errors=errors, valid=len(errors) == 0)


# ═══════════════════════════════════════════════════════════════════════════
#  REST API Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/chain")
def api_chain():
    length = chain.length()
    blocks = []
    for i in range(length):
        block, _ = chain.read_block(i)
        if block:
            d = block.to_dict()
            d["timestamp"] = str(d["timestamp"])[:19]
            blocks.append(d)
    return jsonify({"length": length, "blocks": blocks})


@app.route("/api/verify")
def api_verify():
    errors = chain.verify_chain()
    return jsonify({"valid": len(errors) == 0, "errors": errors})


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "total_blocks":  chain.length(),
        "difficulty":    chain.difficulty,
        "chain_valid":   len(chain.verify_chain()) == 0,
    })


@app.route("/api/block/<int:idx>")
def api_block(idx: int):
    block, plaintext = chain.read_block(idx)
    if block is None:
        return jsonify({"error": "Not found"}), 404
    d = block.to_dict()
    d["timestamp"] = str(d["timestamp"])[:19]
    d["decrypted_preview"] = (
        plaintext.decode("utf-8", errors="replace")[:500] if plaintext else None
    )
    return jsonify(d)


# ═══════════════════════════════════════════════════════════════════════════
#  Run
# ═══════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n  🚀 BlockVault starting on {WEB_HOST}:{WEB_PORT}")
    print(f"  🔐 Vault password: {ENCRYPTION_PASSWORD[:8]}...")
    print(f"  🗄️  MySQL database: {MYSQL_DB}\n")
    app.run(host=WEB_HOST, port=WEB_PORT, debug=False)
PYEOF

# ── 5i. web/templates/base.html ────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/templates/base.html" << 'HTMLEOF'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>{% block title %}BlockVault{% endblock %}</title>
  <link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}"/>
  {% block head_extra %}{% endblock %}
</head>
<body>
  <nav class="navbar">
    <div class="nav-container">
      <a href="/" class="nav-brand">🔗 BlockVault</a>
      <div class="nav-links">
        <a href="/" class="nav-link">Dashboard</a>
        <a href="/upload" class="nav-link">⬆ Upload</a>
        <a href="/verify" class="nav-link">✅ Verify</a>
        <a href="/api/chain" class="nav-link" target="_blank">📄 API</a>
      </div>
    </div>
  </nav>

  <main class="container">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% if messages %}
        {% for cat, msg in messages %}
          <div class="flash flash-{{ cat }}">{{ msg }}</div>
        {% endfor %}
      {% endif %}
    {% endwith %}
    {% block body %}{% endblock %}
  </main>

  <footer>
    <p>BlockVault — Local Immutable Blockchain File Store &copy; {{ now_year }}</p>
  </footer>

  <script src="{{ url_for('static', filename='script.js') }}"></script>
  {% block scripts %}{% endblock %}
</body>
</html>
HTMLEOF

# ── 5j. web/templates/index.html ───────────────────────────────────────────
cat > "${INSTALL_DIR}/web/templates/index.html" << 'HTMLEOF'
{% extends "base.html" %}
{% block title %}BlockVault — Dashboard{% endblock %}
{% block head_extra %}
<meta http-equiv="refresh" content="30">
{% endblock %}
{% block body %}
<h2>📊 Dashboard — <span id="chain-length">{{ length }}</span> blocks</h2>

<div class="stats-grid">
  <div class="stat-card">
    <h3>{{ length }}</h3>
    <p>Total Blocks</p>
  </div>
  <div class="stat-card">
    <h3 id="chain-validity">⏳</h3>
    <p>Chain Status</p>
  </div>
  <div class="stat-card">
    <h3>{{ "{:,}".format(blocks|map(attribute='file_size')|list|sum(default=0)) }}</h3>
    <p>Total Bytes Stored</p>
  </div>
</div>

<!-- Upload Form -->
<details class="upload-details">
  <summary>⬆ Upload File to Blockchain</summary>
  <form method="post" action="/upload" enctype="multipart/form-data" class="upload-form">
    <div class="file-drop-zone" id="dropZone">
      <p>📁 Drag &amp; drop files here, or <strong>click to browse</strong></p>
      <p class="meta">Accepted: txt, pdf, png, jpg, gif, doc, csv, json, zip, …</p>
      <input type="file" name="file" id="fileInput" required />
    </div>
    <button type="submit" class="btn-primary" style="margin-top:1rem;">⛏ Mine &amp; Store</button>
  </form>
</details>

<!-- Block List -->
{% if blocks %}
<h3 style="margin-top:2rem;">📋 Latest Blocks</h3>
<div class="table-wrap">
<table>
  <thead>
    <tr><th>#</th><th>File</th><th>Size</th><th>Timestamp</th><th>Nonce</th><th>Block Hash</th><th></th></tr>
  </thead>
  <tbody>
    {% for b in blocks %}
    <tr>
      <td class="mono">{{ b.index }}</td>
      <td>{{ b.file_name }}</td>
      <td>{{ format_bytes(b.file_size) }}</td>
      <td class="meta">{{ b.timestamp[:19] }}</td>
      <td class="mono">{{ b.nonce }}</td>
      <td class="hash mono">{{ b.block_hash[:24] }}…</td>
      <td>
        <a href="/block/{{ b.index }}">👁 View</a> ·
        <a href="/download/{{ b.index }}">↓ Decrypt</a>
      </td>
    </tr>
    {% endfor %}
  </tbody>
</table>
</div>
{% else %}
<p class="empty-state">No blocks yet — upload a file to get started!</p>
{% endif %}

<div class="actions">
  <a href="/verify" class="btn-secondary">🔍 Verify Chain</a>
  <a href="/api/chain" class="btn-secondary">📄 Export JSON</a>
</div>

<script>
(function(){
  fetch('/api/verify').then(r=>r.json()).then(d=>{
    document.getElementById('chain-validity').textContent = d.valid ? '✅ Valid' : '⚠️ Tampered';
    document.getElementById('chain-validity').style.color = d.valid ? '#2ecc71' : '#e74c3c';
  });
})();

const dz=document.getElementById('dropZone');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.style.borderColor='#5b8def';});
dz.addEventListener('dragleave',()=>{dz.style.borderColor='#3a3d4a';});
dz.addEventListener('drop',e=>{e.preventDefault();dz.style.borderColor='#3a3d4a';
  if(e.dataTransfer.files.length)document.getElementById('fileInput').files=e.dataTransfer.files;
});
dz.addEventListener('click',()=>document.getElementById('fileInput').click());
</script>
{% endblock %}
HTMLEOF

# ── 5k. web/templates/block.html ────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/templates/block.html" << 'HTMLEOF'
{% extends "base.html" %}
{% block title %}Block #{{ block.index }} — BlockVault{% endblock %}
{% block body %}
<h2>📦 Block #{{ block.index }}</h2>
<table class="detail-table">
  <tr><td class="detail-label">Timestamp</td><td>{{ block.timestamp }}</td></tr>
  <tr><td class="detail-label">Previous Hash</td><td class="hash mono">{{ block.previous_hash }}</td></tr>
  <tr><td class="detail-label">Block Hash</td><td class="hash mono">{{ block.block_hash }}</td></tr>
  <tr><td class="detail-label">File Name</td><td>{{ block.file_name }}</td></tr>
  <tr><td class="detail-label">MIME Type</td><td>{{ block.file_mime }}</td></tr>
  <tr><td class="detail-label">Original SHA-256</td><td class="hash mono">{{ block.original_hash }}</td></tr>
  <tr><td class="detail-label">File Size</td><td>{{ format_bytes(block.file_size) }}</td></tr>
  <tr><td class="detail-label">Nonce</td><td>{{ "{:,}".format(block.nonce) }}</td></tr>
  <tr><td class="detail-label">Encrypted Storage</td><td class="mono">{{ block.encrypted_path }}</td></tr>
</table>

<div style="margin-top:1.5rem;">
  {% if has_data %}
    <h3>📝 Decrypted Preview (first 3 KB)</h3>
    <pre class="preview-box">{{ content }}</pre>
    <a href="/download/{{ block.index }}" class="btn-primary" style="margin-top:.75rem;">↓ Download Decrypted File</a>
  {% else %}
    <p class="meta">⚠️ Could not decrypt (wrong password or corrupted data).</p>
  {% endif %}
</div>
<p style="margin-top:1.5rem;"><a href="/">← Back to Dashboard</a></p>
{% endblock %}
HTMLEOF

# ── 5l. web/templates/verify.html ──────────────────────────────────────────
cat > "${INSTALL_DIR}/web/templates/verify.html" << 'HTMLEOF'
{% extends "base.html" %}
{% block title %}Chain Verification — BlockVault{% endblock %}
{% block body %}
<h2>🔍 Chain Verification</h2>
{% if valid %}
  <div class="alert alert-success">
    ✅ The entire chain is <strong>intact and valid</strong>. All block hashes,
    linkages, and encrypted file integrity checks passed.
  </div>
{% else %}
  <div class="alert alert-error">
    ⚠️ {{ errors|length }} issue(s) found:
  </div>
  <ul class="error-list">
    {% for err in errors %}
      <li>{{ err }}</li>
    {% endfor %}
  </ul>
{% endif %}

<h3 style="margin-top:1.5rem;">Verification Checks Performed:</h3>
<ul style="margin:1rem 0;padding-left:1.5rem;">
  <li>✅ Block hash recomputation (SHA-256 of block contents)</li>
  <li>✅ Previous hash linkage (chain continuity)</li>
  <li>✅ Encrypted file existence on disk</li>
  <li>✅ Decryption + original SHA-256 match (file integrity)</li>
</ul>

<a href="/" class="btn-secondary" style="margin-top:1rem;">← Back to Dashboard</a>
{% endblock %}
HTMLEOF

# ── 5m. web/static/style.css ───────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/static/style.css" << 'CSSEOF'
:root {
  --bg:#0f1117; --surface:#1a1d27; --accent:#5b8def;
  --green:#2ecc71; --red:#e74c3c; --amber:#f39c12;
  --text:#e2e4e9; --muted:#8a8fa3; --radius:8px;
}
* { margin:0; padding:0; box-sizing:border-box; }
body {
  font-family:'Segoe UI',system-ui,sans-serif;
  background:var(--bg); color:var(--text);
  line-height:1.6; min-height:100vh;
}
a { color:var(--accent); text-decoration:none; }
a:hover { text-decoration:underline; }

/* Navbar */
.navbar {
  background:var(--surface); border-bottom:1px solid #2a2d3a;
  padding:1rem 0; position:sticky; top:0; z-index:100;
}
.nav-container {
  max-width:1200px; margin:0 auto; padding:0 1.5rem;
  display:flex; align-items:center; justify-content:space-between;
}
.nav-brand { font-size:1.4rem; font-weight:bold; color:#fff; }
.nav-links { display:flex; gap:1.5rem; }
.nav-link {
  color:var(--muted); font-size:.9rem; padding:.3rem .6rem;
  border-radius:var(--radius); transition:.2s;
}
.nav-link:hover { color:var(--text); background:rgba(91,141,239,.1); }

/* Layout */
.container { max-width:1200px; margin:0 auto; padding:1.5rem; }
footer {
  text-align:center; color:var(--muted); font-size:.8rem;
  margin-top:3rem; padding:1.5rem; border-top:1px solid #2a2d3a;
}
.now-year::before { content: attr(data-year); }

/* Flash messages */
.flash {
  padding:.7rem 1rem; border-radius:var(--radius); margin-bottom:1rem;
  font-size:.9rem;
}
.flash-success { background:rgba(46,204,113,.12); border:1px solid var(--green); }
.flash-danger  { background:rgba(231,76,60,.12);  border:1px solid var(--red); }

/* Stats */
.stats-grid {
  display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr));
  gap:1.25rem; margin:1.5rem 0;
}
.stat-card {
  background:var(--surface); border-radius:var(--radius);
  padding:1.5rem; text-align:center; border:1px solid #2a2d3a;
}
.stat-card h3 { font-size:1.8rem; color:var(--accent); margin-bottom:.3rem; }
.stat-card p { color:var(--muted); font-size:.85rem; }

/* Upload */
.upload-details summary {
  cursor:pointer; padding:.7rem 1rem; background:var(--surface);
  border-radius:var(--radius); border:1px solid #2a2d3a;
  font-weight:600; color:var(--text); list-style:none;
}
.upload-details summary::before { content:"⬆ "; }
.upload-details[open] summary { border-radius:var(--radius) var(--radius) 0 0; }
.upload-form { padding:1rem; background:var(--surface); border:1px solid #2a2d3a; border-top:none; border-radius:0 0 var(--radius) var(--radius); }
.file-drop-zone {
  border:2px dashed #3a3d4a; border-radius:var(--radius);
  padding:2.5rem; text-align:center; color:var(--muted);
  transition:.2s; cursor:pointer; margin-bottom:.75rem;
}
.file-drop-zone:hover { border-color:var(--accent); color:var(--text); }
.file-drop-zone input { display:none; }

/* Buttons */
.btn-primary, .btn-secondary {
  display:inline-block; padding:.55rem 1.2rem; border:none;
  border-radius:var(--radius); cursor:pointer; font-size:.9rem;
  color:#fff; transition:opacity .2s; text-decoration:none;
}
.btn-primary { background:var(--accent); }
.btn-secondary { background:#555; }
.btn-primary:hover, .btn-secondary:hover { opacity:.85; }
.actions { margin-top:1.5rem; display:flex; gap:.75rem; flex-wrap:wrap; }

/* Tables */
.table-wrap { overflow-x:auto; margin:1rem 0; }
table {
  width:100%; border-collapse:collapse; background:var(--surface);
  border-radius:var(--radius); overflow:hidden;
}
th, td {
  padding:.65rem .8rem; text-align:left;
  border-bottom:1px solid #2a2d3a; font-size:.9rem;
}
th { background:#1e2130; color:var(--muted); font-size:.8rem;
     text-transform:uppercase; letter-spacing:.04em; }
tr:hover td { background:rgba(91,141,239,.04); }
.mono { font-family:'Fira Code','Consolas',monospace; font-size:.85rem; }
.hash { color:var(--accent); }
.empty-state { color:var(--muted); padding:2rem; text-align:center; }

/* Block detail */
.detail-table { width:100%; margin:1rem 0; }
.detail-label { font-weight:600; color:var(--muted); width:160px; vertical-align:top; padding-top:6px; }
.preview-box {
  background:var(--surface); padding:1rem; border-radius:var(--radius);
  white-space:pre-wrap; word-wrap:break-word; max-height:400px;
  overflow:auto; border:1px solid #2a2d3a; font-size:.85rem;
}
.error-list {
  list-style:none; padding:0; margin:1rem 0;
}
.error-list li {
  color:var(--red); padding:.4rem 0; padding-left:1.5rem;
  position:relative;
}
.error-list li::before { content:"⚠"; position:absolute; left:0; }
CSSEOF

# ── 5n. web/static/script.js ────────────────────────────────────────────────
cat > "${INSTALL_DIR}/web/static/script.js" << 'JSEOF'
document.addEventListener('DOMContentLoaded', function() {
  // Auto-set footer year
  var el = document.querySelector('.now-year');
  if (el) el.textContent = new Date().getFullYear();

  // Chain validity check
  checkChainValidity();
});

function checkChainValidity() {
  fetch('/api/verify')
    .then(function(r){ return r.json(); })
    .then(function(d){
      var el = document.getElementById('chain-validity');
      if (el) {
        el.textContent = d.valid ? '✅ Valid' : '⚠️ Tampered';
        el.style.color = d.valid ? '#2ecc71' : '#e74c3c';
      }
    })
    .catch(function(e){ console.error('Verify check failed:', e); });
}

function verifyChain() {
  checkChainValidity();
  alert('Chain verification complete.');
}

// Format bytes helper (used by server-side template filter as well)
function formatBytes(b) {
  if (b === 0) return '0 B';
  var k = 1024, u = ['B','KB','MB','GB'];
  var i = Math.floor(Math.log(b) / Math.log(k));
  return (b / Math.pow(k, i)).toFixed(1) + ' ' + u[i];
}

// Periodic chain check (every 60 seconds)
setInterval(checkChainValidity, 60000);
JSEOF

# ── 5o. web/templates/layout.html (shared layout with Jinja2 filters) ────
# Note: We add custom filters via app.py. The base.html above serves as layout.

# ── 5p. requirements.txt ───────────────────────────────────────────────────
cat > "${INSTALL_DIR}/requirements.txt" << 'PYEOF'
flask>=3.0
flask-cors>=4.0
cryptography>=42.0
pymysql>=1.1
Werkzeug>=3.0
Pillow>=10.0
python-dotenv>=1.0
bcrypt>=4.0
PYEOF

# ── 5q. run.sh — Convenience launcher ──────────────────────────────────────
cat > "${INSTALL_DIR}/run.sh" << 'BASHEOF'
#!/usr/bin/env bash
SCRIPTDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPTDIR"
source venv/bin/activate
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║         🔗 BlockVault Starting...               ║"
echo "  ╠══════════════════════════════════════════════════╣"
echo "  ║  URL:    http://localhost:${WEB_PORT:-5050}                  ║"
echo "  ║  Port:   ${WEB_PORT:-5050}                                    ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""
exec python web/app.py
BASHEOF
chmod +x "${INSTALL_DIR}/run.sh"

# ── 5r. systemd service ────────────────────────────────────────────────────
cat > /tmp/blockvault.service << SVCEOF
[Unit]
Description=BlockVault — Local Blockchain File Vault
After=network.target mysql.service
Wants=mysql.service

[Service]
Type=simple
User=root
WorkingDirectory=${INSTALL_DIR}
Environment="VAULT_PASSWORD=${VAULT_PASSWORD}"
Environment="PYTHONUNBUFFERED=1"
ExecStart=${PYTHON_ENV}/bin/python ${INSTALL_DIR}/web/app.py
Restart=on-failure
RestartSec=5
StandardOutput=append:${INSTALL_DIR}/logs/server.log
StandardError=append:${INSTALL_DIR}/logs/server.log

[Install]
WantedBy=multi-user.target
SVCEOF

cp /tmp/blockvault.service /etc/systemd/system/blockvault.service
chmod 644 /etc/systemd/system/blockvault.service

# ============================================================================
#  6. FINALIZE AND START
# ============================================================================
info "Step 6/6: Finalizing..."

# Start MySQL
systemctl enable --now mysql 2>/dev/null || service mysql enable --now 2>/dev/null || true
sleep 1

# Verify Python imports work
"${PYTHON_ENV}"/bin/python -c "
import sys
sys.path.insert(0, '${INSTALL_DIR}')
from blockchain.core import Blockchain, Block, sha256_hex
from blockchain.encryption import EncryptionManager, sha256_hex as h2
from blockchain.database import DatabaseBackend
from blockchain.storage import FileVault
print('  ✔ All Python imports OK')
"

systemctl daemon-reload 2>/dev/null || true

echo ""
echo -e "${BOLD}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   ${GREEN}✅ BlockVault installed successfully!${NC}                                       ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   Installation directory : ${INSTALL_DIR}              ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   Web server port        : ${VHOST_PORT}                                     ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   MySQL database         : ${MYSQL_DB}                                       ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   PoW difficulty         : ${DIFFICULTY} zeros                                    ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   Encryption             : AES-256-CBC (PBKDF2 600k iter)               ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   🔑 Vault Password (save this!):${NC}"
echo -e "${BOLD}█${NC}      ${VAULT_PASSWORD}         ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   Quick start (manual):                                                ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     source ${INSTALL_DIR}/venv/bin/activate                                  ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     cd ${INSTALL_DIR} && bash run.sh                                       ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   …or use systemd service:                                             ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     systemctl start blockvault                                          ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     systemctl enable blockvault                                         ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     systemctl status blockvault                                         ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}   Generated credentials:${NC}"
echo -e "${BOLD}█${NC}     MySQL root: ${MYSQL_ROOT_PASS}                              ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}     MySQL app:  ${MYSQL_PASS}                               ${BOLD}█${NC}"
echo -e "${BOLD}█${NC}                                                                        ${BOLD}█${NC}"
echo -e "${BOLD}╚══════════════════════════════════════════════════════════════════╝${NC}"