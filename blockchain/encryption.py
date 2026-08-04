"""
Envelope encryption: per-file DEK wrapped by a KEK stored in Vault (transit) with local fallback.

File format written to disk: JSON header (utf-8, single line) + '\n' + binary payload.
Header keys:
  - version: 1
  - wrap: "vault" or "local"
  - wrapped_key: ciphertext (string). For Vault this is the transit ciphertext string; for local it's base64 of AES-GCM-wrapped DEK.
  - kek: (optional) transit key name used when wrap=="vault"

Payload: nonce (12 bytes) || ciphertext (contains GCM tag)

Notes:
- Requires VAULT_ADDR and VAULT_TOKEN env vars and VAULT_TRANSIT_KEY (name) to use Vault transit.
- Falls back to local KEK derived from password+salt (scrypt) and uses AES-GCM to wrap DEK.
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import urllib.request
import urllib.error

# Sizes
NONCE_SIZE = 12
DEK_SIZE = 32  # 256-bit per-file data encryption key
KEY_SIZE = 32

# Scrypt KDF defaults for local KEK derivation (if Vault not available)
SCRYPT_N = int(os.environ.get("BLOCKVAULT_SCRYPT_N", str(2**14)))
SCRYPT_R = int(os.environ.get("BLOCKVAULT_SCRYPT_R", "8"))
SCRYPT_P = int(os.environ.get("BLOCKVAULT_SCRYPT_P", "1"))

# Vault transit configuration
VAULT_ADDR = os.environ.get("VAULT_ADDR", os.environ.get("VAULT_ADDR"))
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", os.environ.get("VAULT_TOKEN"))
VAULT_TRANSIT_KEY = os.environ.get("VAULT_TRANSIT_KEY", "blockvault-kek")


class EncryptionError(Exception):
    pass


def _vault_transit_encrypt(plaintext_bytes: bytes, key_name: str) -> Optional[str]:
    """Encrypt plaintext (bytes) using Vault transit; returns ciphertext string on success."""
    if not VAULT_ADDR or not VAULT_TOKEN:
        return None
    url = VAULT_ADDR.rstrip('/') + f"/v1/transit/encrypt/{key_name}"
    payload = json.dumps({
        "plaintext": base64.b64encode(plaintext_bytes).decode('ascii')
    }).encode('utf-8')
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('X-Vault-Token', VAULT_TOKEN)
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
            # response: { data: { ciphertext: "..." } }
            return data.get('data', {}).get('ciphertext')
    except Exception:
        return None


def _vault_transit_decrypt(ciphertext: str, key_name: str) -> Optional[bytes]:
    if not VAULT_ADDR or not VAULT_TOKEN:
        return None
    url = VAULT_ADDR.rstrip('/') + f"/v1/transit/decrypt/{key_name}"
    payload = json.dumps({
        "ciphertext": ciphertext
    }).encode('utf-8')
    req = urllib.request.Request(url, data=payload, method='POST')
    req.add_header('X-Vault-Token', VAULT_TOKEN)
    req.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.load(resp)
            b64 = data.get('data', {}).get('plaintext')
            if not b64:
                return None
            return base64.b64decode(b64)
    except Exception:
        return None


def _derive_kek(password: str, salt: bytes) -> bytes:
    # local KEK derived by scrypt (fallback when Vault not available)
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=KEY_SIZE)


class EncryptionManager:
    """Envelope Encryption Manager.

    Usage:
      mgr = EncryptionManager(master_password, system_salt)
      blob = mgr.encrypt(plaintext)
      # blob is bytes: header_json + b"\n" + payload
      plaintext = mgr.decrypt(blob)

    At encrypt time a random DEK is generated per-file; the DEK encrypts the file
    with AES-GCM (nonce || ciphertext). The DEK is then wrapped either by Vault
    transit (preferred) or locally with a KEK derived from master password + salt.
    The wrapped key and metadata are stored in the JSON header which is prepended
    to the blob on disk.
    """

    def __init__(self, master_password: str, salt: bytes):
        if not isinstance(salt, (bytes, bytearray)) or len(salt) == 0:
            raise ValueError('salt must be bytes and non-empty')
        self.master_password = master_password
        self.salt = salt

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        # generate a random DEK
        dek = os.urandom(DEK_SIZE)
        aesgcm = AESGCM(dek)
        nonce = os.urandom(NONCE_SIZE)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data)
        payload = nonce + ct

        # try to wrap DEK with Vault transit
        wrapped = None
        wrap_mode = None
        if VAULT_ADDR and VAULT_TOKEN:
            wrapped_ct = _vault_transit_encrypt(dek, VAULT_TRANSIT_KEY)
            if wrapped_ct:
                wrapped = wrapped_ct
                wrap_mode = 'vault'

        # fallback: local wrapping using KEK derived from master password + salt
        if wrapped is None:
            kek = _derive_kek(self.master_password, self.salt)
            # wrap dek using AES-GCM with KEK
            wrapper = AESGCM(kek)
            wrap_nonce = os.urandom(NONCE_SIZE)
            wrapped_bytes = wrap_nonce + wrapper.encrypt(wrap_nonce, dek, None)
            wrapped = base64.b64encode(wrapped_bytes).decode('ascii')
            wrap_mode = 'local'

        header = {
            'version': 1,
            'wrap': wrap_mode,
            'wrapped_key': wrapped,
        }
        if wrap_mode == 'vault':
            header['kek'] = VAULT_TRANSIT_KEY

        header_json = json.dumps(header, separators=(',', ':')).encode('utf-8')
        return header_json + b"\n" + payload

    def decrypt(self, blob: bytes, associated_data: Optional[bytes] = None) -> bytes:
        # parse header (line up to first newline)
        try:
            header_raw, payload = blob.split(b'\n', 1)
        except ValueError:
            raise EncryptionError('Invalid blob format: missing header')
        try:
            header = json.loads(header_raw.decode('utf-8'))
        except Exception:
            raise EncryptionError('Invalid header JSON')

        wrapped = header.get('wrapped_key')
        wrap_mode = header.get('wrap')
        if not wrapped or not wrap_mode:
            raise EncryptionError('Missing wrapped key or wrap mode')

        # unwrap DEK
        dek = None
        if wrap_mode == 'vault':
            kek = header.get('kek', VAULT_TRANSIT_KEY)
            dek = _vault_transit_decrypt(wrapped, kek)
            if dek is None:
                raise EncryptionError('Failed to unwrap DEK via Vault')
        elif wrap_mode == 'local':
            try:
                wrapped_bytes = base64.b64decode(wrapped)
                wrap_nonce = wrapped_bytes[:NONCE_SIZE]
                wrap_ct = wrapped_bytes[NONCE_SIZE:]
                kek = _derive_kek(self.master_password, self.salt)
                wrapper = AESGCM(kek)
                dek = wrapper.decrypt(wrap_nonce, wrap_ct, None)
            except Exception:
                raise EncryptionError('Failed to unwrap DEK with local KEK')
        else:
            raise EncryptionError('Unknown wrap mode')

        # decrypt payload
        if len(payload) < NONCE_SIZE + 16:
            raise EncryptionError('Payload too short')
        nonce = payload[:NONCE_SIZE]
        ct = payload[NONCE_SIZE:]
        try:
            aesgcm = AESGCM(dek)
            pt = aesgcm.decrypt(nonce, ct, associated_data)
            return pt
        except Exception:
            raise EncryptionError('Payload decryption failed')


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
