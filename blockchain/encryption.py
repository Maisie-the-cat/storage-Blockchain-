"""
AES-256-GCM authenticated encryption using a memory-hard KDF (scrypt).

This module replaces the previous AES-CBC + PKCS7 approach with an AEAD
construction (AES-GCM) so ciphertexts are authenticated and tamper-evident.

Design notes:
- A system-wide salt is still used (stored in chain_meta) to derive the
  encryption key from the installer-generated vault password. This keeps the
  external database layout unchanged.
- KDF: hashlib.scrypt used with sensible defaults. Parameters are configurable
  via environment variables for tuning on target hardware.
- Ciphertext format written to disk: NONCE || CIPHERTEXT (AESGCM returns
  ciphertext that includes the authentication tag). NONCE is 12 bytes.

Security trade-offs / next steps:
- Using a per-file salt (stored alongside the blob) is stronger; consider
  moving to per-file DEKs + envelope encryption (wrap DEK with a master KEK)
  in a follow-up change.
- For production, prefer fetching a KEK from a secrets manager (Vault/KMS)
  instead of deriving from a password each runtime.
"""

import os
import hashlib
import hmac
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Sizes (bytes)
SALT_SIZE = 32        # kept for compatibility with chain_meta storage
NONCE_SIZE = 12       # recommended nonce size for AES-GCM (96 bits)
KEY_SIZE = 32         # 256-bit AES key

# Scrypt KDF defaults — tune via environment if needed
SCRYPT_N = int(os.environ.get("BLOCKVAULT_SCRYPT_N", str(2**14)))
SCRYPT_R = int(os.environ.get("BLOCKVAULT_SCRYPT_R", "8"))
SCRYPT_P = int(os.environ.get("BLOCKVAULT_SCRYPT_P", "1"))


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


class EncryptionManager:
    """Manages AES-256-GCM encryption using a scrypt-derived key.

    API keeps the same surface as the previous implementation: initialized
    with a password and a salt (the system salt from chain_meta). The
    encrypt() method returns NONCE || CIPHERTEXT (where ciphertext includes
    the GCM tag) and decrypt() reverses that.
    """

    def __init__(self, password: str, salt: bytes):
        if not isinstance(salt, (bytes, bytearray)) or len(salt) < 8:
            raise ValueError("salt must be bytes and non-empty")
        self.key = self._derive_key(password, salt)
        self.aesgcm = AESGCM(self.key)

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive a 32-byte key from password+salt using scrypt.

        Parameters are configurable via environment for tuning.
        """
        # hashlib.scrypt is available on modern Python and offers a memory-hard KDF
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=KEY_SIZE,
        )

    def encrypt(self, plaintext: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Encrypt data. Returns NONCE || CIPHERTEXT (ciphertext includes tag).

        associated_data, if provided, is authenticated but not encrypted.
        """
        nonce = os.urandom(NONCE_SIZE)
        ct = self.aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce + ct

    def decrypt(self, blob: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data (NONCE || CIPHERTEXT) back to plaintext.

        Raises EncryptionError on failure.
        """
        if len(blob) < NONCE_SIZE + 16:
            # ciphertext must be at least tag length (16) + nonce
            raise EncryptionError("Ciphertext too short")
        nonce = blob[:NONCE_SIZE]
        ct = blob[NONCE_SIZE:]
        try:
            pt = self.aesgcm.decrypt(nonce, ct, associated_data)
            return pt
        except Exception as exc:
            raise EncryptionError("Decryption failed") from exc


def sha256_hex(data: bytes) -> str:
    """Return hexadecimal SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()
