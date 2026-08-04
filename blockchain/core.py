"""
blockchain/core.py

Minimal Blockchain and Block classes to integrate with the storage layer.
This module is intentionally lightweight: it provides the small API the
installer's import-check expects, and delegates file encryption/decryption
to blockchain.storage.FileVault.

For full application logic replace these placeholders with the richer
implementation (chain validation, PoW mining, consensus rules, etc.).
"""
from dataclasses import dataclass
from typing import Optional, List
import time

from .encryption import sha256_hex
from .storage import FileVault


@dataclass
class Block:
    block_index: int
    timestamp: str
    previous_hash: str
    file_name: str
    original_hash: str
    file_size: int
    encrypted_path: str
    nonce: int = 0
    block_hash: Optional[str] = None


class Blockchain:
    """Very small in-memory Blockchain facade used by the web interface.

    In production this class should be backed by DatabaseBackend and
    implement consensus, mining, and verification. Here it provides a
    minimal API for creating blocks and verifying chain linkage.
    """

    def __init__(self, file_vault: FileVault):
        self.file_vault = file_vault
        self._chain: List[Block] = []

    def add_block(self, block: Block):
        # compute block_hash for immutability check (simple SHA256 of concatenated fields)
        h = sha256_hex(
            (
                f"{block.block_index}|{block.timestamp}|{block.previous_hash}|"
                f"{block.file_name}|{block.original_hash}|{block.file_size}|{block.nonce}"
            ).encode("utf-8")
        )
        block.block_hash = h
        self._chain.append(block)
        return block

    def last_block(self) -> Optional[Block]:
        return self._chain[-1] if self._chain else None

    def verify_chain(self) -> List[str]:
        """Verify chain connectivity and return list of errors (empty if ok).

        This implementation only checks block hash linkage and attempts to
        decrypt stored files (via FileVault) to assert integrity. For large
        datasets you should replace this with a cached verification job.
        """
        errors = []
        prev_hash = None
        for blk in self._chain:
            if prev_hash and blk.previous_hash != prev_hash:
                errors.append(f"block {blk.block_index}: previous_hash mismatch")
            # try to verify file decrypts and matches original hash
            try:
                data = self.file_vault.retrieve_file(blk.encrypted_path)
                if sha256_hex(data) != blk.original_hash:
                    errors.append(f"block {blk.block_index}: original_hash mismatch")
            except Exception as exc:
                errors.append(f"block {blk.block_index}: decryption error: {exc}")
            prev_hash = blk.block_hash
        return errors
