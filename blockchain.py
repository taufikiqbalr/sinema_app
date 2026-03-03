"""
blockchain.py – Nakamoto-style Proof-of-Work blockchain for annotation auditing.

Hashing is done with the `cryptography` library (SHA-256 via hazmat primitives).
Difficulty 2 → every valid block hash must start with "00".
"""

import json
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ── Proof-of-Work settings ────────────────────────────────────────────────────
DIFFICULTY   = 2
TARGET_PREFIX = "0" * DIFFICULTY


# ── Low-level SHA-256 using the `cryptography` library ───────────────────────
def sha256_hex(data: str) -> str:
    """Return lowercase hex SHA-256 digest of *data* (UTF-8 encoded)."""
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data.encode("utf-8"))
    return digest.finalize().hex()


# ── Block ─────────────────────────────────────────────────────────────────────
class Block:
    """
    A single block in the chain.

    Attributes
    ----------
    index         : position in the chain (0 = genesis)
    timestamp     : Unix epoch float when the block was mined
    data          : arbitrary dict – carries the annotation transaction
    previous_hash : hash of the preceding block ("0" * 64 for genesis)
    nonce         : proof-of-work counter
    hash          : SHA-256 of the canonical JSON representation
    """

    def __init__(
        self,
        index: int,
        timestamp: float,
        data: dict,
        previous_hash: str,
        nonce: int = 0,
        block_hash: str | None = None,
    ):
        self.index         = index
        self.timestamp     = timestamp
        self.data          = data
        self.previous_hash = previous_hash
        self.nonce         = nonce
        # Allow pre-loading a stored hash (when reconstructing from DB)
        self.hash = block_hash if block_hash else self._compute_hash()

    # ── Hashing ──────────────────────────────────────────────────────────────
    def _canonical_string(self) -> str:
        return json.dumps(
            {
                "index":         self.index,
                "timestamp":     self.timestamp,
                "data":          self.data,
                "previous_hash": self.previous_hash,
                "nonce":         self.nonce,
            },
            sort_keys=True,
        )

    def _compute_hash(self) -> str:
        return sha256_hex(self._canonical_string())

    # ── Proof of Work ─────────────────────────────────────────────────────────
    def mine(self) -> str:
        """
        Increment nonce until hash starts with TARGET_PREFIX.
        Returns the winning hash.
        """
        self.nonce = 0
        self.hash  = self._compute_hash()
        while not self.hash.startswith(TARGET_PREFIX):
            self.nonce += 1
            self.hash   = self._compute_hash()
        return self.hash

    # ── Validation ───────────────────────────────────────────────────────────
    def is_valid(self) -> bool:
        return (
            self.hash == self._compute_hash()
            and self.hash.startswith(TARGET_PREFIX)
        )

    # ── Serialisation ────────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "index":         self.index,
            "timestamp":     self.timestamp,
            "data":          self.data,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "hash":          self.hash,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Block":
        return cls(
            index         = d["index"],
            timestamp     = d["timestamp"],
            data          = d["data"],
            previous_hash = d["previous_hash"],
            nonce         = d["nonce"],
            block_hash    = d["hash"],
        )


# ── Blockchain ────────────────────────────────────────────────────────────────
class Blockchain:
    """
    In-memory chain.  Persistence is handled externally (PostgreSQL via
    the BlockRecord SQLAlchemy model in app.py).  Use :meth:`load` to
    reconstruct the chain from stored dicts, then :meth:`add_block` to
    append new transactions.
    """

    GENESIS_PREV_HASH = "0" * 64

    def __init__(self):
        self.chain: list[Block] = []

    # ── Initialisation ───────────────────────────────────────────────────────
    def _create_genesis(self) -> Block:
        b = Block(
            index         = 0,
            timestamp     = time.time(),
            data          = {"action": "GENESIS", "annotation_id": None},
            previous_hash = self.GENESIS_PREV_HASH,
        )
        b.mine()
        return b

    def load(self, stored_dicts: list[dict]) -> None:
        """Rebuild chain from a list of dicts (ordered by index)."""
        self.chain = [Block.from_dict(d) for d in stored_dicts]

    def ensure_genesis(self) -> Block | None:
        """
        If chain is empty, create and return the genesis block.
        Returns None if genesis already exists.
        """
        if not self.chain:
            genesis = self._create_genesis()
            self.chain.append(genesis)
            return genesis
        return None

    # ── Core operations ──────────────────────────────────────────────────────
    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, action: str, annotation_id: str, payload: dict) -> Block:
        """
        Mine a new block for the given annotation transaction and append it.

        Parameters
        ----------
        action        : "INSERT" | "UPDATE" | "DELETE"
        annotation_id : UUID string of the annotation
        payload       : snapshot of annotation fields relevant to the transaction
        """
        data = {
            "action":        action,
            "annotation_id": annotation_id,
            "timestamp":     time.time(),
            "payload":       payload,
        }
        block = Block(
            index         = len(self.chain),
            timestamp     = data["timestamp"],
            data          = data,
            previous_hash = self.last_block.hash,
        )
        block.mine()
        self.chain.append(block)
        return block

    # ── Validation ───────────────────────────────────────────────────────────
    def is_valid(self) -> bool:
        """Validate every block and every prev_hash linkage."""
        for i, block in enumerate(self.chain):
            if not block.is_valid():
                return False
            if i > 0 and block.previous_hash != self.chain[i - 1].hash:
                return False
        return True
