"""Block structure with Proof of Work."""
import time
import json
from typing import Optional
import sys
sys.path.insert(0, '..')
from crypto_core.sha256 import sha256


class Block:
    """
    Blockchain block with Proof of Work.
    
    Attributes:
        index: Block position in chain
        timestamp: Block creation time
        transactions: List of transactions
        previous_hash: Hash of previous block
        merkle_root: Merkle root of transactions
        nonce: PoW nonce
        hash: Block hash
    """
    
    def __init__(self, index: int, transactions: list,
                 previous_hash: str, merkle_root: str,
                 timestamp: int = None, nonce: int = 0,
                 block_hash: str = None):
        """
        Initialize a block.
        
        Args:
            index: Block position in chain
            transactions: List of transaction dictionaries
            previous_hash: Hash of previous block
            merkle_root: Merkle root of transactions
            timestamp: Unix timestamp (generated if None)
            nonce: PoW nonce (0 for new blocks)
            block_hash: Pre-computed hash (for loading blocks)
        """
        self.index = index
        self.timestamp = timestamp or int(time.time())
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_root = merkle_root
        self.nonce = nonce
        self.hash = block_hash or self.calculate_hash()
    
    def calculate_hash(self) -> str:
        """Calculate SHA-256 hash of block."""
        block_string = json.dumps({
            'index': self.index,
            'timestamp': self.timestamp,
            'merkle_root': self.merkle_root,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }, sort_keys=True)
        
        return sha256(block_string)
    
    def mine(self, difficulty: int) -> None:
        """
        Mine block with Proof of Work.
        
        Args:
            difficulty: Number of leading zeros required
        """
        target = '0' * difficulty
        
        while not self.hash.startswith(target):
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def is_valid_proof(self, difficulty: int) -> bool:
        """Check if block hash meets difficulty target."""
        target = '0' * difficulty
        return self.hash.startswith(target) and self.hash == self.calculate_hash()
    
    def to_dict(self) -> dict:
        """Convert block to dictionary."""
        return {
            'index': self.index,
            'timestamp': self.timestamp,
            'transactions': self.transactions,
            'previous_hash': self.previous_hash,
            'merkle_root': self.merkle_root,
            'nonce': self.nonce,
            'hash': self.hash
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Block':
        """Create block from dictionary."""
        return cls(
            index=data['index'],
            transactions=data['transactions'],
            previous_hash=data['previous_hash'],
            merkle_root=data['merkle_root'],
            timestamp=data['timestamp'],
            nonce=data['nonce'],
            block_hash=data['hash']
        )
    
    def __repr__(self) -> str:
        return f"Block(index={self.index}, hash={self.hash[:16]}...)"