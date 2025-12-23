"""Blockchain management and validation."""
import time
import json
from typing import Optional
from .block import Block
from .merkle import MerkleAuditTree


class Blockchain:
    """
    Blockchain for immutable audit logging.
    
    Features:
    - Genesis block creation
    - Block mining with PoW
    - Chain validation
    - Transaction logging
    """
    
    def __init__(self, difficulty: int = 4):
        """
        Initialize blockchain.
        
        Args:
            difficulty: PoW difficulty (number of leading zeros)
        """
        self.chain: list[Block] = []
        self.pending_transactions: list[dict] = []
        self.difficulty = difficulty
        
        # Create genesis block
        self._create_genesis_block()
    
    def _create_genesis_block(self) -> None:
        """Create the first block in the chain."""
        genesis_tx = [{
            'type': 'GENESIS',
            'timestamp': int(time.time()),
            'message': 'CryptoVault Genesis Block'
        }]
        
        merkle_root = MerkleAuditTree.get_root(genesis_tx)
        
        genesis = Block(
            index=0,
            transactions=genesis_tx,
            previous_hash='0' * 64,
            merkle_root=merkle_root
        )
        genesis.mine(self.difficulty)
        
        self.chain.append(genesis)
    
    @property
    def last_block(self) -> Block:
        """Get the most recent block."""
        return self.chain[-1]
    
    def add_transaction(self, transaction: dict) -> int:
        """
        Add transaction to pending pool.
        
        Args:
            transaction: Transaction dictionary
            
        Returns:
            Index of transaction in pending pool
        """
        # Add timestamp if not present
        if 'timestamp' not in transaction:
            transaction['timestamp'] = int(time.time())
        
        self.pending_transactions.append(transaction)
        return len(self.pending_transactions) - 1
    
    def mine_pending_transactions(self) -> Optional[Block]:
        """
        Mine a new block with pending transactions.
        
        Returns:
            New block or None if no pending transactions
        """
        if not self.pending_transactions:
            return None
        
        # Build Merkle tree
        merkle_root = MerkleAuditTree.get_root(self.pending_transactions)
        
        # Create new block
        block = Block(
            index=len(self.chain),
            transactions=self.pending_transactions.copy(),
            previous_hash=self.last_block.hash,
            merkle_root=merkle_root
        )
        
        # Mine block
        block.mine(self.difficulty)
        
        # Add to chain and clear pending
        self.chain.append(block)
        self.pending_transactions = []
        
        return block
    
    def is_chain_valid(self) -> tuple[bool, Optional[str]]:
        """
        Validate entire blockchain.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            
            # Verify hash
            if current.hash != current.calculate_hash():
                return False, f"Block {i} hash is invalid"
            
            # Verify link
            if current.previous_hash != previous.hash:
                return False, f"Block {i} previous_hash mismatch"
            
            # Verify PoW
            if not current.is_valid_proof(self.difficulty):
                return False, f"Block {i} PoW is invalid"
            
            # Verify Merkle root
            expected_root = MerkleAuditTree.get_root(current.transactions)
            if current.merkle_root != expected_root:
                return False, f"Block {i} Merkle root mismatch"
        
        return True, None
    
    def get_transaction_proof(self, block_index: int, 
                               tx_index: int) -> Optional[dict]:
        """
        Get proof of transaction inclusion.
        
        Args:
            block_index: Block containing transaction
            tx_index: Transaction index within block
            
        Returns:
            Proof dictionary or None
        """
        if block_index >= len(self.chain):
            return None
        
        block = self.chain[block_index]
        
        if tx_index >= len(block.transactions):
            return None
        
        proof = MerkleAuditTree.get_proof(block.transactions, tx_index)
        
        return {
            'block_index': block_index,
            'block_hash': block.hash,
            'tx_index': tx_index,
            'transaction': block.transactions[tx_index],
            'merkle_proof': proof,
            'merkle_root': block.merkle_root
        }
    
    def verify_transaction_proof(self, proof: dict) -> bool:
        """
        Verify a transaction inclusion proof.
        
        Args:
            proof: Proof from get_transaction_proof()
            
        Returns:
            True if proof is valid
        """
        return MerkleAuditTree.verify_proof(
            proof['transaction'],
            proof['merkle_proof'],
            proof['merkle_root']
        )
    
    def find_transactions(self, **kwargs) -> list[tuple[int, int, dict]]:
        """
        Find transactions matching criteria.
        
        Args:
            **kwargs: Field-value pairs to match
            
        Returns:
            List of (block_index, tx_index, transaction) tuples
        """
        results = []
        
        for block_idx, block in enumerate(self.chain):
            for tx_idx, tx in enumerate(block.transactions):
                matches = all(
                    tx.get(k) == v for k, v in kwargs.items()
                )
                if matches:
                    results.append((block_idx, tx_idx, tx))
        
        return results
    
    def to_dict(self) -> dict:
        """Export blockchain to dictionary."""
        return {
            'difficulty': self.difficulty,
            'chain': [block.to_dict() for block in self.chain],
            'pending': self.pending_transactions
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'Blockchain':
        """Import blockchain from dictionary."""
        blockchain = cls.__new__(cls)
        blockchain.difficulty = data['difficulty']
        blockchain.chain = [Block.from_dict(b) for b in data['chain']]
        blockchain.pending_transactions = data.get('pending', [])
        return blockchain
    
    def __len__(self) -> int:
        return len(self.chain)
    
    def __repr__(self) -> str:
        return f"Blockchain(blocks={len(self.chain)}, difficulty={self.difficulty})"