"""Merkle tree for blockchain transactions."""
import sys
sys.path.insert(0, '..')
from crypto_core.merkle_tree import MerkleTree, MerkleProof
from crypto_core.sha256 import sha256
import json


class MerkleAuditTree:
    """
    Merkle tree specifically for audit log transactions.
    
    Provides:
    - Transaction hashing
    - Tree construction
    - Inclusion proofs
    """
    
    @staticmethod
    def hash_transaction(transaction: dict) -> str:
        """
        Hash a transaction for Merkle tree inclusion.
        
        Args:
            transaction: Transaction dictionary
            
        Returns:
            Transaction hash
        """
        tx_string = json.dumps(transaction, sort_keys=True)
        return sha256(tx_string)
    
    @classmethod
    def build_tree(cls, transactions: list[dict]) -> MerkleTree:
        """
        Build Merkle tree from transactions.
        
        Args:
            transactions: List of transaction dictionaries
            
        Returns:
            MerkleTree instance
        """
        if not transactions:
            # Create tree with single empty transaction
            return MerkleTree([json.dumps({'empty': True})])
        
        # Hash each transaction
        tx_strings = [json.dumps(tx, sort_keys=True) for tx in transactions]
        return MerkleTree(tx_strings)
    
    @classmethod
    def get_root(cls, transactions: list[dict]) -> str:
        """Get Merkle root for transactions."""
        tree = cls.build_tree(transactions)
        return tree.get_root()
    
    @classmethod
    def get_proof(cls, transactions: list[dict], tx_index: int) -> str:
        """
        Get Merkle proof for transaction.
        
        Args:
            transactions: List of all transactions
            tx_index: Index of transaction to prove
            
        Returns:
            Serialized Merkle proof
        """
        tree = cls.build_tree(transactions)
        proof = tree.get_proof(tx_index)
        return MerkleProof.serialize(proof)
    
    @classmethod
    def verify_proof(cls, transaction: dict, proof_str: str, root: str) -> bool:
        """
        Verify transaction inclusion proof.
        
        Args:
            transaction: Transaction to verify
            proof_str: Serialized Merkle proof
            root: Expected Merkle root
            
        Returns:
            True if proof is valid
        """
        proof = MerkleProof.deserialize(proof_str)
        tx_string = json.dumps(transaction, sort_keys=True)
        return MerkleTree.verify_proof(tx_string, proof, root)