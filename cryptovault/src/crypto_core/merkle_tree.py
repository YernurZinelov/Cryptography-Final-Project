"""
Merkle Tree Implementation from Scratch
Supports proof generation and verification
"""
from typing import Optional
from .sha256 import sha256, sha256_bytes


class MerkleTree:
    """
    Merkle Tree implementation for transaction verification.
    
    Attributes:
        leaves: List of leaf hashes
        root: Merkle root hash
        tree: Complete tree structure (list of levels)
    """
    
    def __init__(self, data: list[bytes | str]):
        """
        Build Merkle tree from list of data items.
        
        Args:
            data: List of data items to include in tree
        """
        if not data:
            raise ValueError("Cannot create Merkle tree with empty data")
        
        # Hash all leaf nodes
        self.leaves = [sha256(item) for item in data]
        self.tree = [self.leaves.copy()]
        self._build_tree()
        self.root = self.tree[-1][0]
    
    def _build_tree(self) -> None:
        """Build tree levels from leaves to root."""
        current_level = self.leaves.copy()
        
        while len(current_level) > 1:
            next_level = []
            
            # Handle odd number of nodes by duplicating last one
            if len(current_level) % 2 == 1:
                current_level.append(current_level[-1])
            
            # Combine pairs
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                next_level.append(sha256(combined))
            
            self.tree.append(next_level)
            current_level = next_level
    
    def get_root(self) -> str:
        """
        Get Merkle root hash.
        
        Returns:
            Root hash as hex string
        """
        return self.root
    
    def get_proof(self, index: int) -> list[tuple[str, str]]:
        """
        Generate Merkle proof for item at index.
        
        Args:
            index: Index of item in original data list
            
        Returns:
            List of (hash, direction) tuples where direction is 'left' or 'right'
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError(f"Index {index} out of range")
        
        proof = []
        current_index = index
        
        for level in self.tree[:-1]:  # Exclude root level
            # Handle odd-length levels
            level_copy = level.copy()
            if len(level_copy) % 2 == 1:
                level_copy.append(level_copy[-1])
            
            # Determine sibling
            if current_index % 2 == 0:
                sibling_index = current_index + 1
                direction = 'right'
            else:
                sibling_index = current_index - 1
                direction = 'left'
            
            if sibling_index < len(level_copy):
                proof.append((level_copy[sibling_index], direction))
            
            # Move to parent index
            current_index //= 2
        
        return proof
    
    @classmethod
    def verify_proof(cls, leaf_data: bytes | str, proof: list[tuple[str, str]], root: str) -> bool:
        """
        Verify a Merkle proof.
        
        Args:
            leaf_data: Original data item
            proof: Merkle proof from get_proof()
            root: Expected Merkle root
            
        Returns:
            True if proof is valid
        """
        current_hash = sha256(leaf_data)
        
        for sibling_hash, direction in proof:
            if direction == 'left':
                combined = sibling_hash + current_hash
            else:
                combined = current_hash + sibling_hash
            current_hash = sha256(combined)
        
        return current_hash == root
    
    def __repr__(self) -> str:
        return f"MerkleTree(leaves={len(self.leaves)}, root={self.root[:16]}...)"


class MerkleProof:
    """Helper class to serialize/deserialize Merkle proofs."""
    
    @staticmethod
    def serialize(proof: list[tuple[str, str]]) -> str:
        """Serialize proof to string."""
        parts = []
        for hash_val, direction in proof:
            parts.append(f"{hash_val}:{direction}")
        return "|".join(parts)
    
    @staticmethod
    def deserialize(proof_str: str) -> list[tuple[str, str]]:
        """Deserialize proof from string."""
        if not proof_str:
            return []
        
        proof = []
        for part in proof_str.split("|"):
            hash_val, direction = part.rsplit(":", 1)
            proof.append((hash_val, direction))
        return proof