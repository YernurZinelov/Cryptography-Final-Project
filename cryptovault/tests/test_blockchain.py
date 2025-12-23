"""Tests for blockchain module."""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from blockchain import Blockchain, Block, MerkleAuditTree


class TestBlock:
    """Tests for Block class."""
    
    def test_block_creation(self):
        """Test block creation."""
        block = Block(
            index=1,
            transactions=[{"data": "test"}],
            previous_hash="0" * 64,
            merkle_root="a" * 64
        )
        
        assert block.index == 1
        assert block.hash is not None
    
    def test_block_hash_changes_with_nonce(self):
        """Test block hash changes when nonce changes."""
        block = Block(
            index=1,
            transactions=[{"data": "test"}],
            previous_hash="0" * 64,
            merkle_root="a" * 64
        )
        
        hash1 = block.hash
        block.nonce = 100
        block.hash = block.calculate_hash()
        
        assert hash1 != block.hash
    
    def test_block_mining(self):
        """Test block mining meets difficulty."""
        block = Block(
            index=1,
            transactions=[{"data": "test"}],
            previous_hash="0" * 64,
            merkle_root="a" * 64
        )
        
        difficulty = 2
        block.mine(difficulty)
        
        assert block.hash.startswith("0" * difficulty)
    
    def test_block_serialization(self):
        """Test block to/from dict."""
        block = Block(
            index=1,
            transactions=[{"data": "test"}],
            previous_hash="0" * 64,
            merkle_root="a" * 64
        )
        block.mine(2)
        
        data = block.to_dict()
        restored = Block.from_dict(data)
        
        assert restored.hash == block.hash
        assert restored.nonce == block.nonce


class TestBlockchain:
    """Tests for Blockchain class."""
    
    def test_genesis_block(self):
        """Test genesis block creation."""
        chain = Blockchain(difficulty=2)
        
        assert len(chain) == 1
        assert chain.chain[0].index == 0
    
    def test_add_transaction(self):
        """Test adding transactions."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TEST", "data": "value"})
        
        assert len(chain.pending_transactions) == 1
    
    def test_mine_block(self):
        """Test mining pending transactions."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TEST1"})
        chain.add_transaction({"type": "TEST2"})
        
        block = chain.mine_pending_transactions()
        
        assert block is not None
        assert len(chain) == 2
        assert len(chain.pending_transactions) == 0
    
    def test_chain_validation(self):
        """Test chain validation passes."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TX1"})
        chain.mine_pending_transactions()
        
        chain.add_transaction({"type": "TX2"})
        chain.mine_pending_transactions()
        
        is_valid, error = chain.is_chain_valid()
        assert is_valid
        assert error is None
    
    def test_tampered_chain_detected(self):
        """Test tampering is detected."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TX1"})
        chain.mine_pending_transactions()
        
        # Tamper with block
        chain.chain[1].transactions[0]["type"] = "TAMPERED"
        
        is_valid, error = chain.is_chain_valid()
        assert not is_valid
    
    def test_transaction_proof(self):
        """Test Merkle proof for transaction."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TX1"})
        chain.add_transaction({"type": "TX2"})
        chain.mine_pending_transactions()
        
        proof = chain.get_transaction_proof(1, 0)
        
        assert proof is not None
        assert chain.verify_transaction_proof(proof)
    
    def test_serialization(self):
        """Test blockchain to/from dict."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "TX1"})
        chain.mine_pending_transactions()
        
        data = chain.to_dict()
        restored = Blockchain.from_dict(data)
        
        assert len(restored) == len(chain)
        is_valid, _ = restored.is_chain_valid()
        assert is_valid
    
    def test_find_transactions(self):
        """Test finding transactions by criteria."""
        chain = Blockchain(difficulty=2)
        
        chain.add_transaction({"type": "AUTH", "user": "alice"})
        chain.add_transaction({"type": "FILE", "user": "bob"})
        chain.add_transaction({"type": "AUTH", "user": "charlie"})
        chain.mine_pending_transactions()
        
        results = chain.find_transactions(type="AUTH")
        
        assert len(results) == 2
    
    def test_no_pending_returns_none(self):
        """Test mining with no pending transactions."""
        chain = Blockchain(difficulty=2)
        
        result = chain.mine_pending_transactions()
        
        assert result is None
    
    def test_multiple_blocks(self):
        """Test chain with multiple blocks."""
        chain = Blockchain(difficulty=2)
        
        for i in range(5):
            chain.add_transaction({"type": f"TX{i}"})
            chain.mine_pending_transactions()
        
        assert len(chain) == 6  # Genesis + 5 mined
        is_valid, _ = chain.is_chain_valid()
        assert is_valid


class TestMerkleAuditTree:
    """Tests for Merkle audit tree."""
    
    def test_hash_transaction(self):
        """Test transaction hashing."""
        tx = {"type": "TEST", "value": 123}
        hash1 = MerkleAuditTree.hash_transaction(tx)
        hash2 = MerkleAuditTree.hash_transaction(tx)
        
        assert hash1 == hash2
        assert len(hash1) == 64
    
    def test_build_tree(self):
        """Test tree building from transactions."""
        txs = [{"type": "TX1"}, {"type": "TX2"}, {"type": "TX3"}]
        tree = MerkleAuditTree.build_tree(txs)
        
        assert tree.get_root() is not None
    
    def test_proof_verification(self):
        """Test Merkle proof for transactions."""
        txs = [{"type": "TX1"}, {"type": "TX2"}, {"type": "TX3"}, {"type": "TX4"}]
        
        root = MerkleAuditTree.get_root(txs)
        
        for i, tx in enumerate(txs):
            proof = MerkleAuditTree.get_proof(txs, i)
            assert MerkleAuditTree.verify_proof(tx, proof, root)
    
    def test_empty_transactions(self):
        """Test tree with empty transaction list."""
        txs = []
        tree = MerkleAuditTree.build_tree(txs)
        
        # Should create tree with placeholder
        assert tree.get_root() is not None
    
    def test_single_transaction(self):
        """Test tree with single transaction."""
        txs = [{"type": "SINGLE"}]
        
        root = MerkleAuditTree.get_root(txs)
        proof = MerkleAuditTree.get_proof(txs, 0)
        
        assert MerkleAuditTree.verify_proof(txs[0], proof, root)
    
    def test_different_transactions_different_roots(self):
        """Test different transactions produce different roots."""
        txs1 = [{"type": "A"}, {"type": "B"}]
        txs2 = [{"type": "C"}, {"type": "D"}]
        
        root1 = MerkleAuditTree.get_root(txs1)
        root2 = MerkleAuditTree.get_root(txs2)
        
        assert root1 != root2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])