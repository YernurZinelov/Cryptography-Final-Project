"""Tests for storage module."""
import pytest
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from storage import Database


class TestDatabase:
    """Tests for Database class."""
    
    @pytest.fixture
    def db(self, tmp_path):
        """Create temporary database."""
        db_path = tmp_path / "test_db.json"
        return Database(str(db_path))
    
    def test_create_user(self, db):
        """Test user creation."""
        result = db.create_user("alice", {"password": "hash123"})
        assert result == True
    
    def test_create_duplicate_user(self, db):
        """Test duplicate user rejected."""
        db.create_user("alice", {"password": "hash123"})
        result = db.create_user("alice", {"password": "other"})
        assert result == False
    
    def test_get_user(self, db):
        """Test get user."""
        db.create_user("alice", {"password": "hash123"})
        user = db.get_user("alice")
        assert user["password"] == "hash123"
    
    def test_get_nonexistent_user(self, db):
        """Test get nonexistent user returns None."""
        user = db.get_user("nobody")
        assert user is None
    
    def test_update_user(self, db):
        """Test update user."""
        db.create_user("alice", {"password": "hash123"})
        db.update_user("alice", {"password": "newhash"})
        user = db.get_user("alice")
        assert user["password"] == "newhash"
    
    def test_delete_user(self, db):
        """Test delete user."""
        db.create_user("alice", {"password": "hash123"})
        result = db.delete_user("alice")
        assert result == True
        assert db.get_user("alice") is None
    
    def test_list_users(self, db):
        """Test list users."""
        db.create_user("alice", {})
        db.create_user("bob", {})
        users = db.list_users()
        assert "alice" in users
        assert "bob" in users
    
    def test_store_session(self, db):
        """Test session storage."""
        db.store_session("token123", {"user": "alice"})
        session = db.get_session("token123")
        assert session["user"] == "alice"
    
    def test_delete_session(self, db):
        """Test session deletion."""
        db.store_session("token123", {"user": "alice"})
        result = db.delete_session("token123")
        assert result == True
        assert db.get_session("token123") is None
    
    def test_store_key(self, db):
        """Test key storage."""
        db.store_key("key1", {"data": "secret"})
        key = db.get_key("key1")
        assert key["data"] == "secret"
    
    def test_save_load_blockchain(self, db):
        """Test blockchain persistence."""
        blockchain_data = {"chain": [], "difficulty": 4}
        db.save_blockchain(blockchain_data)
        loaded = db.load_blockchain()
        assert loaded["difficulty"] == 4
    
    def test_store_message(self, db):
        """Test message storage."""
        db.store_message("msg1", {"sender": "alice", "recipient": "bob"})
        msg = db.get_message("msg1")
        assert msg["sender"] == "alice"
    
    def test_get_user_messages(self, db):
        """Test get user messages."""
        db.store_message("msg1", {"sender": "alice", "recipient": "bob"})
        db.store_message("msg2", {"sender": "charlie", "recipient": "bob"})
        messages = db.get_user_messages("bob")
        assert len(messages) == 2
    
    def test_set_get(self, db):
        """Test generic set/get."""
        db.set("custom_key", {"value": 123})
        result = db.get("custom_key")
        assert result["value"] == 123
    
    def test_clear(self, db):
        """Test clear database."""
        db.create_user("alice", {})
        db.clear()
        assert db.get_user("alice") is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])