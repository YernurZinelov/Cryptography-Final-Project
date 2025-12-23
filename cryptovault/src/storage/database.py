"""JSON file-based storage for users, sessions, and blockchain."""
import os
import json
import threading
from typing import Optional, Any
from pathlib import Path


class Database:
    """
    Simple JSON file-based database.
    
    Thread-safe with file locking.
    
    Data structure:
    {
        "users": {...},
        "sessions": {...},
        "keys": {...},
        "blockchain": {...}
    }
    """
    
    def __init__(self, db_path: str = "cryptovault_data.json"):
        """
        Initialize database.
        
        Args:
            db_path: Path to JSON database file
        """
        self.db_path = Path(db_path)
        self._lock = threading.Lock()
        self._init_db()
    
    def _init_db(self) -> None:
        """Initialize database file if it doesn't exist."""
        if not self.db_path.exists():
            self._write_db({
                'users': {},
                'sessions': {},
                'keys': {},
                'blockchain': None,
                'messages': {}
            })
    
    def _read_db(self) -> dict:
        """Read database from file."""
        try:
            with open(self.db_path, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            return {
                'users': {},
                'sessions': {},
                'keys': {},
                'blockchain': None,
                'messages': {}
            }
    
    def _write_db(self, data: dict) -> None:
        """Write database to file."""
        with open(self.db_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    # User operations
    def create_user(self, username: str, user_data: dict) -> bool:
        """
        Create a new user.
        
        Args:
            username: Unique username
            user_data: User data dictionary
            
        Returns:
            True if created, False if exists
        """
        with self._lock:
            db = self._read_db()
            
            if username in db['users']:
                return False
            
            db['users'][username] = user_data
            self._write_db(db)
            return True
    
    def get_user(self, username: str) -> Optional[dict]:
        """Get user data by username."""
        with self._lock:
            db = self._read_db()
            return db['users'].get(username)
    
    def update_user(self, username: str, user_data: dict) -> bool:
        """Update user data."""
        with self._lock:
            db = self._read_db()
            
            if username not in db['users']:
                return False
            
            db['users'][username].update(user_data)
            self._write_db(db)
            return True
    
    def delete_user(self, username: str) -> bool:
        """Delete a user."""
        with self._lock:
            db = self._read_db()
            
            if username not in db['users']:
                return False
            
            del db['users'][username]
            self._write_db(db)
            return True
    
    def list_users(self) -> list[str]:
        """List all usernames."""
        with self._lock:
            db = self._read_db()
            return list(db['users'].keys())
    
    # Session operations
    def store_session(self, token: str, session_data: dict) -> None:
        """Store session data."""
        with self._lock:
            db = self._read_db()
            db['sessions'][token] = session_data
            self._write_db(db)
    
    def get_session(self, token: str) -> Optional[dict]:
        """Get session data."""
        with self._lock:
            db = self._read_db()
            return db['sessions'].get(token)
    
    def delete_session(self, token: str) -> bool:
        """Delete session."""
        with self._lock:
            db = self._read_db()
            
            if token not in db['sessions']:
                return False
            
            del db['sessions'][token]
            self._write_db(db)
            return True
    
    # Key storage
    def store_key(self, key_id: str, key_data: dict) -> None:
        """Store encrypted key data."""
        with self._lock:
            db = self._read_db()
            db['keys'][key_id] = key_data
            self._write_db(db)
    
    def get_key(self, key_id: str) -> Optional[dict]:
        """Get key data."""
        with self._lock:
            db = self._read_db()
            return db['keys'].get(key_id)
    
    # Blockchain operations
    def save_blockchain(self, blockchain_data: dict) -> None:
        """Save blockchain state."""
        with self._lock:
            db = self._read_db()
            db['blockchain'] = blockchain_data
            self._write_db(db)
    
    def load_blockchain(self) -> Optional[dict]:
        """Load blockchain state."""
        with self._lock:
            db = self._read_db()
            return db.get('blockchain')
    
    # Message operations
    def store_message(self, msg_id: str, message_data: dict) -> None:
        """Store encrypted message."""
        with self._lock:
            db = self._read_db()
            db['messages'][msg_id] = message_data
            self._write_db(db)
    
    def get_message(self, msg_id: str) -> Optional[dict]:
        """Get message data."""
        with self._lock:
            db = self._read_db()
            return db['messages'].get(msg_id)
    
    def get_user_messages(self, username: str) -> list[dict]:
        """Get all messages for a user."""
        with self._lock:
            db = self._read_db()
            return [
                msg for msg in db['messages'].values()
                if msg.get('recipient') == username or msg.get('sender') == username
            ]
    
    # Generic operations
    def set(self, key: str, value: Any) -> None:
        """Set arbitrary key-value."""
        with self._lock:
            db = self._read_db()
            db[key] = value
            self._write_db(db)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get arbitrary value."""
        with self._lock:
            db = self._read_db()
            return db.get(key, default)
    
    def clear(self) -> None:
        """Clear all data."""
        with self._lock:
            self._write_db({
                'users': {},
                'sessions': {},
                'keys': {},
                'blockchain': None,
                'messages': {}
            })