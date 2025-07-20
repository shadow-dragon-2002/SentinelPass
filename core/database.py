"""
Database management module for SentinelPass Password Manager.

This module handles all database operations including initialization, CRUD operations
for password entries, and secure data storage with encryption. It uses SQLite for
local storage with encrypted sensitive fields.

Security Features:
- Encrypted storage of sensitive data
- Prepared statements to prevent SQL injection
- Secure database initialization
- Data integrity validation
- Transaction management

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sqlite3
import json
import logging
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple, Any
from pathlib import Path
import threading

from config.settings import settings
from core.encryption import crypto_manager, EncryptionError, DecryptionError


class DatabaseError(Exception):
    """Custom exception for database-related errors."""
    pass


class PasswordEntry:
    """
    Data class representing a password entry.
    
    This class encapsulates all information related to a stored password
    including metadata and provides methods for serialization.
    """
    
    def __init__(self, entry_id: Optional[int] = None, title: str = "", 
                 username: str = "", password: str = "", url: str = "", 
                 notes: str = "", category: str = "General", 
                 created_at: Optional[datetime] = None, 
                 updated_at: Optional[datetime] = None,
                 last_accessed: Optional[datetime] = None):
        """
        Initialize a password entry.
        
        Args:
            entry_id (int, optional): Unique identifier
            title (str): Entry title/name
            username (str): Username/email
            password (str): Password
            url (str): Associated URL
            notes (str): Additional notes
            category (str): Entry category
            created_at (datetime, optional): Creation timestamp
            updated_at (datetime, optional): Last update timestamp
            last_accessed (datetime, optional): Last access timestamp
        """
        self.entry_id = entry_id
        self.title = title
        self.username = username
        self.password = password
        self.url = url
        self.notes = notes
        self.category = category
        self.created_at = created_at or datetime.now(timezone.utc)
        self.updated_at = updated_at or datetime.now(timezone.utc)
        self.last_accessed = last_accessed
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert entry to dictionary representation."""
        return {
            'entry_id': self.entry_id,
            'title': self.title,
            'username': self.username,
            'password': self.password,
            'url': self.url,
            'notes': self.notes,
            'category': self.category,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PasswordEntry':
        """Create entry from dictionary representation."""
        entry = cls()
        entry.entry_id = data.get('entry_id')
        entry.title = data.get('title', '')
        entry.username = data.get('username', '')
        entry.password = data.get('password', '')
        entry.url = data.get('url', '')
        entry.notes = data.get('notes', '')
        entry.category = data.get('category', 'General')
        
        # Parse timestamps
        if data.get('created_at'):
            entry.created_at = datetime.fromisoformat(data['created_at'])
        if data.get('updated_at'):
            entry.updated_at = datetime.fromisoformat(data['updated_at'])
        if data.get('last_accessed'):
            entry.last_accessed = datetime.fromisoformat(data['last_accessed'])
            
        return entry


class DatabaseManager:
    """
    Comprehensive database manager for SentinelPass.
    
    This class handles all database operations including initialization,
    password entry management, and secure data storage with encryption.
    """
    
    def __init__(self):
        """Initialize the database manager."""
        self.logger = logging.getLogger(__name__)
        self.db_path = settings.database_path
        self.connection = None
        self.master_password = None
        self._lock = threading.Lock()
        
        # Database schema version for future migrations
        self.schema_version = 1
        
        self.logger.info(f"DatabaseManager initialized with database: {self.db_path}")
        
    def is_initialized(self) -> bool:
        """
        Check if the database is initialized.
        
        Returns:
            bool: True if database exists and is properly initialized
        """
        db_file = Path(self.db_path)
        if not db_file.exists():
            return False
            
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT name FROM sqlite_master 
                    WHERE type='table' AND name='password_entries'
                """)
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            self.logger.error(f"Database check failed: {str(e)}")
            return False
            
    def initialize_database(self, master_password: str) -> bool:
        """
        Initialize the database with master password.
        
        Args:
            master_password (str): Master password for encryption
            
        Returns:
            bool: True if initialization successful
        """
        try:
            with self._lock:
                self.master_password = master_password
                
                # Create database connection
                self.connection = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                self.connection.row_factory = sqlite3.Row
                
                # Enable foreign keys and WAL mode for better performance
                self.connection.execute("PRAGMA foreign_keys = ON")
                self.connection.execute("PRAGMA journal_mode = WAL")
                self.connection.execute("PRAGMA synchronous = NORMAL")
                
                # Create tables
                self._create_tables()
                
                # Store master password hash for verification
                self._store_master_password_hash(master_password)
                
                self.logger.info("Database initialized successfully")
                return True
                
        except Exception as e:
            self.logger.error(f"Database initialization failed: {str(e)}")
            if self.connection:
                self.connection.close()
                self.connection = None
            return False
            
    def _create_tables(self):
        """Create database tables with proper schema."""
        cursor = self.connection.cursor()
        
        # Password entries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS password_entries (
                entry_id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                username_encrypted TEXT,
                password_encrypted TEXT NOT NULL,
                url TEXT,
                notes_encrypted TEXT,
                category TEXT DEFAULT 'General',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_accessed TIMESTAMP,
                UNIQUE(title, username_encrypted)
            )
        """)
        
        # Master password verification table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS master_auth (
                id INTEGER PRIMARY KEY,
                password_hash BLOB NOT NULL,
                salt BLOB NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Application metadata table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_title ON password_entries(title)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_category ON password_entries(category)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_entries_updated ON password_entries(updated_at)")
        
        # Store schema version
        cursor.execute("""
            INSERT OR REPLACE INTO app_metadata (key, value) 
            VALUES ('schema_version', ?)
        """, (str(self.schema_version),))
        
        self.connection.commit()
        self.logger.info("Database tables created successfully")
        
    def _store_master_password_hash(self, master_password: str):
        """Store master password hash for verification."""
        password_hash, salt = crypto_manager.hash_password(master_password)
        
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO master_auth (id, password_hash, salt) 
            VALUES (1, ?, ?)
        """, (password_hash, salt))
        
        self.connection.commit()
        self.logger.info("Master password hash stored")
        
    def connect(self, master_password: str) -> bool:
        """
        Connect to existing database with master password.
        
        Args:
            master_password (str): Master password for authentication
            
        Returns:
            bool: True if connection successful
        """
        try:
            with self._lock:
                # Verify master password first
                if not self._verify_master_password(master_password):
                    self.logger.error("Master password verification failed")
                    return False
                    
                self.master_password = master_password
                
                # Create database connection
                self.connection = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                self.connection.row_factory = sqlite3.Row
                
                # Configure database
                self.connection.execute("PRAGMA foreign_keys = ON")
                self.connection.execute("PRAGMA journal_mode = WAL")
                
                self.logger.info("Database connection established")
                return True
                
        except Exception as e:
            self.logger.error(f"Database connection failed: {str(e)}")
            return False
            
    def _verify_master_password(self, password: str) -> bool:
        """Verify master password against stored hash."""
        try:
            temp_conn = sqlite3.connect(self.db_path)
            cursor = temp_conn.cursor()
            
            cursor.execute("SELECT password_hash, salt FROM master_auth WHERE id = 1")
            result = cursor.fetchone()
            temp_conn.close()
            
            if not result:
                return False
                
            stored_hash, salt = result
            return crypto_manager.verify_password(password, stored_hash, salt)
            
        except Exception as e:
            self.logger.error(f"Master password verification error: {str(e)}")
            return False
            
    def add_password_entry(self, entry: PasswordEntry) -> Optional[int]:
        """
        Add a new password entry to the database.
        
        Args:
            entry (PasswordEntry): Password entry to add
            
        Returns:
            Optional[int]: Entry ID if successful, None otherwise
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                # Encrypt sensitive fields
                username_encrypted = crypto_manager.encrypt_string(
                    entry.username, self.master_password
                ) if entry.username else ""
                
                password_encrypted = crypto_manager.encrypt_string(
                    entry.password, self.master_password
                )
                
                notes_encrypted = crypto_manager.encrypt_string(
                    entry.notes, self.master_password
                ) if entry.notes else ""
                
                # Insert entry
                cursor = self.connection.cursor()
                cursor.execute("""
                    INSERT INTO password_entries 
                    (title, username_encrypted, password_encrypted, url, 
                     notes_encrypted, category, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    entry.title,
                    username_encrypted,
                    password_encrypted,
                    entry.url,
                    notes_encrypted,
                    entry.category,
                    entry.created_at.isoformat(),
                    entry.updated_at.isoformat()
                ))
                
                entry_id = cursor.lastrowid
                self.connection.commit()
                
                self.logger.info(f"Password entry added with ID: {entry_id}")
                return entry_id
                
        except sqlite3.IntegrityError as e:
            self.logger.error(f"Duplicate entry error: {str(e)}")
            raise DatabaseError("Entry with this title and username already exists")
        except (EncryptionError, sqlite3.Error) as e:
            self.logger.error(f"Failed to add password entry: {str(e)}")
            raise DatabaseError(f"Failed to add password entry: {str(e)}")
            
    def get_password_entry(self, entry_id: int) -> Optional[PasswordEntry]:
        """
        Retrieve a password entry by ID.
        
        Args:
            entry_id (int): Entry ID to retrieve
            
        Returns:
            Optional[PasswordEntry]: Password entry if found, None otherwise
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                cursor = self.connection.cursor()
                cursor.execute("""
                    SELECT * FROM password_entries WHERE entry_id = ?
                """, (entry_id,))
                
                row = cursor.fetchone()
                if not row:
                    return None
                    
                # Update last accessed timestamp
                cursor.execute("""
                    UPDATE password_entries 
                    SET last_accessed = ? 
                    WHERE entry_id = ?
                """, (datetime.now(timezone.utc).isoformat(), entry_id))
                self.connection.commit()
                
                return self._row_to_entry(row)
                
        except (DecryptionError, sqlite3.Error) as e:
            self.logger.error(f"Failed to get password entry: {str(e)}")
            raise DatabaseError(f"Failed to retrieve password entry: {str(e)}")
            
    def get_all_password_entries(self) -> List[PasswordEntry]:
        """
        Retrieve all password entries.
        
        Returns:
            List[PasswordEntry]: List of all password entries
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                cursor = self.connection.cursor()
                cursor.execute("""
                    SELECT * FROM password_entries 
                    ORDER BY updated_at DESC
                """)
                
                entries = []
                for row in cursor.fetchall():
                    try:
                        entry = self._row_to_entry(row)
                        entries.append(entry)
                    except DecryptionError as e:
                        self.logger.warning(f"Failed to decrypt entry {row['entry_id']}: {str(e)}")
                        continue
                        
                self.logger.info(f"Retrieved {len(entries)} password entries")
                return entries
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get password entries: {str(e)}")
            raise DatabaseError(f"Failed to retrieve password entries: {str(e)}")
            
    def search_password_entries(self, query: str) -> List[PasswordEntry]:
        """
        Search password entries by title, URL, or category.
        
        Args:
            query (str): Search query
            
        Returns:
            List[PasswordEntry]: Matching password entries
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                cursor = self.connection.cursor()
                search_pattern = f"%{query}%"
                
                cursor.execute("""
                    SELECT * FROM password_entries 
                    WHERE title LIKE ? OR url LIKE ? OR category LIKE ?
                    ORDER BY title
                """, (search_pattern, search_pattern, search_pattern))
                
                entries = []
                for row in cursor.fetchall():
                    try:
                        entry = self._row_to_entry(row)
                        entries.append(entry)
                    except DecryptionError:
                        continue
                        
                self.logger.info(f"Search returned {len(entries)} entries for query: {query}")
                return entries
                
        except sqlite3.Error as e:
            self.logger.error(f"Search failed: {str(e)}")
            raise DatabaseError(f"Search failed: {str(e)}")
            
    def update_password_entry(self, entry: PasswordEntry) -> bool:
        """
        Update an existing password entry.
        
        Args:
            entry (PasswordEntry): Updated password entry
            
        Returns:
            bool: True if update successful
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                if not entry.entry_id:
                    raise DatabaseError("Entry ID required for update")
                    
                # Encrypt sensitive fields
                username_encrypted = crypto_manager.encrypt_string(
                    entry.username, self.master_password
                ) if entry.username else ""
                
                password_encrypted = crypto_manager.encrypt_string(
                    entry.password, self.master_password
                )
                
                notes_encrypted = crypto_manager.encrypt_string(
                    entry.notes, self.master_password
                ) if entry.notes else ""
                
                # Update entry
                cursor = self.connection.cursor()
                cursor.execute("""
                    UPDATE password_entries 
                    SET title = ?, username_encrypted = ?, password_encrypted = ?,
                        url = ?, notes_encrypted = ?, category = ?, updated_at = ?
                    WHERE entry_id = ?
                """, (
                    entry.title,
                    username_encrypted,
                    password_encrypted,
                    entry.url,
                    notes_encrypted,
                    entry.category,
                    datetime.now(timezone.utc).isoformat(),
                    entry.entry_id
                ))
                
                success = cursor.rowcount > 0
                self.connection.commit()
                
                if success:
                    self.logger.info(f"Password entry {entry.entry_id} updated")
                else:
                    self.logger.warning(f"No entry found with ID {entry.entry_id}")
                    
                return success
                
        except (EncryptionError, sqlite3.Error) as e:
            self.logger.error(f"Failed to update password entry: {str(e)}")
            raise DatabaseError(f"Failed to update password entry: {str(e)}")
            
    def delete_password_entry(self, entry_id: int) -> bool:
        """
        Delete a password entry.
        
        Args:
            entry_id (int): ID of entry to delete
            
        Returns:
            bool: True if deletion successful
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                cursor = self.connection.cursor()
                cursor.execute("DELETE FROM password_entries WHERE entry_id = ?", (entry_id,))
                
                success = cursor.rowcount > 0
                self.connection.commit()
                
                if success:
                    self.logger.info(f"Password entry {entry_id} deleted")
                else:
                    self.logger.warning(f"No entry found with ID {entry_id}")
                    
                return success
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to delete password entry: {str(e)}")
            raise DatabaseError(f"Failed to delete password entry: {str(e)}")
            
    def get_categories(self) -> List[str]:
        """
        Get all unique categories.
        
        Returns:
            List[str]: List of categories
        """
        try:
            with self._lock:
                if not self.connection:
                    raise DatabaseError("Database not connected")
                    
                cursor = self.connection.cursor()
                cursor.execute("SELECT DISTINCT category FROM password_entries ORDER BY category")
                
                categories = [row[0] for row in cursor.fetchall()]
                return categories
                
        except sqlite3.Error as e:
            self.logger.error(f"Failed to get categories: {str(e)}")
            return []
            
    def _row_to_entry(self, row) -> PasswordEntry:
        """Convert database row to PasswordEntry object."""
        # Decrypt sensitive fields
        username = ""
        if row['username_encrypted']:
            username = crypto_manager.decrypt_string(
                row['username_encrypted'], self.master_password
            )
            
        password = crypto_manager.decrypt_string(
            row['password_encrypted'], self.master_password
        )
        
        notes = ""
        if row['notes_encrypted']:
            notes = crypto_manager.decrypt_string(
                row['notes_encrypted'], self.master_password
            )
            
        # Parse timestamps and ensure they are timezone-aware
        created_at = None
        if row['created_at']:
            created_at = datetime.fromisoformat(row['created_at'])
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)
                
        updated_at = None
        if row['updated_at']:
            updated_at = datetime.fromisoformat(row['updated_at'])
            if updated_at.tzinfo is None:
                updated_at = updated_at.replace(tzinfo=timezone.utc)
                
        last_accessed = None
        if row['last_accessed']:
            last_accessed = datetime.fromisoformat(row['last_accessed'])
            if last_accessed.tzinfo is None:
                last_accessed = last_accessed.replace(tzinfo=timezone.utc)
        
        return PasswordEntry(
            entry_id=row['entry_id'],
            title=row['title'],
            username=username,
            password=password,
            url=row['url'] or "",
            notes=notes,
            category=row['category'] or "General",
            created_at=created_at,
            updated_at=updated_at,
            last_accessed=last_accessed
        )
        
    def export_data(self) -> Dict[str, Any]:
        """
        Export all data for backup purposes.
        
        Returns:
            Dict[str, Any]: Exported data structure
        """
        try:
            entries = self.get_all_password_entries()
            
            export_data = {
                'version': self.schema_version,
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'entries': [entry.to_dict() for entry in entries]
            }
            
            self.logger.info(f"Exported {len(entries)} entries")
            return export_data
            
        except Exception as e:
            self.logger.error(f"Data export failed: {str(e)}")
            raise DatabaseError(f"Failed to export data: {str(e)}")
            
    def import_data(self, data: Dict[str, Any]) -> int:
        """
        Import data from backup.
        
        Args:
            data (Dict[str, Any]): Data to import
            
        Returns:
            int: Number of entries imported
        """
        try:
            entries_data = data.get('entries', [])
            imported_count = 0
            
            for entry_data in entries_data:
                try:
                    entry = PasswordEntry.from_dict(entry_data)
                    entry.entry_id = None  # Let database assign new ID
                    self.add_password_entry(entry)
                    imported_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to import entry: {str(e)}")
                    continue
                    
            self.logger.info(f"Imported {imported_count} entries")
            return imported_count
            
        except Exception as e:
            self.logger.error(f"Data import failed: {str(e)}")
            raise DatabaseError(f"Failed to import data: {str(e)}")
            
    def close(self):
        """Close database connection and cleanup."""
        with self._lock:
            if self.connection:
                self.connection.close()
                self.connection = None
                
            # Clear master password from memory
            if self.master_password:
                self.master_password = None
                
            self.logger.info("Database connection closed")
