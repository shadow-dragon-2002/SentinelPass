"""
Master password authentication module for SentinelPass Password Manager.

This module handles master password authentication, session management,
and security features like auto-lock and failed attempt tracking.

Security Features:
- Secure password verification with timing attack protection
- Session timeout management
- Failed attempt tracking and lockout
- Secure memory handling for passwords
- Auto-lock functionality

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import time
import threading
import logging
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, Any
from dataclasses import dataclass

from config.settings import settings
from core.encryption import crypto_manager


class AuthenticationError(Exception):
    """Custom exception for authentication-related errors."""
    pass


class SessionExpiredError(Exception):
    """Custom exception for expired session errors."""
    pass


@dataclass
class AuthSession:
    """
    Data class representing an authentication session.
    
    Contains session information including creation time, last activity,
    and session validity status.
    """
    session_id: str
    created_at: datetime
    last_activity: datetime
    is_active: bool = True
    master_password_hash: Optional[str] = None
    
    def is_expired(self) -> bool:
        """Check if session has expired based on timeout settings."""
        timeout_minutes = settings.SESSION_TIMEOUT_MINUTES
        expiry_time = self.last_activity + timedelta(minutes=timeout_minutes)
        return datetime.now() > expiry_time
        
    def update_activity(self):
        """Update last activity timestamp."""
        self.last_activity = datetime.now()
        
    def invalidate(self):
        """Invalidate the session."""
        self.is_active = False


class MasterAuthManager:
    """
    Comprehensive master password authentication manager.
    
    This class handles all aspects of master password authentication including
    verification, session management, security features, and auto-lock functionality.
    """
    
    def __init__(self):
        """Initialize the master authentication manager."""
        self.logger = logging.getLogger(__name__)
        self.current_session: Optional[AuthSession] = None
        self.failed_attempts: Dict[str, int] = {}
        self.lockout_times: Dict[str, datetime] = {}
        self._session_lock = threading.Lock()
        self._auto_lock_timer: Optional[threading.Timer] = None
        
        # Callbacks for session events
        self.on_session_expired = None
        self.on_auto_lock = None
        self.on_authentication_failed = None
        
        self.logger.info("MasterAuthManager initialized")
        
    def authenticate(self, master_password: str, client_id: str = "default") -> bool:
        """
        Authenticate user with master password.
        
        Args:
            master_password (str): Master password to verify
            client_id (str): Client identifier for tracking attempts
            
        Returns:
            bool: True if authentication successful
            
        Raises:
            AuthenticationError: If authentication fails due to lockout or other issues
        """
        try:
            with self._session_lock:
                # Check if client is locked out
                if self._is_locked_out(client_id):
                    lockout_remaining = self._get_lockout_remaining(client_id)
                    raise AuthenticationError(
                        f"Account locked due to too many failed attempts. "
                        f"Try again in {lockout_remaining} minutes."
                    )
                
                # Verify master password
                if self._verify_master_password(master_password):
                    # Clear failed attempts on successful authentication
                    self._clear_failed_attempts(client_id)
                    
                    # Create new session
                    self._create_session(master_password)
                    
                    # Start auto-lock timer
                    self._start_auto_lock_timer()
                    
                    self.logger.info(f"Authentication successful for client: {client_id}")
                    return True
                else:
                    # Record failed attempt
                    self._record_failed_attempt(client_id)
                    
                    # Trigger callback if set
                    if self.on_authentication_failed:
                        self.on_authentication_failed(client_id)
                    
                    self.logger.warning(f"Authentication failed for client: {client_id}")
                    return False
                    
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            raise AuthenticationError(f"Authentication failed: {str(e)}")
            
    def _verify_master_password(self, password: str) -> bool:
        """
        Verify master password against stored hash.
        
        Args:
            password (str): Password to verify
            
        Returns:
            bool: True if password is correct
        """
        try:
            # This would typically verify against database
            # For now, we'll use a placeholder implementation
            # In real implementation, this would query the database
            from core.database import DatabaseManager
            
            # Create temporary database connection to verify password
            import sqlite3
            import os
            
            db_path = settings.database_path
            if not os.path.exists(db_path):
                self.logger.warning(f"Database file not found: {db_path}")
                return False
                
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT password_hash, salt FROM master_auth WHERE id = 1")
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return False
                
            stored_hash, salt = result
            return crypto_manager.verify_password(password, stored_hash, salt)
            
        except Exception as e:
            self.logger.error(f"Password verification failed: {str(e)}")
            return False
            
    def _create_session(self, master_password: str):
        """Create a new authentication session."""
        session_id = crypto_manager.generate_secure_token(16)
        
        self.current_session = AuthSession(
            session_id=session_id,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            is_active=True
        )
        
        self.logger.info(f"New session created: {session_id[:8]}...")
        
    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated.
        
        Returns:
            bool: True if authenticated and session is valid
        """
        with self._session_lock:
            if not self.current_session:
                return False
                
            if not self.current_session.is_active:
                return False
                
            if self.current_session.is_expired():
                self._expire_session()
                return False
                
            # Update activity timestamp
            self.current_session.update_activity()
            self._restart_auto_lock_timer()
            
            return True
            
    def get_session_info(self) -> Optional[Dict[str, Any]]:
        """
        Get current session information.
        
        Returns:
            Optional[Dict[str, Any]]: Session information or None if not authenticated
        """
        if not self.is_authenticated():
            return None
            
        return {
            'session_id': self.current_session.session_id[:8] + "...",
            'created_at': self.current_session.created_at.isoformat(),
            'last_activity': self.current_session.last_activity.isoformat(),
            'expires_at': (self.current_session.last_activity + 
                          timedelta(minutes=settings.SESSION_TIMEOUT_MINUTES)).isoformat()
        }
        
    def logout(self):
        """Logout and invalidate current session."""
        with self._session_lock:
            if self.current_session:
                self.current_session.invalidate()
                session_id = self.current_session.session_id
                self.current_session = None
                
                # Stop auto-lock timer
                self._stop_auto_lock_timer()
                
                self.logger.info(f"Session logged out: {session_id[:8]}...")
                
    def _expire_session(self):
        """Expire current session due to timeout."""
        if self.current_session:
            session_id = self.current_session.session_id
            self.current_session.invalidate()
            self.current_session = None
            
            # Stop auto-lock timer
            self._stop_auto_lock_timer()
            
            # Trigger callback if set
            if self.on_session_expired:
                self.on_session_expired()
                
            self.logger.info(f"Session expired: {session_id[:8]}...")
            
    def _is_locked_out(self, client_id: str) -> bool:
        """Check if client is currently locked out."""
        if client_id not in self.lockout_times:
            return False
            
        lockout_time = self.lockout_times[client_id]
        lockout_duration = timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
        
        return datetime.now() < lockout_time + lockout_duration
        
    def _get_lockout_remaining(self, client_id: str) -> int:
        """Get remaining lockout time in minutes."""
        if client_id not in self.lockout_times:
            return 0
            
        lockout_time = self.lockout_times[client_id]
        lockout_duration = timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
        remaining = (lockout_time + lockout_duration) - datetime.now()
        
        return max(0, int(remaining.total_seconds() / 60))
        
    def _record_failed_attempt(self, client_id: str):
        """Record a failed authentication attempt."""
        if client_id not in self.failed_attempts:
            self.failed_attempts[client_id] = 0
            
        self.failed_attempts[client_id] += 1
        
        # Check if lockout threshold reached
        if self.failed_attempts[client_id] >= settings.MAX_LOGIN_ATTEMPTS:
            self.lockout_times[client_id] = datetime.now()
            self.logger.warning(f"Client locked out due to failed attempts: {client_id}")
            
    def _clear_failed_attempts(self, client_id: str):
        """Clear failed attempts for successful authentication."""
        if client_id in self.failed_attempts:
            del self.failed_attempts[client_id]
        if client_id in self.lockout_times:
            del self.lockout_times[client_id]
            
    def get_failed_attempts(self, client_id: str = "default") -> int:
        """
        Get number of failed attempts for client.
        
        Args:
            client_id (str): Client identifier
            
        Returns:
            int: Number of failed attempts
        """
        return self.failed_attempts.get(client_id, 0)
        
    def _start_auto_lock_timer(self):
        """Start auto-lock timer."""
        self._stop_auto_lock_timer()  # Stop existing timer
        
        timeout_seconds = settings.SESSION_TIMEOUT_MINUTES * 60
        self._auto_lock_timer = threading.Timer(timeout_seconds, self._auto_lock)
        self._auto_lock_timer.daemon = True
        self._auto_lock_timer.start()
        
    def _restart_auto_lock_timer(self):
        """Restart auto-lock timer due to activity."""
        if self.current_session and self.current_session.is_active:
            self._start_auto_lock_timer()
            
    def _stop_auto_lock_timer(self):
        """Stop auto-lock timer."""
        if self._auto_lock_timer:
            self._auto_lock_timer.cancel()
            self._auto_lock_timer = None
            
    def _auto_lock(self):
        """Auto-lock due to inactivity."""
        with self._session_lock:
            if self.current_session and self.current_session.is_active:
                self._expire_session()
                
                # Trigger callback if set
                if self.on_auto_lock:
                    self.on_auto_lock()
                    
                self.logger.info("Auto-lock triggered due to inactivity")
                
    def change_master_password(self, current_password: str, new_password: str) -> bool:
        """
        Change master password.
        
        Args:
            current_password (str): Current master password
            new_password (str): New master password
            
        Returns:
            bool: True if password changed successfully
            
        Raises:
            AuthenticationError: If current password is incorrect or change fails
        """
        try:
            # Verify current password
            if not self._verify_master_password(current_password):
                raise AuthenticationError("Current password is incorrect")
                
            # Validate new password
            is_valid, errors = settings.validate_master_password(new_password)
            if not is_valid:
                raise AuthenticationError(f"New password does not meet requirements: {', '.join(errors)}")
                
            # Update password in database
            password_hash, salt = crypto_manager.hash_password(new_password)
            
            import sqlite3
            conn = sqlite3.connect(settings.database_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                UPDATE master_auth 
                SET password_hash = ?, salt = ?, updated_at = CURRENT_TIMESTAMP 
                WHERE id = 1
            """, (password_hash, salt))
            
            conn.commit()
            conn.close()
            
            # Invalidate current session to force re-authentication
            self.logout()
            
            self.logger.info("Master password changed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Password change failed: {str(e)}")
            raise AuthenticationError(f"Failed to change password: {str(e)}")
            
    def get_security_status(self) -> Dict[str, Any]:
        """
        Get comprehensive security status information.
        
        Returns:
            Dict[str, Any]: Security status information
        """
        status = {
            'authenticated': self.is_authenticated(),
            'session_active': self.current_session is not None and self.current_session.is_active,
            'session_info': self.get_session_info(),
            'failed_attempts': dict(self.failed_attempts),
            'locked_clients': [],
            'auto_lock_enabled': settings.SESSION_TIMEOUT_MINUTES > 0,
            'session_timeout_minutes': settings.SESSION_TIMEOUT_MINUTES,
            'max_login_attempts': settings.MAX_LOGIN_ATTEMPTS,
            'lockout_duration_minutes': settings.LOCKOUT_DURATION_MINUTES
        }
        
        # Get locked clients
        current_time = datetime.now()
        for client_id, lockout_time in self.lockout_times.items():
            lockout_duration = timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
            if current_time < lockout_time + lockout_duration:
                remaining_minutes = int(((lockout_time + lockout_duration) - current_time).total_seconds() / 60)
                status['locked_clients'].append({
                    'client_id': client_id,
                    'remaining_minutes': remaining_minutes
                })
                
        return status
        
    def cleanup(self):
        """Cleanup resources and stop timers."""
        self._stop_auto_lock_timer()
        if self.current_session:
            self.current_session.invalidate()
            self.current_session = None
            
        self.logger.info("MasterAuthManager cleanup completed")


# Global authentication manager instance
auth_manager = MasterAuthManager()
