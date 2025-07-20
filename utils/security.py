"""
Security utilities for SentinelPass Password Manager.

This module provides additional security utilities including secure memory
handling, timing attack prevention, security monitoring, and other
security-related helper functions.

Security Features:
- Secure memory operations
- Timing attack prevention
- Security event logging
- Input sanitization helpers
- Security policy enforcement

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import os
import time
import secrets
import hashlib
import logging
import threading
from typing import Any, Optional, Dict, List, Callable, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass
from enum import Enum

from config.settings import settings


class SecurityLevel(Enum):
    """Security event severity levels."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class SecurityEvent:
    """Security event data structure."""
    timestamp: datetime
    event_type: str
    level: SecurityLevel
    description: str
    source: str
    metadata: Dict[str, Any]


class SecurityError(Exception):
    """Custom exception for security-related errors."""
    pass


class SecureMemoryManager:
    """
    Secure memory management utilities.
    
    Provides utilities for secure handling of sensitive data in memory
    including secure deletion and memory protection.
    """
    
    def __init__(self):
        """Initialize secure memory manager."""
        self.logger = logging.getLogger(__name__)
        self._sensitive_refs = set()
        self._lock = threading.Lock()
        
    def register_sensitive_data(self, data_ref: Any):
        """
        Register sensitive data reference for tracking.
        
        Args:
            data_ref: Reference to sensitive data
        """
        with self._lock:
            self._sensitive_refs.add(id(data_ref))
            
    def unregister_sensitive_data(self, data_ref: Any):
        """
        Unregister sensitive data reference.
        
        Args:
            data_ref: Reference to sensitive data
        """
        with self._lock:
            self._sensitive_refs.discard(id(data_ref))
            
    def secure_zero_memory(self, data: bytearray) -> bool:
        """
        Securely zero out memory.
        
        Args:
            data (bytearray): Data to zero out
            
        Returns:
            bool: True if successful
        """
        try:
            if isinstance(data, bytearray):
                # Overwrite with zeros multiple times
                for _ in range(3):
                    for i in range(len(data)):
                        data[i] = 0
                        
                # Overwrite with random data
                for i in range(len(data)):
                    data[i] = secrets.randbits(8)
                    
                # Final zero pass
                for i in range(len(data)):
                    data[i] = 0
                    
                return True
            else:
                self.logger.warning("Cannot securely zero non-bytearray data")
                return False
                
        except Exception as e:
            self.logger.error(f"Secure memory zeroing failed: {str(e)}")
            return False
            
    def create_secure_string(self, data: str) -> bytearray:
        """
        Create secure string as bytearray for better memory control.
        
        Args:
            data (str): String data
            
        Returns:
            bytearray: Secure string representation
        """
        secure_data = bytearray(data.encode('utf-8'))
        self.register_sensitive_data(secure_data)
        return secure_data
        
    def cleanup_all_sensitive_data(self):
        """Cleanup all registered sensitive data."""
        with self._lock:
            self.logger.info(f"Cleaning up {len(self._sensitive_refs)} sensitive data references")
            self._sensitive_refs.clear()


class TimingAttackPrevention:
    """
    Utilities to prevent timing attacks.
    
    Provides constant-time operations and timing attack prevention
    for sensitive comparisons and operations.
    """
    
    @staticmethod
    def constant_time_compare(a: bytes, b: bytes) -> bool:
        """
        Perform constant-time comparison of byte sequences.
        
        Args:
            a (bytes): First byte sequence
            b (bytes): Second byte sequence
            
        Returns:
            bool: True if sequences are equal
        """
        return secrets.compare_digest(a, b)
        
    @staticmethod
    def constant_time_string_compare(a: str, b: str) -> bool:
        """
        Perform constant-time comparison of strings.
        
        Args:
            a (str): First string
            b (str): Second string
            
        Returns:
            bool: True if strings are equal
        """
        return secrets.compare_digest(a.encode('utf-8'), b.encode('utf-8'))
        
    @staticmethod
    def add_timing_delay(min_ms: int = 100, max_ms: int = 500):
        """
        Add random timing delay to prevent timing analysis.
        
        Args:
            min_ms (int): Minimum delay in milliseconds
            max_ms (int): Maximum delay in milliseconds
        """
        delay_ms = secrets.randbelow(max_ms - min_ms + 1) + min_ms
        time.sleep(delay_ms / 1000.0)


class SecurityMonitor:
    """
    Security event monitoring and logging system.
    
    Monitors security events, tracks suspicious activities,
    and provides security alerting capabilities.
    """
    
    def __init__(self):
        """Initialize security monitor."""
        self.logger = logging.getLogger(__name__)
        self._events: List[SecurityEvent] = []
        self._event_handlers: Dict[str, List[Callable]] = {}
        self._lock = threading.Lock()
        self._max_events = 1000
        
        self.logger.info("SecurityMonitor initialized")
        
    def log_security_event(self, event_type: str, level: SecurityLevel,
                          description: str, source: str = "unknown",
                          metadata: Optional[Dict[str, Any]] = None):
        """
        Log a security event.
        
        Args:
            event_type (str): Type of security event
            level (SecurityLevel): Severity level
            description (str): Event description
            source (str): Event source
            metadata (dict, optional): Additional event metadata
        """
        event = SecurityEvent(
            timestamp=datetime.now(),
            event_type=event_type,
            level=level,
            description=description,
            source=source,
            metadata=metadata or {}
        )
        
        with self._lock:
            self._events.append(event)
            
            # Limit event history
            if len(self._events) > self._max_events:
                self._events.pop(0)
                
        # Log to standard logger
        log_level = {
            SecurityLevel.LOW: logging.INFO,
            SecurityLevel.MEDIUM: logging.WARNING,
            SecurityLevel.HIGH: logging.ERROR,
            SecurityLevel.CRITICAL: logging.CRITICAL
        }.get(level, logging.INFO)
        
        self.logger.log(log_level, f"SECURITY [{event_type}] {description} (source: {source})")
        
        # Trigger event handlers
        self._trigger_event_handlers(event)
        
    def _trigger_event_handlers(self, event: SecurityEvent):
        """Trigger registered event handlers."""
        handlers = self._event_handlers.get(event.event_type, [])
        handlers.extend(self._event_handlers.get('*', []))  # Global handlers
        
        for handler in handlers:
            try:
                handler(event)
            except Exception as e:
                self.logger.error(f"Security event handler failed: {str(e)}")
                
    def register_event_handler(self, event_type: str, handler: Callable[[SecurityEvent], None]):
        """
        Register security event handler.
        
        Args:
            event_type (str): Event type to handle ('*' for all events)
            handler: Handler function
        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []
        self._event_handlers[event_type].append(handler)
        
    def get_recent_events(self, hours: int = 24, 
                         min_level: SecurityLevel = SecurityLevel.LOW) -> List[SecurityEvent]:
        """
        Get recent security events.
        
        Args:
            hours (int): Number of hours to look back
            min_level (SecurityLevel): Minimum severity level
            
        Returns:
            List[SecurityEvent]: Recent security events
        """
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        with self._lock:
            return [
                event for event in self._events
                if event.timestamp >= cutoff_time and event.level.value >= min_level.value
            ]
            
    def get_security_summary(self) -> Dict[str, Any]:
        """
        Get security summary statistics.
        
        Returns:
            Dict[str, Any]: Security summary
        """
        with self._lock:
            recent_events = self.get_recent_events(24)
            
            summary = {
                'total_events': len(self._events),
                'recent_events_24h': len(recent_events),
                'events_by_level': {
                    'low': len([e for e in recent_events if e.level == SecurityLevel.LOW]),
                    'medium': len([e for e in recent_events if e.level == SecurityLevel.MEDIUM]),
                    'high': len([e for e in recent_events if e.level == SecurityLevel.HIGH]),
                    'critical': len([e for e in recent_events if e.level == SecurityLevel.CRITICAL])
                },
                'events_by_type': {}
            }
            
            # Count events by type
            for event in recent_events:
                event_type = event.event_type
                if event_type not in summary['events_by_type']:
                    summary['events_by_type'][event_type] = 0
                summary['events_by_type'][event_type] += 1
                
            return summary


class SecurityPolicyEnforcer:
    """
    Security policy enforcement utilities.
    
    Enforces security policies and provides policy validation
    for various security-related operations.
    """
    
    def __init__(self):
        """Initialize security policy enforcer."""
        self.logger = logging.getLogger(__name__)
        self._policies: Dict[str, Dict[str, Any]] = {}
        self._load_default_policies()
        
    def _load_default_policies(self):
        """Load default security policies."""
        self._policies = {
            'password_policy': {
                'min_length': settings.MIN_MASTER_PASSWORD_LENGTH,
                'require_uppercase': settings.REQUIRE_UPPERCASE,
                'require_lowercase': settings.REQUIRE_LOWERCASE,
                'require_digits': settings.REQUIRE_DIGITS,
                'require_special': settings.REQUIRE_SPECIAL_CHARS,
                'max_age_days': 90,  # Recommend password change
                'prevent_reuse_count': 5
            },
            'session_policy': {
                'max_idle_minutes': settings.SESSION_TIMEOUT_MINUTES,
                'max_session_hours': 8,
                'require_reauth_for_sensitive': True
            },
            'access_policy': {
                'max_failed_attempts': settings.MAX_LOGIN_ATTEMPTS,
                'lockout_duration_minutes': settings.LOCKOUT_DURATION_MINUTES,
                'require_secure_connection': True
            },
            'data_policy': {
                'encryption_required': True,
                'backup_encryption_required': True,
                'secure_deletion_required': True
            }
        }
        
    def validate_password_policy(self, password: str) -> Tuple[bool, List[str]]:
        """
        Validate password against security policy.
        
        Args:
            password (str): Password to validate
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, violations)
        """
        policy = self._policies['password_policy']
        violations = []
        
        if len(password) < policy['min_length']:
            violations.append(f"Password must be at least {policy['min_length']} characters")
            
        if policy['require_uppercase'] and not any(c.isupper() for c in password):
            violations.append("Password must contain uppercase letters")
            
        if policy['require_lowercase'] and not any(c.islower() for c in password):
            violations.append("Password must contain lowercase letters")
            
        if policy['require_digits'] and not any(c.isdigit() for c in password):
            violations.append("Password must contain digits")
            
        if policy['require_special'] and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            violations.append("Password must contain special characters")
            
        return len(violations) == 0, violations
        
    def check_session_policy(self, session_start: datetime, 
                           last_activity: datetime) -> Tuple[bool, List[str]]:
        """
        Check session against security policy.
        
        Args:
            session_start (datetime): Session start time
            last_activity (datetime): Last activity time
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, violations)
        """
        policy = self._policies['session_policy']
        violations = []
        now = datetime.now()
        
        # Check idle time
        idle_minutes = (now - last_activity).total_seconds() / 60
        if idle_minutes > policy['max_idle_minutes']:
            violations.append(f"Session idle for {idle_minutes:.1f} minutes (max: {policy['max_idle_minutes']})")
            
        # Check total session time
        session_hours = (now - session_start).total_seconds() / 3600
        if session_hours > policy['max_session_hours']:
            violations.append(f"Session active for {session_hours:.1f} hours (max: {policy['max_session_hours']})")
            
        return len(violations) == 0, violations
        
    def get_policy(self, policy_name: str) -> Optional[Dict[str, Any]]:
        """
        Get security policy by name.
        
        Args:
            policy_name (str): Name of policy
            
        Returns:
            Optional[Dict[str, Any]]: Policy configuration or None
        """
        return self._policies.get(policy_name)
        
    def update_policy(self, policy_name: str, policy_config: Dict[str, Any]):
        """
        Update security policy.
        
        Args:
            policy_name (str): Name of policy
            policy_config (Dict[str, Any]): Policy configuration
        """
        self._policies[policy_name] = policy_config
        self.logger.info(f"Security policy updated: {policy_name}")


class SecurityUtils:
    """
    General security utility functions.
    
    Provides various security-related utility functions for
    common security operations throughout the application.
    """
    
    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate cryptographically secure random token.
        
        Args:
            length (int): Token length in bytes
            
        Returns:
            str: Hex-encoded secure token
        """
        return secrets.token_hex(length)
        
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """
        Generate cryptographically secure password.
        
        Args:
            length (int): Password length
            
        Returns:
            str: Secure password
        """
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
        
    @staticmethod
    def hash_data(data: bytes, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Hash data with optional salt.
        
        Args:
            data (bytes): Data to hash
            salt (bytes, optional): Salt for hashing
            
        Returns:
            Tuple[bytes, bytes]: (hash, salt)
        """
        if salt is None:
            salt = secrets.token_bytes(32)
            
        hash_obj = hashlib.pbkdf2_hmac('sha256', data, salt, 100000)
        return hash_obj, salt
        
    @staticmethod
    def verify_hash(data: bytes, hash_value: bytes, salt: bytes) -> bool:
        """
        Verify data against hash.
        
        Args:
            data (bytes): Data to verify
            hash_value (bytes): Expected hash
            salt (bytes): Salt used for hashing
            
        Returns:
            bool: True if hash matches
        """
        computed_hash, _ = SecurityUtils.hash_data(data, salt)
        return secrets.compare_digest(computed_hash, hash_value)
        
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize filename for security.
        
        Args:
            filename (str): Filename to sanitize
            
        Returns:
            str: Sanitized filename
        """
        # Remove dangerous characters
        dangerous_chars = '<>:"/\\|?*\x00'
        for char in dangerous_chars:
            filename = filename.replace(char, '_')
            
        # Remove leading/trailing spaces and dots
        filename = filename.strip(' .')
        
        # Limit length
        if len(filename) > 255:
            name, ext = os.path.splitext(filename)
            filename = name[:255-len(ext)] + ext
            
        return filename
        
    @staticmethod
    def is_safe_path(path: str, base_path: str) -> bool:
        """
        Check if path is safe (no directory traversal).
        
        Args:
            path (str): Path to check
            base_path (str): Base path that should contain the path
            
        Returns:
            bool: True if path is safe
        """
        try:
            abs_path = os.path.abspath(path)
            abs_base = os.path.abspath(base_path)
            return abs_path.startswith(abs_base)
        except Exception:
            return False


# Global security instances
secure_memory = SecureMemoryManager()
timing_protection = TimingAttackPrevention()
security_monitor = SecurityMonitor()
security_policy = SecurityPolicyEnforcer()
security_utils = SecurityUtils()
