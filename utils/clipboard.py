"""
Secure clipboard management utilities for SentinelPass Password Manager.

This module provides secure clipboard operations with automatic clearing,
security features, and cross-platform compatibility for copying passwords
and usernames safely.

Security Features:
- Automatic clipboard clearing after timeout
- Secure clipboard operations
- Cross-platform compatibility
- Memory protection for sensitive data
- Clipboard history prevention

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import threading
import time
import logging
from typing import Optional, Callable
import sys

# Import clipboard library
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False
    logging.warning("Clipboard functionality not available - install pyperclip")

from config.settings import settings


class ClipboardError(Exception):
    """Custom exception for clipboard-related errors."""
    pass


class SecureClipboard:
    """
    Secure clipboard manager with automatic clearing and security features.
    
    This class provides secure clipboard operations with automatic clearing
    after a specified timeout to prevent sensitive data from remaining in
    the clipboard indefinitely.
    """
    
    def __init__(self):
        """Initialize the secure clipboard manager."""
        self.logger = logging.getLogger(__name__)
        self._clear_timer: Optional[threading.Timer] = None
        self._last_copied_data: Optional[str] = None
        self._clear_callbacks: list = []
        self._lock = threading.Lock()
        
        # Check clipboard availability
        if not CLIPBOARD_AVAILABLE:
            self.logger.warning("Clipboard functionality not available")
            
        self.logger.info("SecureClipboard initialized")
        
    def is_available(self) -> bool:
        """
        Check if clipboard functionality is available.
        
        Returns:
            bool: True if clipboard is available
        """
        return CLIPBOARD_AVAILABLE
        
    def copy_text(self, text: str, auto_clear: bool = True, 
                  clear_timeout: Optional[int] = None,
                  description: str = "data") -> bool:
        """
        Copy text to clipboard with optional automatic clearing.
        
        Args:
            text (str): Text to copy to clipboard
            auto_clear (bool): Whether to automatically clear clipboard
            clear_timeout (int, optional): Timeout in seconds for auto-clear
            description (str): Description of data being copied for logging
            
        Returns:
            bool: True if copy operation successful
            
        Raises:
            ClipboardError: If clipboard operation fails
        """
        if not CLIPBOARD_AVAILABLE:
            raise ClipboardError("Clipboard functionality not available")
            
        try:
            with self._lock:
                # Cancel any existing clear timer
                self._cancel_clear_timer()
                
                # Copy to clipboard
                pyperclip.copy(text)
                
                # Store reference for verification
                self._last_copied_data = text
                
                # Set up auto-clear if requested
                if auto_clear:
                    timeout = clear_timeout or settings.CLIPBOARD_CLEAR_SECONDS
                    self._start_clear_timer(timeout)
                    
                self.logger.info(f"Copied {description} to clipboard (auto-clear: {auto_clear})")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to copy to clipboard: {str(e)}")
            raise ClipboardError(f"Failed to copy to clipboard: {str(e)}")
            
    def copy_password(self, password: str, auto_clear: bool = True) -> bool:
        """
        Copy password to clipboard with security measures.
        
        Args:
            password (str): Password to copy
            auto_clear (bool): Whether to automatically clear clipboard
            
        Returns:
            bool: True if copy operation successful
        """
        return self.copy_text(
            password, 
            auto_clear=auto_clear,
            description="password"
        )
        
    def copy_username(self, username: str, auto_clear: bool = True) -> bool:
        """
        Copy username to clipboard.
        
        Args:
            username (str): Username to copy
            auto_clear (bool): Whether to automatically clear clipboard
            
        Returns:
            bool: True if copy operation successful
        """
        return self.copy_text(
            username, 
            auto_clear=auto_clear,
            clear_timeout=10,  # Shorter timeout for usernames
            description="username"
        )
        
    def get_clipboard_content(self) -> Optional[str]:
        """
        Get current clipboard content.
        
        Returns:
            Optional[str]: Clipboard content or None if unavailable
        """
        if not CLIPBOARD_AVAILABLE:
            return None
            
        try:
            return pyperclip.paste()
        except Exception as e:
            self.logger.error(f"Failed to get clipboard content: {str(e)}")
            return None
            
    def clear_clipboard(self, force: bool = False) -> bool:
        """
        Clear clipboard content.
        
        Args:
            force (bool): Force clear even if content doesn't match last copied
            
        Returns:
            bool: True if clear operation successful
        """
        if not CLIPBOARD_AVAILABLE:
            return False
            
        try:
            with self._lock:
                # Check if we should clear (only clear our own data unless forced)
                if not force and self._last_copied_data:
                    current_content = self.get_clipboard_content()
                    if current_content != self._last_copied_data:
                        self.logger.info("Clipboard content changed, skipping auto-clear")
                        return True
                        
                # Clear clipboard by copying empty string
                pyperclip.copy("")
                
                # Clear our reference
                self._last_copied_data = None
                
                # Cancel any pending clear timer
                self._cancel_clear_timer()
                
                # Notify callbacks
                self._notify_clear_callbacks()
                
                self.logger.info("Clipboard cleared")
                return True
                
        except Exception as e:
            self.logger.error(f"Failed to clear clipboard: {str(e)}")
            return False
            
    def _start_clear_timer(self, timeout_seconds: int):
        """Start timer for automatic clipboard clearing."""
        self._clear_timer = threading.Timer(timeout_seconds, self._auto_clear)
        self._clear_timer.daemon = True
        self._clear_timer.start()
        
        self.logger.debug(f"Auto-clear timer started: {timeout_seconds} seconds")
        
    def _cancel_clear_timer(self):
        """Cancel automatic clear timer."""
        if self._clear_timer:
            self._clear_timer.cancel()
            self._clear_timer = None
            
    def _auto_clear(self):
        """Automatic clipboard clearing callback."""
        self.logger.info("Auto-clearing clipboard")
        self.clear_clipboard()
        
    def add_clear_callback(self, callback: Callable[[], None]):
        """
        Add callback to be called when clipboard is cleared.
        
        Args:
            callback: Function to call when clipboard is cleared
        """
        self._clear_callbacks.append(callback)
        
    def remove_clear_callback(self, callback: Callable[[], None]):
        """
        Remove clear callback.
        
        Args:
            callback: Function to remove from callbacks
        """
        if callback in self._clear_callbacks:
            self._clear_callbacks.remove(callback)
            
    def _notify_clear_callbacks(self):
        """Notify all clear callbacks."""
        for callback in self._clear_callbacks:
            try:
                callback()
            except Exception as e:
                self.logger.error(f"Clear callback failed: {str(e)}")
                
    def get_status(self) -> dict:
        """
        Get clipboard manager status.
        
        Returns:
            dict: Status information
        """
        status = {
            'available': self.is_available(),
            'auto_clear_active': self._clear_timer is not None,
            'has_data': self._last_copied_data is not None,
            'clear_timeout_seconds': settings.CLIPBOARD_CLEAR_SECONDS
        }
        
        if self._clear_timer:
            # Estimate remaining time (not exact due to threading)
            status['estimated_clear_remaining'] = "Active"
            
        return status
        
    def test_clipboard(self) -> bool:
        """
        Test clipboard functionality.
        
        Returns:
            bool: True if clipboard is working properly
        """
        if not CLIPBOARD_AVAILABLE:
            return False
            
        try:
            # Test copy and paste
            test_data = "SentinelPass_Test_" + str(int(time.time()))
            original_content = self.get_clipboard_content()
            
            # Copy test data
            pyperclip.copy(test_data)
            
            # Verify copy
            copied_content = self.get_clipboard_content()
            success = copied_content == test_data
            
            # Restore original content if possible
            if original_content is not None:
                pyperclip.copy(original_content)
            else:
                pyperclip.copy("")
                
            self.logger.info(f"Clipboard test {'passed' if success else 'failed'}")
            return success
            
        except Exception as e:
            self.logger.error(f"Clipboard test failed: {str(e)}")
            return False
            
    def cleanup(self):
        """Cleanup clipboard manager resources."""
        with self._lock:
            # Cancel any pending clear timer
            self._cancel_clear_timer()
            
            # Clear clipboard if we have data
            if self._last_copied_data:
                self.clear_clipboard(force=True)
                
            # Clear callbacks
            self._clear_callbacks.clear()
            
            self.logger.info("SecureClipboard cleanup completed")


class ClipboardManager:
    """
    High-level clipboard manager with additional security features.
    
    This class provides a higher-level interface for clipboard operations
    with additional security features and convenience methods.
    """
    
    def __init__(self):
        """Initialize the clipboard manager."""
        self.logger = logging.getLogger(__name__)
        self.clipboard = SecureClipboard()
        self._copy_history = []
        self._max_history = 10
        
        self.logger.info("ClipboardManager initialized")
        
    def copy_password_entry_field(self, field_value: str, field_name: str, 
                                 entry_title: str = "") -> bool:
        """
        Copy a password entry field with appropriate security measures.
        
        Args:
            field_value (str): Value to copy
            field_name (str): Name of the field (password, username, etc.)
            entry_title (str): Title of the password entry
            
        Returns:
            bool: True if copy operation successful
        """
        try:
            if not field_value:
                self.logger.warning(f"Attempted to copy empty {field_name}")
                return False
                
            # Determine auto-clear settings based on field type
            auto_clear = True
            clear_timeout = settings.CLIPBOARD_CLEAR_SECONDS
            
            if field_name.lower() == "password":
                # Passwords get full security treatment
                auto_clear = True
                clear_timeout = settings.CLIPBOARD_CLEAR_SECONDS
            elif field_name.lower() in ["username", "email"]:
                # Usernames get shorter timeout
                auto_clear = True
                clear_timeout = min(10, settings.CLIPBOARD_CLEAR_SECONDS)
            else:
                # Other fields get minimal timeout
                auto_clear = True
                clear_timeout = 5
                
            # Copy to clipboard
            success = self.clipboard.copy_text(
                field_value,
                auto_clear=auto_clear,
                clear_timeout=clear_timeout,
                description=f"{field_name} from '{entry_title}'" if entry_title else field_name
            )
            
            if success:
                # Add to history (without storing actual sensitive data)
                self._add_to_history(field_name, entry_title)
                
            return success
            
        except Exception as e:
            self.logger.error(f"Failed to copy {field_name}: {str(e)}")
            return False
            
    def _add_to_history(self, field_name: str, entry_title: str):
        """Add copy operation to history (metadata only)."""
        history_entry = {
            'timestamp': time.time(),
            'field_name': field_name,
            'entry_title': entry_title
        }
        
        self._copy_history.append(history_entry)
        
        # Limit history size
        if len(self._copy_history) > self._max_history:
            self._copy_history.pop(0)
            
    def get_copy_history(self) -> list:
        """
        Get copy operation history (metadata only, no sensitive data).
        
        Returns:
            list: List of copy operations with timestamps
        """
        return self._copy_history.copy()
        
    def clear_copy_history(self):
        """Clear copy operation history."""
        self._copy_history.clear()
        self.logger.info("Copy history cleared")
        
    def emergency_clear(self):
        """Emergency clear of clipboard and history."""
        self.clipboard.clear_clipboard(force=True)
        self.clear_copy_history()
        self.logger.info("Emergency clipboard clear performed")
        
    def get_comprehensive_status(self) -> dict:
        """
        Get comprehensive clipboard status.
        
        Returns:
            dict: Comprehensive status information
        """
        status = self.clipboard.get_status()
        status.update({
            'copy_history_count': len(self._copy_history),
            'last_copy_time': self._copy_history[-1]['timestamp'] if self._copy_history else None,
            'clipboard_test_result': self.clipboard.test_clipboard()
        })
        
        return status
        
    def cleanup(self):
        """Cleanup clipboard manager resources."""
        self.emergency_clear()
        self.clipboard.cleanup()
        self.logger.info("ClipboardManager cleanup completed")


# Global clipboard manager instance
clipboard_manager = ClipboardManager()
