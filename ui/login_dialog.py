"""
Login dialog for SentinelPass Password Manager master password authentication.

This module provides a secure login dialog for master password authentication
with security features like failed attempt tracking, auto-lock prevention,
and secure input handling.

Security Features:
- Secure password input with visibility toggle
- Failed attempt tracking and lockout
- Auto-clear password field on failure
- Timing attack prevention
- Security event logging

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import Optional
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, 
    QLineEdit, QPushButton, QCheckBox, QProgressBar, QFrame,
    QSpacerItem, QSizePolicy, QMessageBox
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal
from PyQt5.QtGui import QFont, QPixmap, QIcon, QKeySequence

from config.settings import settings
from auth.master_auth import auth_manager
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager


class LoginDialog(QDialog):
    """
    Secure login dialog for master password authentication.
    
    Provides a professional login interface with security features
    including failed attempt tracking, secure input, and lockout protection.
    """
    
    # Signals
    authentication_successful = pyqtSignal()
    authentication_failed = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """Initialize login dialog."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.password = None
        self.failed_attempts = 0
        self.is_locked_out = False
        
        # UI components
        self.password_input = None
        self.show_password_checkbox = None
        self.login_button = None
        self.cancel_button = None
        self.status_label = None
        self.attempts_label = None
        self.lockout_timer = None
        self.lockout_progress = None
        
        self.setup_dialog()
        self.setup_ui()
        self.connect_signals()
        self.update_attempt_display()
        
    def setup_dialog(self):
        """Setup dialog properties."""
        self.setWindowTitle("SentinelPass - Login")
        self.setModal(True)
        self.setFixedSize(400, 300)
        
        # Remove window controls for security
        self.setWindowFlags(Qt.Dialog | Qt.CustomizeWindowHint | Qt.WindowTitleHint)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
    def setup_ui(self):
        """Setup the login dialog UI."""
        layout = QVBoxLayout()
        layout.setSpacing(20)
        
        # Header section
        header_layout = self.create_header_section()
        layout.addLayout(header_layout)
        
        # Login form section
        form_layout = self.create_form_section()
        layout.addLayout(form_layout)
        
        # Status section
        status_layout = self.create_status_section()
        layout.addLayout(status_layout)
        
        # Button section
        button_layout = self.create_button_section()
        layout.addLayout(button_layout)
        
        # Add stretch
        layout.addStretch()
        
        self.setLayout(layout)
        
    def create_header_section(self):
        """Create header section with logo and title."""
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel("SentinelPass")
        title_label.setAlignment(Qt.AlignCenter)
        title_label.setStyleSheet(
            f"font-size: 24pt; font-weight: bold; "
            f"color: {theme_manager.get_color('secondary')}; "
            f"margin: 10px;"
        )
        layout.addWidget(title_label)
        
        # Subtitle
        subtitle_label = QLabel("Enter your master password to continue")
        subtitle_label.setAlignment(Qt.AlignCenter)
        subtitle_label.setStyleSheet(
            f"font-size: 11pt; color: {theme_manager.get_color('text_secondary')};"
        )
        layout.addWidget(subtitle_label)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        separator.setStyleSheet(f"color: {theme_manager.get_color('border')};")
        layout.addWidget(separator)
        
        return layout
        
    def create_form_section(self):
        """Create login form section."""
        layout = QGridLayout()
        layout.setSpacing(10)
        
        # Password label
        password_label = QLabel("Master Password:")
        password_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(password_label, 0, 0)
        
        # Password input
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your master password")
        self.password_input.setStyleSheet(
            f"padding: 8px; font-size: 11pt; "
            f"border: 2px solid {theme_manager.get_color('input_border')}; "
            f"border-radius: 5px;"
        )
        layout.addWidget(self.password_input, 0, 1)
        
        # Show password checkbox
        self.show_password_checkbox = QCheckBox("Show password")
        self.show_password_checkbox.setStyleSheet("margin-left: 5px;")
        layout.addWidget(self.show_password_checkbox, 1, 1)
        
        return layout
        
    def create_status_section(self):
        """Create status section for messages and lockout info."""
        layout = QVBoxLayout()
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setWordWrap(True)
        self.status_label.setStyleSheet("font-size: 10pt; margin: 5px;")
        layout.addWidget(self.status_label)
        
        # Attempts label
        self.attempts_label = QLabel("")
        self.attempts_label.setAlignment(Qt.AlignCenter)
        self.attempts_label.setStyleSheet(
            f"font-size: 9pt; color: {theme_manager.get_color('text_secondary')};"
        )
        layout.addWidget(self.attempts_label)
        
        # Lockout progress bar (hidden by default)
        self.lockout_progress = QProgressBar()
        self.lockout_progress.setVisible(False)
        self.lockout_progress.setStyleSheet(
            f"QProgressBar::chunk {{ background-color: {theme_manager.get_color('danger')}; }}"
        )
        layout.addWidget(self.lockout_progress)
        
        return layout
        
    def create_button_section(self):
        """Create button section."""
        layout = QHBoxLayout()
        
        # Cancel button
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setStyleSheet("QPushButton { min-width: 80px; }")
        layout.addWidget(self.cancel_button)
        
        # Spacer
        layout.addStretch()
        
        # Login button
        self.login_button = QPushButton("Login")
        self.login_button.setDefault(True)
        self.login_button.setStyleSheet(
            f"QPushButton {{ "
            f"min-width: 80px; "
            f"background-color: {theme_manager.get_color('secondary')}; "
            f"}} "
            f"QPushButton:hover {{ "
            f"background-color: {theme_manager.get_color('secondary_light')}; "
            f"}}"
        )
        layout.addWidget(self.login_button)
        
        return layout
        
    def connect_signals(self):
        """Connect UI signals."""
        self.password_input.returnPressed.connect(self.attempt_login)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.show_password_checkbox.toggled.connect(self.toggle_password_visibility)
        self.login_button.clicked.connect(self.attempt_login)
        self.cancel_button.clicked.connect(self.reject)
        
        # Note: Authentication manager callbacks are handled in attempt_login method
        # No need to assign callback here as it causes attribute errors
        
    def on_password_changed(self):
        """Handle password input changes."""
        # Clear status when user starts typing
        if self.status_label.text() and not self.is_locked_out:
            self.status_label.setText("")
            
        # Enable/disable login button
        has_password = bool(self.password_input.text().strip())
        self.login_button.setEnabled(has_password and not self.is_locked_out)
        
    def toggle_password_visibility(self, checked):
        """Toggle password visibility."""
        echo_mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.password_input.setEchoMode(echo_mode)
        
        # Log security event
        security_monitor.log_security_event(
            "password_visibility_toggle",
            SecurityLevel.LOW,
            f"Password visibility {'shown' if checked else 'hidden'}",
            "login_dialog"
        )
        
    def attempt_login(self):
        """Attempt to authenticate with entered password."""
        if self.is_locked_out:
            return
            
        password = self.password_input.text().strip()
        if not password:
            self.show_status("Please enter your master password", "warning")
            return
            
        # Disable UI during authentication
        self.set_ui_enabled(False)
        self.show_status("Authenticating...", "info")
        
        try:
            # Attempt authentication
            if auth_manager.authenticate(password, "login_dialog"):
                self.on_authentication_success(password)
            else:
                self.on_authentication_failure()
                
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            self.show_status(f"Authentication error: {str(e)}", "error")
            self.set_ui_enabled(True)
            
    def on_authentication_success(self, password):
        """Handle successful authentication."""
        self.password = password
        self.show_status("Authentication successful!", "success")
        
        # Log security event
        security_monitor.log_security_event(
            "login_success",
            SecurityLevel.LOW,
            "Master password authentication successful",
            "login_dialog"
        )
        
        # Emit signal and accept dialog
        self.authentication_successful.emit()
        
        # Small delay to show success message
        QTimer.singleShot(500, self.accept)
        
    def on_authentication_failure(self):
        """Handle authentication failure."""
        self.failed_attempts += 1
        
        # Clear password field
        self.password_input.clear()
        
        # Check for lockout
        if self.failed_attempts >= settings.MAX_LOGIN_ATTEMPTS:
            self.start_lockout()
        else:
            remaining_attempts = settings.MAX_LOGIN_ATTEMPTS - self.failed_attempts
            self.show_status(
                f"Invalid password. {remaining_attempts} attempts remaining.",
                "error"
            )
            
        # Update attempt display
        self.update_attempt_display()
        
        # Re-enable UI
        self.set_ui_enabled(True)
        
        # Focus password input
        self.password_input.setFocus()
        
        # Log security event
        security_monitor.log_security_event(
            "login_failure",
            SecurityLevel.MEDIUM,
            f"Failed login attempt {self.failed_attempts}/{settings.MAX_LOGIN_ATTEMPTS}",
            "login_dialog",
            {"attempts": self.failed_attempts}
        )
        
        # Emit signal
        self.authentication_failed.emit(f"Authentication failed (attempt {self.failed_attempts})")
        
    def start_lockout(self):
        """Start lockout period after too many failed attempts."""
        self.is_locked_out = True
        lockout_seconds = settings.LOCKOUT_DURATION_MINUTES * 60
        
        # Show lockout message
        self.show_status(
            f"Too many failed attempts. Locked out for {settings.LOCKOUT_DURATION_MINUTES} minutes.",
            "error"
        )
        
        # Setup lockout timer
        self.lockout_timer = QTimer()
        self.lockout_timer.timeout.connect(self.update_lockout_progress)
        
        # Setup progress bar
        self.lockout_progress.setVisible(True)
        self.lockout_progress.setRange(0, lockout_seconds)
        self.lockout_progress.setValue(lockout_seconds)
        
        # Disable UI
        self.set_ui_enabled(False)
        
        # Start timer
        self.lockout_start_time = lockout_seconds
        self.lockout_timer.start(1000)  # Update every second
        
        # Log security event
        security_monitor.log_security_event(
            "login_lockout",
            SecurityLevel.HIGH,
            f"Login locked out for {settings.LOCKOUT_DURATION_MINUTES} minutes after {self.failed_attempts} failed attempts",
            "login_dialog",
            {"lockout_duration": settings.LOCKOUT_DURATION_MINUTES}
        )
        
    def update_lockout_progress(self):
        """Update lockout progress bar."""
        current_value = self.lockout_progress.value()
        
        if current_value > 0:
            new_value = current_value - 1
            self.lockout_progress.setValue(new_value)
            
            # Update status with remaining time
            remaining_minutes = new_value // 60
            remaining_seconds = new_value % 60
            self.show_status(
                f"Locked out. Time remaining: {remaining_minutes:02d}:{remaining_seconds:02d}",
                "error"
            )
        else:
            # Lockout period ended
            self.end_lockout()
            
    def end_lockout(self):
        """End lockout period."""
        self.is_locked_out = False
        self.failed_attempts = 0
        
        # Stop timer
        if self.lockout_timer:
            self.lockout_timer.stop()
            self.lockout_timer = None
            
        # Hide progress bar
        self.lockout_progress.setVisible(False)
        
        # Re-enable UI
        self.set_ui_enabled(True)
        
        # Clear status
        self.show_status("Lockout period ended. You may try again.", "info")
        
        # Update attempt display
        self.update_attempt_display()
        
        # Focus password input
        self.password_input.setFocus()
        
        # Log security event
        security_monitor.log_security_event(
            "lockout_ended",
            SecurityLevel.MEDIUM,
            "Login lockout period ended",
            "login_dialog"
        )
        
    def update_attempt_display(self):
        """Update failed attempts display."""
        if self.failed_attempts > 0 and not self.is_locked_out:
            remaining = settings.MAX_LOGIN_ATTEMPTS - self.failed_attempts
            self.attempts_label.setText(
                f"Failed attempts: {self.failed_attempts}/{settings.MAX_LOGIN_ATTEMPTS} "
                f"({remaining} remaining)"
            )
            self.attempts_label.setStyleSheet(
                f"color: {theme_manager.get_color('warning')}; font-size: 9pt;"
            )
        else:
            self.attempts_label.setText("")
            
    def show_status(self, message: str, status_type: str = "info"):
        """
        Show status message with appropriate styling.
        
        Args:
            message (str): Status message
            status_type (str): Type of status (info, success, warning, error)
        """
        colors = {
            "info": theme_manager.get_color('text_secondary'),
            "success": theme_manager.get_color('success'),
            "warning": theme_manager.get_color('warning'),
            "error": theme_manager.get_color('danger')
        }
        
        color = colors.get(status_type, colors["info"])
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color}; font-size: 10pt; margin: 5px;")
        
    def set_ui_enabled(self, enabled: bool):
        """Enable/disable UI components."""
        self.password_input.setEnabled(enabled)
        self.show_password_checkbox.setEnabled(enabled)
        self.login_button.setEnabled(enabled and bool(self.password_input.text().strip()))
        
    def get_password(self):
        """Get the entered password."""
        return self.password
        
    def keyPressEvent(self, event):
        """Handle key press events."""
        # Prevent Alt+F4 and other window closing shortcuts during lockout
        if self.is_locked_out and event.key() in [Qt.Key_F4, Qt.Key_Escape]:
            event.ignore()
            return
            
        super().keyPressEvent(event)
        
    def closeEvent(self, event):
        """Handle close event."""
        # Prevent closing during lockout
        if self.is_locked_out:
            event.ignore()
            return
            
        # Clean up timer
        if self.lockout_timer:
            self.lockout_timer.stop()
            
        # Clear password from memory
        if self.password:
            self.password = None
            
        super().closeEvent(event)
        
    def reject(self):
        """Handle dialog rejection."""
        # Prevent rejection during lockout
        if self.is_locked_out:
            return
            
        # Log security event
        security_monitor.log_security_event(
            "login_cancelled",
            SecurityLevel.LOW,
            "Login dialog cancelled by user",
            "login_dialog"
        )
        
        super().reject()
