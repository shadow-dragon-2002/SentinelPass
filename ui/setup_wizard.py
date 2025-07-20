"""
Setup wizard for SentinelPass Password Manager first-time setup.

This module provides a comprehensive setup wizard that guides new users through
the initial configuration of SentinelPass, including master password creation,
security settings, and optional Google Drive integration.

Features:
- Step-by-step setup process
- Master password creation with strength validation
- Security policy configuration
- Google Drive backup setup (optional)
- Welcome and completion screens

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import Optional, Dict, Any
from PyQt5.QtWidgets import (
    QWizard, QWizardPage, QVBoxLayout, QHBoxLayout, QGridLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QProgressBar,
    QTextEdit, QGroupBox, QRadioButton, QButtonGroup, QSpacerItem,
    QSizePolicy, QFrame, QScrollArea, QWidget
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QPixmap, QPalette, QIcon

from config.settings import settings
from utils.validators import input_validator
from core.password_generator import password_generator, PasswordStrength
from auth.google_auth import google_auth_manager
from ui.styles import theme_manager


class WelcomePage(QWizardPage):
    """Welcome page for the setup wizard."""
    
    def __init__(self):
        """Initialize welcome page."""
        super().__init__()
        self.setTitle("Welcome to SentinelPass")
        self.setSubTitle("Professional Password Manager")
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the welcome page UI."""
        layout = QVBoxLayout()
        
        # Welcome message
        welcome_label = QLabel(
            "<h2>Welcome to SentinelPass!</h2>"
            "<p>SentinelPass is a professional password manager that helps you store, "
            "generate, and manage your passwords securely.</p>"
        )
        welcome_label.setWordWrap(True)
        welcome_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(welcome_label)
        
        # Features list
        features_group = QGroupBox("Key Features")
        features_layout = QVBoxLayout()
        
        features = [
            "🔒 Military-grade AES-256 encryption",
            "🔑 Secure master password authentication",
            "🎲 Advanced password generator",
            "☁️ Google Drive backup integration",
            "📋 Quick copy functionality",
            "🔍 Fast search and organization",
            "🛡️ Auto-lock security features"
        ]
        
        for feature in features:
            feature_label = QLabel(feature)
            feature_label.setStyleSheet("padding: 4px; font-size: 11pt;")
            features_layout.addWidget(feature_label)
            
        features_group.setLayout(features_layout)
        layout.addWidget(features_group)
        
        # Setup info
        info_label = QLabel(
            "<p><b>This setup wizard will guide you through:</b></p>"
            "<ul>"
            "<li>Creating your secure master password</li>"
            "<li>Configuring security settings</li>"
            "<li>Setting up Google Drive backup (optional)</li>"
            "</ul>"
            "<p>The setup process takes just a few minutes.</p>"
        )
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        layout.addStretch()
        self.setLayout(layout)


class MasterPasswordPage(QWizardPage):
    """Master password creation page."""
    
    def __init__(self):
        """Initialize master password page."""
        super().__init__()
        self.setTitle("Create Master Password")
        self.setSubTitle("Your master password protects all your stored passwords")
        
        self.password_input = None
        self.confirm_input = None
        self.strength_bar = None
        self.strength_label = None
        self.requirements_labels = {}
        self.show_password_checkbox = None
        
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup the master password page UI."""
        layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel(
            "Create a strong master password that you'll use to access SentinelPass. "
            "This password cannot be recovered if forgotten, so choose something memorable but secure."
        )
        instructions.setWordWrap(True)
        instructions.setStyleSheet("color: #F39C12; font-weight: bold; padding: 10px; "
                                 "background-color: rgba(243, 156, 18, 0.1); border-radius: 5px;")
        layout.addWidget(instructions)
        
        # Password input section
        password_group = QGroupBox("Master Password")
        password_layout = QGridLayout()
        
        # Password field
        password_layout.addWidget(QLabel("Password:"), 0, 0)
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter your master password")
        password_layout.addWidget(self.password_input, 0, 1)
        
        # Confirm password field
        password_layout.addWidget(QLabel("Confirm:"), 1, 0)
        self.confirm_input = QLineEdit()
        self.confirm_input.setEchoMode(QLineEdit.Password)
        self.confirm_input.setPlaceholderText("Confirm your master password")
        password_layout.addWidget(self.confirm_input, 1, 1)
        
        # Show password checkbox
        self.show_password_checkbox = QCheckBox("Show password")
        password_layout.addWidget(self.show_password_checkbox, 2, 1)
        
        password_group.setLayout(password_layout)
        layout.addWidget(password_group)
        
        # Password strength section
        strength_group = QGroupBox("Password Strength")
        strength_layout = QVBoxLayout()
        
        # Strength bar
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        strength_layout.addWidget(self.strength_bar)
        
        # Strength label
        self.strength_label = QLabel("Enter password to see strength")
        self.strength_label.setAlignment(Qt.AlignCenter)
        strength_layout.addWidget(self.strength_label)
        
        strength_group.setLayout(strength_layout)
        layout.addWidget(strength_group)
        
        # Requirements section
        requirements_group = QGroupBox("Password Requirements")
        requirements_layout = QVBoxLayout()
        
        requirements = [
            ("length", f"At least {settings.MIN_MASTER_PASSWORD_LENGTH} characters"),
            ("uppercase", "Contains uppercase letters"),
            ("lowercase", "Contains lowercase letters"),
            ("digits", "Contains numbers"),
            ("special", "Contains special characters"),
            ("no_common", "No common patterns")
        ]
        
        for req_id, req_text in requirements:
            label = QLabel(f"• {req_text}")
            label.setStyleSheet("color: #E74C3C;")  # Red by default
            self.requirements_labels[req_id] = label
            requirements_layout.addWidget(label)
            
        requirements_group.setLayout(requirements_layout)
        layout.addWidget(requirements_group)
        
        # Generate password button
        generate_layout = QHBoxLayout()
        generate_layout.addStretch()
        generate_button = QPushButton("Generate Secure Password")
        generate_button.clicked.connect(self.generate_password)
        generate_layout.addWidget(generate_button)
        generate_layout.addStretch()
        layout.addLayout(generate_layout)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def connect_signals(self):
        """Connect UI signals."""
        self.password_input.textChanged.connect(self.validate_password)
        self.confirm_input.textChanged.connect(self.validate_password)
        self.show_password_checkbox.toggled.connect(self.toggle_password_visibility)
        
    def toggle_password_visibility(self, checked):
        """Toggle password visibility."""
        echo_mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.password_input.setEchoMode(echo_mode)
        self.confirm_input.setEchoMode(echo_mode)
        
    def generate_password(self):
        """Generate a secure password."""
        try:
            password = password_generator.generate_password(
                length=16,
                include_uppercase=True,
                include_lowercase=True,
                include_digits=True,
                include_symbols=True,
                exclude_ambiguous=True
            )
            
            self.password_input.setText(password)
            self.confirm_input.setText(password)
            
        except Exception as e:
            logging.error(f"Password generation failed: {str(e)}")
            
    def validate_password(self):
        """Validate password and update UI."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        # Validate password strength
        is_valid, errors, strength_info = input_validator.validate_password_strength(password)
        
        # Update strength bar and label
        if password:
            strength_level, entropy, criteria = password_generator.assess_password_strength(password)
            
            # Update progress bar
            strength_percent = min(100, int(entropy * 2))  # Scale entropy to percentage
            self.strength_bar.setValue(strength_percent)
            
            # Update strength label and color
            strength_colors = {
                PasswordStrength.VERY_WEAK: ("#E74C3C", "Very Weak"),
                PasswordStrength.WEAK: ("#E67E22", "Weak"),
                PasswordStrength.FAIR: ("#F39C12", "Fair"),
                PasswordStrength.GOOD: ("#27AE60", "Good"),
                PasswordStrength.STRONG: ("#2ECC71", "Strong"),
                PasswordStrength.VERY_STRONG: ("#16A085", "Very Strong")
            }
            
            color, text = strength_colors.get(strength_level, ("#E74C3C", "Very Weak"))
            self.strength_label.setText(f"Password Strength: {text}")
            self.strength_label.setStyleSheet(f"color: {color}; font-weight: bold;")
            self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
            
        else:
            self.strength_bar.setValue(0)
            self.strength_label.setText("Enter password to see strength")
            self.strength_label.setStyleSheet("")
            
        # Update requirements
        self.update_requirements(strength_info if password else {})
        
        # Update page completion
        passwords_match = password and confirm and password == confirm
        self.completeChanged.emit()
        
    def update_requirements(self, strength_info):
        """Update password requirements display."""
        requirements_met = {
            "length": strength_info.get('length_12_plus', False),
            "uppercase": strength_info.get('has_uppercase', False),
            "lowercase": strength_info.get('has_lowercase', False),
            "digits": strength_info.get('has_digits', False),
            "special": strength_info.get('has_symbols', False),
            "no_common": strength_info.get('no_common_patterns', True)
        }
        
        for req_id, is_met in requirements_met.items():
            if req_id in self.requirements_labels:
                label = self.requirements_labels[req_id]
                if is_met:
                    label.setStyleSheet("color: #27AE60;")  # Green
                    label.setText(label.text().replace("•", "✓"))
                else:
                    label.setStyleSheet("color: #E74C3C;")  # Red
                    label.setText(label.text().replace("✓", "•"))
                    
    def isComplete(self):
        """Check if page is complete."""
        password = self.password_input.text()
        confirm = self.confirm_input.text()
        
        if not password or not confirm:
            return False
            
        if password != confirm:
            return False
            
        # Validate password strength
        is_valid, errors, _ = input_validator.validate_password_strength(password)
        return is_valid
        
    def get_master_password(self):
        """Get the entered master password."""
        return self.password_input.text()


class SecuritySettingsPage(QWizardPage):
    """Security settings configuration page."""
    
    def __init__(self):
        """Initialize security settings page."""
        super().__init__()
        self.setTitle("Security Settings")
        self.setSubTitle("Configure security options for your password manager")
        
        self.auto_lock_checkbox = None
        self.timeout_buttons = None
        self.clipboard_checkbox = None
        self.clipboard_timeout_buttons = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the security settings page UI."""
        layout = QVBoxLayout()
        
        # Auto-lock settings
        autolock_group = QGroupBox("Auto-Lock Settings")
        autolock_layout = QVBoxLayout()
        
        self.auto_lock_checkbox = QCheckBox("Enable auto-lock after inactivity")
        self.auto_lock_checkbox.setChecked(True)
        autolock_layout.addWidget(self.auto_lock_checkbox)
        
        # Timeout options
        timeout_label = QLabel("Auto-lock timeout:")
        autolock_layout.addWidget(timeout_label)
        
        self.timeout_buttons = QButtonGroup()
        timeout_options = [
            (5, "5 minutes"),
            (15, "15 minutes (recommended)"),
            (30, "30 minutes"),
            (60, "1 hour")
        ]
        
        for minutes, text in timeout_options:
            radio = QRadioButton(text)
            if minutes == 15:  # Default selection
                radio.setChecked(True)
            self.timeout_buttons.addButton(radio, minutes)
            autolock_layout.addWidget(radio)
            
        autolock_group.setLayout(autolock_layout)
        layout.addWidget(autolock_group)
        
        # Clipboard settings
        clipboard_group = QGroupBox("Clipboard Security")
        clipboard_layout = QVBoxLayout()
        
        self.clipboard_checkbox = QCheckBox("Auto-clear clipboard after copying passwords")
        self.clipboard_checkbox.setChecked(True)
        clipboard_layout.addWidget(self.clipboard_checkbox)
        
        # Clipboard timeout options
        clipboard_timeout_label = QLabel("Clipboard clear timeout:")
        clipboard_layout.addWidget(clipboard_timeout_label)
        
        self.clipboard_timeout_buttons = QButtonGroup()
        clipboard_timeout_options = [
            (10, "10 seconds"),
            (30, "30 seconds (recommended)"),
            (60, "1 minute"),
            (120, "2 minutes")
        ]
        
        for seconds, text in clipboard_timeout_options:
            radio = QRadioButton(text)
            if seconds == 30:  # Default selection
                radio.setChecked(True)
            self.clipboard_timeout_buttons.addButton(radio, seconds)
            clipboard_layout.addWidget(radio)
            
        clipboard_group.setLayout(clipboard_layout)
        layout.addWidget(clipboard_group)
        
        # Additional security options
        additional_group = QGroupBox("Additional Security")
        additional_layout = QVBoxLayout()
        
        # Security recommendations
        recommendations = [
            "✓ All passwords are encrypted with AES-256",
            "✓ Master password uses secure key derivation (PBKDF2)",
            "✓ Sensitive data is cleared from memory when possible",
            "✓ Failed login attempts are tracked and limited"
        ]
        
        for recommendation in recommendations:
            label = QLabel(recommendation)
            label.setStyleSheet("color: #27AE60; padding: 2px;")
            additional_layout.addWidget(label)
            
        additional_group.setLayout(additional_layout)
        layout.addWidget(additional_group)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def get_security_settings(self):
        """Get selected security settings."""
        return {
            'auto_lock_enabled': self.auto_lock_checkbox.isChecked(),
            'auto_lock_timeout': self.timeout_buttons.checkedId(),
            'clipboard_clear_enabled': self.clipboard_checkbox.isChecked(),
            'clipboard_clear_timeout': self.clipboard_timeout_buttons.checkedId()
        }


class GoogleDriveSetupPage(QWizardPage):
    """Google Drive backup setup page."""
    
    def __init__(self):
        """Initialize Google Drive setup page."""
        super().__init__()
        self.setTitle("Google Drive Backup (Optional)")
        self.setSubTitle("Set up encrypted cloud backup for your passwords")
        
        self.enable_checkbox = None
        self.setup_button = None
        self.status_label = None
        self.credentials_text = None
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the Google Drive setup page UI."""
        layout = QVBoxLayout()
        
        # Introduction
        intro_label = QLabel(
            "SentinelPass can automatically backup your encrypted password database to Google Drive. "
            "This provides an additional layer of protection and allows you to restore your passwords "
            "if needed."
        )
        intro_label.setWordWrap(True)
        layout.addWidget(intro_label)
        
        # Enable checkbox
        self.enable_checkbox = QCheckBox("Enable Google Drive backup")
        self.enable_checkbox.toggled.connect(self.toggle_google_drive_setup)
        layout.addWidget(self.enable_checkbox)
        
        # Setup section
        setup_group = QGroupBox("Google Drive Setup")
        setup_layout = QVBoxLayout()
        
        # Instructions
        instructions = QLabel(
            "To enable Google Drive backup:\n"
            "1. The setup will open your web browser\n"
            "2. Sign in to your Google account\n"
            "3. Grant permission for SentinelPass to access Google Drive\n"
            "4. Your backups will be stored in a dedicated SentinelPass folder"
        )
        instructions.setWordWrap(True)
        setup_layout.addWidget(instructions)
        
        # Setup button
        button_layout = QHBoxLayout()
        self.setup_button = QPushButton("Setup Google Drive")
        self.setup_button.clicked.connect(self.setup_google_drive)
        self.setup_button.setEnabled(False)
        button_layout.addWidget(self.setup_button)
        button_layout.addStretch()
        setup_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("Google Drive not configured")
        self.status_label.setStyleSheet("color: #E74C3C;")
        setup_layout.addWidget(self.status_label)
        
        setup_group.setLayout(setup_layout)
        layout.addWidget(setup_group)
        
        # Security note
        security_note = QLabel(
            "<b>Security Note:</b> Your password database is encrypted before being uploaded to Google Drive. "
            "Even if someone gains access to your Google Drive, they cannot read your passwords without "
            "your master password."
        )
        security_note.setWordWrap(True)
        security_note.setStyleSheet("color: #27AE60; background-color: rgba(39, 174, 96, 0.1); "
                                  "padding: 10px; border-radius: 5px;")
        layout.addWidget(security_note)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def toggle_google_drive_setup(self, enabled):
        """Toggle Google Drive setup options."""
        self.setup_button.setEnabled(enabled)
        
        if not enabled:
            self.status_label.setText("Google Drive backup disabled")
            self.status_label.setStyleSheet("color: #6C757D;")
            
    def setup_google_drive(self):
        """Setup Google Drive authentication."""
        try:
            self.setup_button.setEnabled(False)
            self.setup_button.setText("Setting up...")
            self.status_label.setText("Opening browser for authentication...")
            self.status_label.setStyleSheet("color: #F39C12;")
            
            # Check if Google Drive is available
            if not google_auth_manager.is_available():
                self.status_label.setText("Google Drive API not available")
                self.status_label.setStyleSheet("color: #E74C3C;")
                return
                
            # Attempt authentication
            if google_auth_manager.authenticate():
                self.status_label.setText("✓ Google Drive configured successfully!")
                self.status_label.setStyleSheet("color: #27AE60;")
                self.setup_button.setText("Reconfigure")
            else:
                self.status_label.setText("Google Drive setup failed")
                self.status_label.setStyleSheet("color: #E74C3C;")
                
        except Exception as e:
            self.status_label.setText(f"Setup failed: {str(e)}")
            self.status_label.setStyleSheet("color: #E74C3C;")
            
        finally:
            self.setup_button.setEnabled(True)
            if self.setup_button.text() != "Reconfigure":
                self.setup_button.setText("Setup Google Drive")
                
    def get_google_drive_settings(self):
        """Get Google Drive settings."""
        return {
            'enabled': self.enable_checkbox.isChecked(),
            'configured': google_auth_manager.is_authenticated()
        }


class CompletionPage(QWizardPage):
    """Setup completion page."""
    
    def __init__(self):
        """Initialize completion page."""
        super().__init__()
        self.setTitle("Setup Complete!")
        self.setSubTitle("SentinelPass is ready to use")
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the completion page UI."""
        layout = QVBoxLayout()
        
        # Success message
        success_label = QLabel(
            "<h2>🎉 Congratulations!</h2>"
            "<p>SentinelPass has been successfully configured and is ready to use.</p>"
        )
        success_label.setAlignment(Qt.AlignCenter)
        success_label.setWordWrap(True)
        layout.addWidget(success_label)
        
        # Summary
        summary_group = QGroupBox("Setup Summary")
        summary_layout = QVBoxLayout()
        
        summary_items = [
            "✓ Master password created and secured",
            "✓ Database initialized with encryption",
            "✓ Security settings configured",
            "✓ Application ready for use"
        ]
        
        for item in summary_items:
            label = QLabel(item)
            label.setStyleSheet("color: #27AE60; padding: 4px; font-size: 11pt;")
            summary_layout.addWidget(label)
            
        summary_group.setLayout(summary_layout)
        layout.addWidget(summary_group)
        
        # Next steps
        next_steps_group = QGroupBox("Next Steps")
        next_steps_layout = QVBoxLayout()
        
        next_steps = [
            "1. Start adding your passwords and accounts",
            "2. Use the password generator for new accounts",
            "3. Explore the search and organization features",
            "4. Set up regular backups for your data"
        ]
        
        for step in next_steps:
            label = QLabel(step)
            label.setStyleSheet("padding: 4px; font-size: 11pt;")
            next_steps_layout.addWidget(label)
            
        next_steps_group.setLayout(next_steps_layout)
        layout.addWidget(next_steps_group)
        
        # Tips
        tips_label = QLabel(
            "<b>💡 Tips:</b><br>"
            "• Remember your master password - it cannot be recovered<br>"
            "• Use the auto-generated passwords for better security<br>"
            "• Enable auto-backup to protect your data<br>"
            "• Keep SentinelPass updated for the latest security features"
        )
        tips_label.setWordWrap(True)
        tips_label.setStyleSheet("color: #3498DB; background-color: rgba(52, 152, 219, 0.1); "
                               "padding: 15px; border-radius: 5px; margin: 10px;")
        layout.addWidget(tips_label)
        
        layout.addStretch()
        self.setLayout(layout)


class SetupWizard(QWizard):
    """
    Main setup wizard for SentinelPass first-time configuration.
    
    Guides users through the complete setup process including master password
    creation, security configuration, and optional Google Drive setup.
    """
    
    def __init__(self, parent=None):
        """Initialize setup wizard."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.master_password = None
        self.security_settings = None
        self.google_drive_settings = None
        
        self.setup_wizard()
        self.setup_pages()
        
    def setup_wizard(self):
        """Setup wizard properties."""
        self.setWindowTitle("SentinelPass Setup Wizard")
        self.setWizardStyle(QWizard.ModernStyle)
        self.setOption(QWizard.HaveHelpButton, False)
        self.setOption(QWizard.HaveCustomButton1, False)
        
        # Set window properties
        self.setMinimumSize(700, 500)
        self.resize(800, 600)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
    def setup_pages(self):
        """Setup wizard pages."""
        # Add pages
        self.welcome_page = WelcomePage()
        self.password_page = MasterPasswordPage()
        self.security_page = SecuritySettingsPage()
        self.google_drive_page = GoogleDriveSetupPage()
        self.completion_page = CompletionPage()
        
        self.addPage(self.welcome_page)
        self.addPage(self.password_page)
        self.addPage(self.security_page)
        self.addPage(self.google_drive_page)
        self.addPage(self.completion_page)
        
        # Connect signals
        self.finished.connect(self.on_wizard_finished)
        
    def on_wizard_finished(self, result):
        """Handle wizard completion."""
        if result == QWizard.Accepted:
            # Collect all settings
            self.master_password = self.password_page.get_master_password()
            self.security_settings = self.security_page.get_security_settings()
            self.google_drive_settings = self.google_drive_page.get_google_drive_settings()
            
            self.logger.info("Setup wizard completed successfully")
        else:
            self.logger.info("Setup wizard cancelled")
            
    def get_master_password(self):
        """Get the configured master password."""
        return self.master_password
        
    def get_security_settings(self):
        """Get the configured security settings."""
        return self.security_settings
        
    def get_google_drive_settings(self):
        """Get the configured Google Drive settings."""
        return self.google_drive_settings
