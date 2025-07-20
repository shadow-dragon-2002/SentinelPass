"""
Password form dialog for SentinelPass Password Manager.

This module provides a comprehensive form dialog for adding and editing
password entries with validation, password generation, and security features.

Features:
- Add/edit password entries
- Real-time validation
- Integrated password generator
- Password strength indicator
- Secure input handling
- Category management

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import Optional
from datetime import datetime, timezone
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QCheckBox, QComboBox,
    QGroupBox, QProgressBar, QDialogButtonBox, QMessageBox, QFrame,
    QSpacerItem, QSizePolicy
)
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QFont, QIcon

from config.settings import settings
from core.database import DatabaseManager, PasswordEntry
from core.password_generator import password_generator, PasswordStrength
from utils.validators import input_validator
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager


class PasswordFormDialog(QDialog):
    """
    Comprehensive password form dialog for adding and editing entries.
    
    Provides a professional interface for password entry management with
    validation, generation, and security features.
    """
    
    # Signals
    entry_saved = pyqtSignal(PasswordEntry)
    
    def __init__(self, db_manager: DatabaseManager, entry: Optional[PasswordEntry] = None, parent=None):
        """
        Initialize password form dialog.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
            entry (PasswordEntry, optional): Entry to edit (None for new entry)
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        self.entry = entry
        self.is_editing = entry is not None
        
        # Form fields
        self.title_input = None
        self.username_input = None
        self.password_input = None
        self.confirm_password_input = None
        self.url_input = None
        self.notes_input = None
        self.category_combo = None
        
        # Password controls
        self.show_password_checkbox = None
        self.generate_button = None
        self.strength_bar = None
        self.strength_label = None
        
        # Dialog controls
        self.button_box = None
        
        # Validation state
        self.validation_errors = {}
        
        self.setup_dialog()
        self.setup_ui()
        self.connect_signals()
        self.load_categories()
        
        if self.is_editing:
            self.load_entry_data()
        else:
            self.set_defaults()
            
        self.validate_form()
        
    def setup_dialog(self):
        """Setup dialog properties."""
        title = "Edit Password" if self.is_editing else "Add Password"
        self.setWindowTitle(f"SentinelPass - {title}")
        self.setModal(True)
        self.setMinimumSize(500, 600)
        self.resize(600, 700)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
    def setup_ui(self):
        """Setup the form dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header_layout = self.create_header_section()
        layout.addLayout(header_layout)
        
        # Main form
        form_group = self.create_form_section()
        layout.addWidget(form_group)
        
        # Password section
        password_group = self.create_password_section()
        layout.addWidget(password_group)
        
        # Additional info section
        additional_group = self.create_additional_section()
        layout.addWidget(additional_group)
        
        # Button box
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.Save | QDialogButtonBox.Cancel,
            Qt.Horizontal
        )
        layout.addWidget(self.button_box)
        
    def create_header_section(self):
        """Create header section."""
        layout = QVBoxLayout()
        
        # Title
        title_text = "Edit Password Entry" if self.is_editing else "Add New Password Entry"
        title_label = QLabel(title_text)
        title_label.setStyleSheet(
            f"font-size: 16pt; font-weight: bold; "
            f"color: {theme_manager.get_color('secondary')}; "
            f"margin: 10px 0;"
        )
        layout.addWidget(title_label)
        
        # Separator
        separator = QFrame()
        separator.setFrameShape(QFrame.HLine)
        separator.setFrameShadow(QFrame.Sunken)
        layout.addWidget(separator)
        
        return layout
        
    def create_form_section(self):
        """Create main form section."""
        group = QGroupBox("Basic Information")
        layout = QFormLayout(group)
        layout.setSpacing(10)
        
        # Title field
        self.title_input = QLineEdit()
        self.title_input.setPlaceholderText("e.g., Gmail, Facebook, Bank Account")
        layout.addRow("Title *:", self.title_input)
        
        # Username field
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Username or email address")
        layout.addRow("Username:", self.username_input)
        
        # URL field
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://example.com")
        layout.addRow("Website URL:", self.url_input)
        
        # Category field
        self.category_combo = QComboBox()
        self.category_combo.setEditable(True)
        self.category_combo.setPlaceholderText("Select or enter category")
        layout.addRow("Category:", self.category_combo)
        
        return group
        
    def create_password_section(self):
        """Create password section."""
        group = QGroupBox("Password")
        layout = QVBoxLayout(group)
        layout.setSpacing(10)
        
        # Password input section
        password_input_layout = QFormLayout()
        
        # Password field
        password_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Enter password")
        password_layout.addWidget(self.password_input)
        
        # Generate button
        self.generate_button = QPushButton("Generate")
        self.generate_button.setMaximumWidth(80)
        self.generate_button.setToolTip("Generate secure password")
        password_layout.addWidget(self.generate_button)
        
        password_input_layout.addRow("Password *:", password_layout)
        
        # Confirm password field
        self.confirm_password_input = QLineEdit()
        self.confirm_password_input.setEchoMode(QLineEdit.Password)
        self.confirm_password_input.setPlaceholderText("Confirm password")
        password_input_layout.addRow("Confirm Password *:", self.confirm_password_input)
        
        layout.addLayout(password_input_layout)
        
        # Show password checkbox
        self.show_password_checkbox = QCheckBox("Show passwords")
        layout.addWidget(self.show_password_checkbox)
        
        # Password strength section
        strength_layout = self.create_strength_section()
        layout.addLayout(strength_layout)
        
        return group
        
    def create_strength_section(self):
        """Create password strength section."""
        layout = QVBoxLayout()
        
        # Strength label
        strength_label = QLabel("Password Strength:")
        strength_label.setStyleSheet("font-weight: bold; margin-top: 10px;")
        layout.addWidget(strength_label)
        
        # Strength bar
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setMaximumHeight(20)
        layout.addWidget(self.strength_bar)
        
        # Strength description
        self.strength_label = QLabel("Enter password to see strength")
        self.strength_label.setStyleSheet("font-size: 10pt; color: #6C757D;")
        layout.addWidget(self.strength_label)
        
        return layout
        
    def create_additional_section(self):
        """Create additional information section."""
        group = QGroupBox("Additional Information")
        layout = QVBoxLayout(group)
        
        # Notes field
        notes_label = QLabel("Notes:")
        notes_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(notes_label)
        
        self.notes_input = QTextEdit()
        self.notes_input.setPlaceholderText("Additional notes or information...")
        self.notes_input.setMaximumHeight(100)
        layout.addWidget(self.notes_input)
        
        return group
        
    def connect_signals(self):
        """Connect form signals."""
        # Form validation
        self.title_input.textChanged.connect(self.validate_form)
        self.username_input.textChanged.connect(self.validate_form)
        self.password_input.textChanged.connect(self.on_password_changed)
        self.confirm_password_input.textChanged.connect(self.validate_form)
        self.url_input.textChanged.connect(self.validate_form)
        
        # Password controls
        self.show_password_checkbox.toggled.connect(self.toggle_password_visibility)
        self.generate_button.clicked.connect(self.generate_password)
        
        # Dialog buttons
        self.button_box.accepted.connect(self.save_entry)
        self.button_box.rejected.connect(self.reject)
        
    def load_categories(self):
        """Load available categories."""
        try:
            categories = self.db_manager.get_categories()
            
            # Add default categories
            default_categories = ["General", "Social", "Work", "Banking", "Shopping", "Entertainment"]
            all_categories = list(set(default_categories + categories))
            all_categories.sort()
            
            self.category_combo.addItems(all_categories)
            
        except Exception as e:
            self.logger.error(f"Failed to load categories: {str(e)}")
            # Add default categories only
            self.category_combo.addItems(["General", "Social", "Work", "Banking", "Shopping", "Entertainment"])
            
    def load_entry_data(self):
        """Load existing entry data into form."""
        if not self.entry:
            return
            
        self.title_input.setText(self.entry.title)
        self.username_input.setText(self.entry.username or "")
        self.password_input.setText(self.entry.password)
        self.confirm_password_input.setText(self.entry.password)
        self.url_input.setText(self.entry.url or "")
        self.notes_input.setPlainText(self.entry.notes or "")
        
        # Set category
        category = self.entry.category or "General"
        index = self.category_combo.findText(category)
        if index >= 0:
            self.category_combo.setCurrentIndex(index)
        else:
            self.category_combo.setCurrentText(category)
            
    def set_defaults(self):
        """Set default values for new entry."""
        self.category_combo.setCurrentText("General")
        
    def on_password_changed(self):
        """Handle password input changes."""
        password = self.password_input.text()
        
        # Update strength indicator
        self.update_password_strength(password)
        
        # Validate form
        self.validate_form()
        
    def update_password_strength(self, password: str):
        """Update password strength indicator."""
        if not password:
            self.strength_bar.setValue(0)
            self.strength_label.setText("Enter password to see strength")
            self.strength_label.setStyleSheet("font-size: 10pt; color: #6C757D;")
            return
            
        # Assess password strength
        strength_level, entropy, criteria = password_generator.assess_password_strength(password)
        
        # Update progress bar
        strength_percent = min(100, int(entropy * 1.5))  # Scale entropy to percentage
        self.strength_bar.setValue(strength_percent)
        
        # Update label and colors
        strength_colors = {
            PasswordStrength.VERY_WEAK: ("#E74C3C", "Very Weak"),
            PasswordStrength.WEAK: ("#E67E22", "Weak"),
            PasswordStrength.FAIR: ("#F39C12", "Fair"),
            PasswordStrength.GOOD: ("#27AE60", "Good"),
            PasswordStrength.STRONG: ("#2ECC71", "Strong"),
            PasswordStrength.VERY_STRONG: ("#16A085", "Very Strong")
        }
        
        color, text = strength_colors.get(strength_level, ("#E74C3C", "Very Weak"))
        self.strength_label.setText(f"Strength: {text} ({entropy:.1f} bits)")
        self.strength_label.setStyleSheet(f"font-size: 10pt; color: {color}; font-weight: bold;")
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
        
    def toggle_password_visibility(self, checked):
        """Toggle password field visibility."""
        echo_mode = QLineEdit.Normal if checked else QLineEdit.Password
        self.password_input.setEchoMode(echo_mode)
        self.confirm_password_input.setEchoMode(echo_mode)
        
    def generate_password(self):
        """Generate a secure password."""
        try:
            # Generate password with good defaults
            password = password_generator.generate_password(
                length=16,
                include_uppercase=True,
                include_lowercase=True,
                include_digits=True,
                include_symbols=True,
                exclude_ambiguous=True
            )
            
            # Set password in both fields
            self.password_input.setText(password)
            self.confirm_password_input.setText(password)
            
            # Log security event
            security_monitor.log_security_event(
                "password_generated",
                SecurityLevel.LOW,
                "Password generated in form dialog",
                "password_form"
            )
            
        except Exception as e:
            self.logger.error(f"Password generation failed: {str(e)}")
            QMessageBox.warning(self, "Error", f"Failed to generate password:\n{str(e)}")
            
    def validate_form(self):
        """Validate form inputs."""
        self.validation_errors.clear()
        
        # Validate title
        title = self.title_input.text().strip()
        if not title:
            self.validation_errors['title'] = "Title is required"
        elif len(title) > 100:
            self.validation_errors['title'] = "Title is too long (max 100 characters)"
            
        # Validate username
        username = self.username_input.text().strip()
        if username:
            is_valid, error = input_validator.validate_text_input(username, "Username", 100)
            if not is_valid:
                self.validation_errors['username'] = error
                
        # Validate password
        password = self.password_input.text()
        if not password:
            self.validation_errors['password'] = "Password is required"
        else:
            # Check password strength for new entries
            if not self.is_editing:
                is_valid, errors, _ = input_validator.validate_password_strength(password)
                if not is_valid:
                    self.validation_errors['password'] = "; ".join(errors)
                    
        # Validate password confirmation
        confirm_password = self.confirm_password_input.text()
        if password != confirm_password:
            self.validation_errors['confirm_password'] = "Passwords do not match"
            
        # Validate URL
        url = self.url_input.text().strip()
        if url:
            is_valid, error = input_validator.validate_url(url)
            if not is_valid:
                self.validation_errors['url'] = error
                
        # Validate category
        category = self.category_combo.currentText().strip()
        if category:
            is_valid, error = input_validator.validate_category(category)
            if not is_valid:
                self.validation_errors['category'] = error
                
        # Update UI based on validation
        self.update_validation_ui()
        
        # Enable/disable save button
        save_button = self.button_box.button(QDialogButtonBox.Save)
        save_button.setEnabled(len(self.validation_errors) == 0)
        
    def update_validation_ui(self):
        """Update UI to show validation errors."""
        # Reset all field styles
        fields = [
            self.title_input, self.username_input, self.password_input,
            self.confirm_password_input, self.url_input, self.category_combo
        ]
        
        for field in fields:
            field.setStyleSheet("")
            
        # Highlight fields with errors
        error_style = f"border: 2px solid {theme_manager.get_color('danger')};"
        
        if 'title' in self.validation_errors:
            self.title_input.setStyleSheet(error_style)
            self.title_input.setToolTip(self.validation_errors['title'])
        else:
            self.title_input.setToolTip("")
            
        if 'username' in self.validation_errors:
            self.username_input.setStyleSheet(error_style)
            self.username_input.setToolTip(self.validation_errors['username'])
        else:
            self.username_input.setToolTip("")
            
        if 'password' in self.validation_errors:
            self.password_input.setStyleSheet(error_style)
            self.password_input.setToolTip(self.validation_errors['password'])
        else:
            self.password_input.setToolTip("")
            
        if 'confirm_password' in self.validation_errors:
            self.confirm_password_input.setStyleSheet(error_style)
            self.confirm_password_input.setToolTip(self.validation_errors['confirm_password'])
        else:
            self.confirm_password_input.setToolTip("")
            
        if 'url' in self.validation_errors:
            self.url_input.setStyleSheet(error_style)
            self.url_input.setToolTip(self.validation_errors['url'])
        else:
            self.url_input.setToolTip("")
            
        if 'category' in self.validation_errors:
            self.category_combo.setStyleSheet(error_style)
            self.category_combo.setToolTip(self.validation_errors['category'])
        else:
            self.category_combo.setToolTip("")
            
    def save_entry(self):
        """Save password entry."""
        if self.validation_errors:
            error_messages = "\n".join(self.validation_errors.values())
            QMessageBox.warning(self, "Validation Error", f"Please fix the following errors:\n\n{error_messages}")
            return
            
        try:
            # Create or update entry
            if self.is_editing:
                entry = self.entry
                entry.title = self.title_input.text().strip()
                entry.username = self.username_input.text().strip() or None
                entry.password = self.password_input.text()
                entry.url = self.url_input.text().strip() or None
                entry.notes = self.notes_input.toPlainText().strip() or None
                entry.category = self.category_combo.currentText().strip() or "General"
                entry.updated_at = datetime.now(timezone.utc)
                
                # Update in database
                success = self.db_manager.update_password_entry(entry)
                action = "updated"
            else:
                entry = PasswordEntry(
                    title=self.title_input.text().strip(),
                    username=self.username_input.text().strip() or None,
                    password=self.password_input.text(),
                    url=self.url_input.text().strip() or None,
                    notes=self.notes_input.toPlainText().strip() or None,
                    category=self.category_combo.currentText().strip() or "General"
                )
                
                # Add to database
                entry_id = self.db_manager.add_password_entry(entry)
                if entry_id:
                    entry.entry_id = entry_id
                    success = True
                else:
                    success = False
                action = "added"
                
            if success:
                # Log security event
                security_monitor.log_security_event(
                    f"password_entry_{action}",
                    SecurityLevel.LOW,
                    f"Password entry {action}: {entry.title}",
                    "password_form"
                )
                
                # Emit signal and accept dialog
                self.entry_saved.emit(entry)
                self.accept()
            else:
                QMessageBox.critical(self, "Error", f"Failed to save password entry.")
                
        except Exception as e:
            self.logger.error(f"Failed to save entry: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to save password entry:\n{str(e)}")
            
    def get_password_entry(self) -> Optional[PasswordEntry]:
        """Get the password entry from form data."""
        if self.result() == QDialog.Accepted:
            return self.entry if self.is_editing else None
        return None
        
    def closeEvent(self, event):
        """Handle dialog close event."""
        # Check for unsaved changes
        if self.has_unsaved_changes():
            reply = QMessageBox.question(
                self,
                "Unsaved Changes",
                "You have unsaved changes. Are you sure you want to close?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            
            if reply == QMessageBox.No:
                event.ignore()
                return
                
        super().closeEvent(event)
        
    def has_unsaved_changes(self) -> bool:
        """Check if form has unsaved changes."""
        if not self.is_editing:
            # For new entries, check if any field has content
            return (
                bool(self.title_input.text().strip()) or
                bool(self.username_input.text().strip()) or
                bool(self.password_input.text()) or
                bool(self.url_input.text().strip()) or
                bool(self.notes_input.toPlainText().strip())
            )
        else:
            # For editing, check if any field has changed
            return (
                self.title_input.text().strip() != self.entry.title or
                (self.username_input.text().strip() or None) != self.entry.username or
                self.password_input.text() != self.entry.password or
                (self.url_input.text().strip() or None) != self.entry.url or
                (self.notes_input.toPlainText().strip() or None) != self.entry.notes or
                (self.category_combo.currentText().strip() or "General") != (self.entry.category or "General")
            )
