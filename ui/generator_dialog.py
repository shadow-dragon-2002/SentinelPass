"""
Password generator dialog for SentinelPass Password Manager.

This module provides a comprehensive password generator interface with
customizable options, strength analysis, and multiple generation modes
including passwords and passphrases.

Features:
- Customizable password generation options
- Real-time password strength analysis
- Passphrase generation with word lists
- Generation history
- Quick copy functionality
- Preset configurations

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import List, Dict, Any, Optional
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QLineEdit, QPushButton, QCheckBox, QSpinBox, QSlider,
    QComboBox, QTextEdit, QGroupBox, QTabWidget, QWidget, QProgressBar,
    QListWidget, QListWidgetItem, QSplitter, QFrame, QButtonGroup,
    QRadioButton, QDialogButtonBox, QMessageBox, QApplication
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QClipboard

from config.settings import settings
from core.password_generator import password_generator, PasswordStrength
from utils.clipboard import clipboard_manager
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager


class PasswordGeneratorTab(QWidget):
    """
    Password generation tab with customizable options.
    
    Provides comprehensive password generation with various customization
    options and real-time strength analysis.
    """
    
    # Signals
    password_generated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """Initialize password generator tab."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        
        # UI components
        self.length_slider = None
        self.length_spinbox = None
        self.uppercase_checkbox = None
        self.lowercase_checkbox = None
        self.digits_checkbox = None
        self.symbols_checkbox = None
        self.ambiguous_checkbox = None
        self.custom_symbols_input = None
        self.min_uppercase_spinbox = None
        self.min_lowercase_spinbox = None
        self.min_digits_spinbox = None
        self.min_symbols_spinbox = None
        self.preset_combo = None
        self.password_output = None
        self.strength_bar = None
        self.strength_label = None
        self.generate_button = None
        self.copy_button = None
        
        self.setup_ui()
        self.connect_signals()
        self.load_presets()
        self.set_defaults()
        
    def setup_ui(self):
        """Setup the password generator UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Preset section
        preset_layout = self.create_preset_section()
        layout.addLayout(preset_layout)
        
        # Options section
        options_group = self.create_options_section()
        layout.addWidget(options_group)
        
        # Advanced options section
        advanced_group = self.create_advanced_section()
        layout.addWidget(advanced_group)
        
        # Generation section
        generation_group = self.create_generation_section()
        layout.addWidget(generation_group)
        
        # Strength section
        strength_group = self.create_strength_section()
        layout.addWidget(strength_group)
        
        layout.addStretch()
        
    def create_preset_section(self):
        """Create preset selection section."""
        layout = QHBoxLayout()
        
        preset_label = QLabel("Preset:")
        preset_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(preset_label)
        
        self.preset_combo = QComboBox()
        self.preset_combo.setMinimumWidth(200)
        layout.addWidget(self.preset_combo)
        
        layout.addStretch()
        
        return layout
        
    def create_options_section(self):
        """Create basic options section."""
        group = QGroupBox("Password Options")
        layout = QVBoxLayout(group)
        
        # Length section
        length_layout = QHBoxLayout()
        
        length_label = QLabel("Length:")
        length_label.setStyleSheet("font-weight: bold;")
        length_layout.addWidget(length_label)
        
        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(4, 64)
        self.length_slider.setValue(16)
        length_layout.addWidget(self.length_slider)
        
        self.length_spinbox = QSpinBox()
        self.length_spinbox.setRange(4, 64)
        self.length_spinbox.setValue(16)
        self.length_spinbox.setMaximumWidth(60)
        length_layout.addWidget(self.length_spinbox)
        
        layout.addLayout(length_layout)
        
        # Character type checkboxes
        checkbox_layout = QGridLayout()
        
        self.uppercase_checkbox = QCheckBox("Uppercase letters (A-Z)")
        self.uppercase_checkbox.setChecked(True)
        checkbox_layout.addWidget(self.uppercase_checkbox, 0, 0)
        
        self.lowercase_checkbox = QCheckBox("Lowercase letters (a-z)")
        self.lowercase_checkbox.setChecked(True)
        checkbox_layout.addWidget(self.lowercase_checkbox, 0, 1)
        
        self.digits_checkbox = QCheckBox("Digits (0-9)")
        self.digits_checkbox.setChecked(True)
        checkbox_layout.addWidget(self.digits_checkbox, 1, 0)
        
        self.symbols_checkbox = QCheckBox("Symbols (!@#$%^&*)")
        self.symbols_checkbox.setChecked(True)
        checkbox_layout.addWidget(self.symbols_checkbox, 1, 1)
        
        self.ambiguous_checkbox = QCheckBox("Exclude ambiguous characters (0, O, l, I)")
        self.ambiguous_checkbox.setChecked(True)
        checkbox_layout.addWidget(self.ambiguous_checkbox, 2, 0, 1, 2)
        
        layout.addLayout(checkbox_layout)
        
        return group
        
    def create_advanced_section(self):
        """Create advanced options section."""
        group = QGroupBox("Advanced Options")
        layout = QVBoxLayout(group)
        
        # Custom symbols
        symbols_layout = QHBoxLayout()
        symbols_label = QLabel("Custom symbols:")
        symbols_layout.addWidget(symbols_label)
        
        self.custom_symbols_input = QLineEdit()
        self.custom_symbols_input.setPlaceholderText("Leave empty to use default symbols")
        symbols_layout.addWidget(self.custom_symbols_input)
        
        layout.addLayout(symbols_layout)
        
        # Minimum requirements
        min_req_layout = QGridLayout()
        
        min_req_layout.addWidget(QLabel("Minimum uppercase:"), 0, 0)
        self.min_uppercase_spinbox = QSpinBox()
        self.min_uppercase_spinbox.setRange(0, 10)
        self.min_uppercase_spinbox.setValue(1)
        min_req_layout.addWidget(self.min_uppercase_spinbox, 0, 1)
        
        min_req_layout.addWidget(QLabel("Minimum lowercase:"), 0, 2)
        self.min_lowercase_spinbox = QSpinBox()
        self.min_lowercase_spinbox.setRange(0, 10)
        self.min_lowercase_spinbox.setValue(1)
        min_req_layout.addWidget(self.min_lowercase_spinbox, 0, 3)
        
        min_req_layout.addWidget(QLabel("Minimum digits:"), 1, 0)
        self.min_digits_spinbox = QSpinBox()
        self.min_digits_spinbox.setRange(0, 10)
        self.min_digits_spinbox.setValue(1)
        min_req_layout.addWidget(self.min_digits_spinbox, 1, 1)
        
        min_req_layout.addWidget(QLabel("Minimum symbols:"), 1, 2)
        self.min_symbols_spinbox = QSpinBox()
        self.min_symbols_spinbox.setRange(0, 10)
        self.min_symbols_spinbox.setValue(1)
        min_req_layout.addWidget(self.min_symbols_spinbox, 1, 3)
        
        layout.addLayout(min_req_layout)
        
        return group
        
    def create_generation_section(self):
        """Create password generation section."""
        group = QGroupBox("Generated Password")
        layout = QVBoxLayout(group)
        
        # Password output
        self.password_output = QLineEdit()
        self.password_output.setReadOnly(True)
        self.password_output.setStyleSheet(
            "font-family: 'Consolas', 'Monaco', monospace; "
            "font-size: 12pt; padding: 8px; "
            "background-color: #F8F9FA; border: 2px solid #DEE2E6;"
        )
        layout.addWidget(self.password_output)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("Generate Password")
        self.generate_button.setStyleSheet(
            f"QPushButton {{ "
            f"background-color: {theme_manager.get_color('secondary')}; "
            f"color: white; font-weight: bold; padding: 8px 16px; "
            f"}} "
            f"QPushButton:hover {{ "
            f"background-color: {theme_manager.get_color('secondary_light')}; "
            f"}}"
        )
        button_layout.addWidget(self.generate_button)
        
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.setEnabled(False)
        button_layout.addWidget(self.copy_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
        
    def create_strength_section(self):
        """Create password strength section."""
        group = QGroupBox("Password Strength")
        layout = QVBoxLayout(group)
        
        # Strength bar
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        layout.addWidget(self.strength_bar)
        
        # Strength label
        self.strength_label = QLabel("Generate a password to see strength analysis")
        self.strength_label.setAlignment(Qt.AlignCenter)
        self.strength_label.setWordWrap(True)
        layout.addWidget(self.strength_label)
        
        return group
        
    def connect_signals(self):
        """Connect UI signals."""
        # Length controls
        self.length_slider.valueChanged.connect(self.length_spinbox.setValue)
        self.length_spinbox.valueChanged.connect(self.length_slider.setValue)
        
        # Preset selection
        self.preset_combo.currentTextChanged.connect(self.apply_preset)
        
        # Character type checkboxes
        checkboxes = [
            self.uppercase_checkbox, self.lowercase_checkbox,
            self.digits_checkbox, self.symbols_checkbox
        ]
        for checkbox in checkboxes:
            checkbox.toggled.connect(self.validate_options)
            
        # Generation buttons
        self.generate_button.clicked.connect(self.generate_password)
        self.copy_button.clicked.connect(self.copy_password)
        
    def load_presets(self):
        """Load password generation presets."""
        presets = password_generator.get_generation_presets()
        
        self.preset_combo.addItem("Custom")
        for preset_name in presets.keys():
            display_name = preset_name.replace('_', ' ').title()
            self.preset_combo.addItem(display_name, preset_name)
            
    def set_defaults(self):
        """Set default values."""
        self.preset_combo.setCurrentText("Medium Security")
        
    def apply_preset(self, preset_display_name):
        """Apply selected preset configuration."""
        if preset_display_name == "Custom":
            return
            
        # Find preset by display name
        presets = password_generator.get_generation_presets()
        preset_key = None
        
        for key in presets.keys():
            if key.replace('_', ' ').title() == preset_display_name:
                preset_key = key
                break
                
        if not preset_key:
            return
            
        preset = presets[preset_key]
        
        # Apply preset settings
        self.length_slider.setValue(preset.get('length', 16))
        self.uppercase_checkbox.setChecked(preset.get('include_uppercase', True))
        self.lowercase_checkbox.setChecked(preset.get('include_lowercase', True))
        self.digits_checkbox.setChecked(preset.get('include_digits', True))
        self.symbols_checkbox.setChecked(preset.get('include_symbols', True))
        self.ambiguous_checkbox.setChecked(preset.get('exclude_ambiguous', True))
        
        # Apply minimum requirements
        self.min_uppercase_spinbox.setValue(preset.get('min_uppercase', 1))
        self.min_lowercase_spinbox.setValue(preset.get('min_lowercase', 1))
        self.min_digits_spinbox.setValue(preset.get('min_digits', 1))
        self.min_symbols_spinbox.setValue(preset.get('min_symbols', 1))
        
    def validate_options(self):
        """Validate generation options."""
        # At least one character type must be selected
        has_char_type = (
            self.uppercase_checkbox.isChecked() or
            self.lowercase_checkbox.isChecked() or
            self.digits_checkbox.isChecked() or
            self.symbols_checkbox.isChecked()
        )
        
        self.generate_button.setEnabled(has_char_type)
        
        if not has_char_type:
            self.password_output.setText("")
            self.copy_button.setEnabled(False)
            self.update_strength_display("", 0, "Select at least one character type")
            
    def generate_password(self):
        """Generate password with current settings."""
        try:
            # Get generation parameters
            params = {
                'length': self.length_slider.value(),
                'include_uppercase': self.uppercase_checkbox.isChecked(),
                'include_lowercase': self.lowercase_checkbox.isChecked(),
                'include_digits': self.digits_checkbox.isChecked(),
                'include_symbols': self.symbols_checkbox.isChecked(),
                'exclude_ambiguous': self.ambiguous_checkbox.isChecked(),
                'min_uppercase': self.min_uppercase_spinbox.value(),
                'min_lowercase': self.min_lowercase_spinbox.value(),
                'min_digits': self.min_digits_spinbox.value(),
                'min_symbols': self.min_symbols_spinbox.value()
            }
            
            # Add custom symbols if specified
            custom_symbols = self.custom_symbols_input.text().strip()
            if custom_symbols:
                params['custom_symbols'] = custom_symbols
                
            # Validate parameters
            is_valid, errors = password_generator.validate_generation_params(**params)
            if not is_valid:
                QMessageBox.warning(self, "Invalid Parameters", "\n".join(errors))
                return
                
            # Generate password
            password = password_generator.generate_password(**params)
            
            # Display password
            self.password_output.setText(password)
            self.copy_button.setEnabled(True)
            
            # Update strength analysis
            strength_level, entropy, criteria = password_generator.assess_password_strength(password)
            self.update_strength_analysis(password, strength_level, entropy, criteria)
            
            # Emit signal
            self.password_generated.emit(password)
            
            # Log security event
            security_monitor.log_security_event(
                "password_generated",
                SecurityLevel.LOW,
                f"Password generated with length {len(password)}",
                "generator_dialog"
            )
            
        except Exception as e:
            self.logger.error(f"Password generation failed: {str(e)}")
            QMessageBox.critical(self, "Generation Error", f"Failed to generate password:\n{str(e)}")
            
    def update_strength_analysis(self, password: str, strength_level: PasswordStrength, 
                               entropy: float, criteria: Dict[str, bool]):
        """Update password strength analysis display."""
        # Update progress bar
        strength_percent = min(100, int(entropy * 1.5))
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
        
        # Create detailed analysis
        analysis_text = f"<b>Strength: {text}</b><br>"
        analysis_text += f"<b>Entropy: {entropy:.1f} bits</b><br><br>"
        
        # Add criteria details
        criteria_text = []
        if criteria.get('has_lowercase'):
            criteria_text.append("✓ Lowercase letters")
        if criteria.get('has_uppercase'):
            criteria_text.append("✓ Uppercase letters")
        if criteria.get('has_digits'):
            criteria_text.append("✓ Digits")
        if criteria.get('has_symbols'):
            criteria_text.append("✓ Symbols")
        if criteria.get('no_common_patterns'):
            criteria_text.append("✓ No common patterns")
        if criteria.get('no_repetition'):
            criteria_text.append("✓ No excessive repetition")
            
        analysis_text += "<br>".join(criteria_text)
        
        self.strength_label.setText(analysis_text)
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
        
    def update_strength_display(self, password: str, strength: int, message: str):
        """Update strength display with custom message."""
        self.strength_bar.setValue(strength)
        self.strength_label.setText(message)
        
    def copy_password(self):
        """Copy generated password to clipboard."""
        password = self.password_output.text()
        if password:
            success = clipboard_manager.copy_password_entry_field(
                password, "generated password", "Password Generator"
            )
            if success:
                self.copy_button.setText("Copied!")
                QTimer.singleShot(2000, lambda: self.copy_button.setText("Copy to Clipboard"))
            else:
                QMessageBox.warning(self, "Copy Failed", "Failed to copy password to clipboard.")
                
    def get_current_password(self) -> str:
        """Get currently generated password."""
        return self.password_output.text()


class PassphraseGeneratorTab(QWidget):
    """
    Passphrase generation tab with word-based passwords.
    
    Provides passphrase generation using word lists for more
    memorable but still secure passwords.
    """
    
    # Signals
    passphrase_generated = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """Initialize passphrase generator tab."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        
        # UI components
        self.word_count_slider = None
        self.word_count_spinbox = None
        self.separator_input = None
        self.numbers_checkbox = None
        self.capitalize_checkbox = None
        self.passphrase_output = None
        self.generate_button = None
        self.copy_button = None
        self.strength_bar = None
        self.strength_label = None
        
        self.setup_ui()
        self.connect_signals()
        self.set_defaults()
        
    def setup_ui(self):
        """Setup the passphrase generator UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Options section
        options_group = self.create_options_section()
        layout.addWidget(options_group)
        
        # Generation section
        generation_group = self.create_generation_section()
        layout.addWidget(generation_group)
        
        # Strength section
        strength_group = self.create_strength_section()
        layout.addWidget(strength_group)
        
        # Info section
        info_group = self.create_info_section()
        layout.addWidget(info_group)
        
        layout.addStretch()
        
    def create_options_section(self):
        """Create passphrase options section."""
        group = QGroupBox("Passphrase Options")
        layout = QVBoxLayout(group)
        
        # Word count
        word_count_layout = QHBoxLayout()
        
        word_count_label = QLabel("Number of words:")
        word_count_label.setStyleSheet("font-weight: bold;")
        word_count_layout.addWidget(word_count_label)
        
        self.word_count_slider = QSlider(Qt.Horizontal)
        self.word_count_slider.setRange(3, 8)
        self.word_count_slider.setValue(4)
        word_count_layout.addWidget(self.word_count_slider)
        
        self.word_count_spinbox = QSpinBox()
        self.word_count_spinbox.setRange(3, 8)
        self.word_count_spinbox.setValue(4)
        self.word_count_spinbox.setMaximumWidth(60)
        word_count_layout.addWidget(self.word_count_spinbox)
        
        layout.addLayout(word_count_layout)
        
        # Separator
        separator_layout = QHBoxLayout()
        separator_label = QLabel("Word separator:")
        separator_layout.addWidget(separator_label)
        
        self.separator_input = QLineEdit()
        self.separator_input.setText("-")
        self.separator_input.setMaximumWidth(100)
        separator_layout.addWidget(self.separator_input)
        
        separator_layout.addStretch()
        layout.addLayout(separator_layout)
        
        # Options checkboxes
        self.numbers_checkbox = QCheckBox("Include random numbers")
        self.numbers_checkbox.setChecked(True)
        layout.addWidget(self.numbers_checkbox)
        
        self.capitalize_checkbox = QCheckBox("Capitalize first letter of each word")
        self.capitalize_checkbox.setChecked(True)
        layout.addWidget(self.capitalize_checkbox)
        
        return group
        
    def create_generation_section(self):
        """Create passphrase generation section."""
        group = QGroupBox("Generated Passphrase")
        layout = QVBoxLayout(group)
        
        # Passphrase output
        self.passphrase_output = QLineEdit()
        self.passphrase_output.setReadOnly(True)
        self.passphrase_output.setStyleSheet(
            "font-family: 'Consolas', 'Monaco', monospace; "
            "font-size: 12pt; padding: 8px; "
            "background-color: #F8F9FA; border: 2px solid #DEE2E6;"
        )
        layout.addWidget(self.passphrase_output)
        
        # Buttons
        button_layout = QHBoxLayout()
        
        self.generate_button = QPushButton("Generate Passphrase")
        self.generate_button.setStyleSheet(
            f"QPushButton {{ "
            f"background-color: {theme_manager.get_color('secondary')}; "
            f"color: white; font-weight: bold; padding: 8px 16px; "
            f"}} "
            f"QPushButton:hover {{ "
            f"background-color: {theme_manager.get_color('secondary_light')}; "
            f"}}"
        )
        button_layout.addWidget(self.generate_button)
        
        self.copy_button = QPushButton("Copy to Clipboard")
        self.copy_button.setEnabled(False)
        button_layout.addWidget(self.copy_button)
        
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
        
    def create_strength_section(self):
        """Create passphrase strength section."""
        group = QGroupBox("Passphrase Strength")
        layout = QVBoxLayout(group)
        
        # Strength bar
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        layout.addWidget(self.strength_bar)
        
        # Strength label
        self.strength_label = QLabel("Generate a passphrase to see strength analysis")
        self.strength_label.setAlignment(Qt.AlignCenter)
        self.strength_label.setWordWrap(True)
        layout.addWidget(self.strength_label)
        
        return group
        
    def create_info_section(self):
        """Create information section."""
        group = QGroupBox("About Passphrases")
        layout = QVBoxLayout(group)
        
        info_text = """
        <b>Passphrases</b> are passwords made up of multiple words. They offer several advantages:
        <ul>
        <li><b>Memorable:</b> Easier to remember than random character strings</li>
        <li><b>Secure:</b> Long length provides high entropy</li>
        <li><b>Typeable:</b> Easier to type accurately</li>
        </ul>
        
        <b>Example:</b> "Correct-Horse-Battery-Staple-42" is both secure and memorable.
        """
        
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        info_label.setStyleSheet("padding: 10px; background-color: rgba(52, 152, 219, 0.1); border-radius: 5px;")
        layout.addWidget(info_label)
        
        return group
        
    def connect_signals(self):
        """Connect UI signals."""
        # Word count controls
        self.word_count_slider.valueChanged.connect(self.word_count_spinbox.setValue)
        self.word_count_spinbox.valueChanged.connect(self.word_count_slider.setValue)
        
        # Generation buttons
        self.generate_button.clicked.connect(self.generate_passphrase)
        self.copy_button.clicked.connect(self.copy_passphrase)
        
    def set_defaults(self):
        """Set default values."""
        pass  # Defaults are set in UI creation
        
    def generate_passphrase(self):
        """Generate passphrase with current settings."""
        try:
            # Get generation parameters
            word_count = self.word_count_slider.value()
            separator = self.separator_input.text()
            include_numbers = self.numbers_checkbox.isChecked()
            capitalize_words = self.capitalize_checkbox.isChecked()
            
            # Generate passphrase
            passphrase = password_generator.generate_passphrase(
                word_count=word_count,
                separator=separator,
                include_numbers=include_numbers,
                capitalize_words=capitalize_words
            )
            
            # Display passphrase
            self.passphrase_output.setText(passphrase)
            self.copy_button.setEnabled(True)
            
            # Update strength analysis
            strength_level, entropy, criteria = password_generator.assess_password_strength(passphrase)
            self.update_strength_analysis(passphrase, strength_level, entropy, criteria)
            
            # Emit signal
            self.passphrase_generated.emit(passphrase)
            
            # Log security event
            security_monitor.log_security_event(
                "passphrase_generated",
                SecurityLevel.LOW,
                f"Passphrase generated with {word_count} words",
                "generator_dialog"
            )
            
        except Exception as e:
            self.logger.error(f"Passphrase generation failed: {str(e)}")
            QMessageBox.critical(self, "Generation Error", f"Failed to generate passphrase:\n{str(e)}")
            
    def update_strength_analysis(self, passphrase: str, strength_level: PasswordStrength, 
                               entropy: float, criteria: Dict[str, bool]):
        """Update passphrase strength analysis display."""
        # Update progress bar
        strength_percent = min(100, int(entropy * 1.5))
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
        
        # Create analysis text
        analysis_text = f"<b>Strength: {text}</b><br>"
        analysis_text += f"<b>Entropy: {entropy:.1f} bits</b><br>"
        analysis_text += f"<b>Length: {len(passphrase)} characters</b>"
        
        self.strength_label.setText(analysis_text)
        self.strength_bar.setStyleSheet(f"QProgressBar::chunk {{ background-color: {color}; }}")
        
    def copy_passphrase(self):
        """Copy generated passphrase to clipboard."""
        passphrase = self.passphrase_output.text()
        if passphrase:
            success = clipboard_manager.copy_password_entry_field(
                passphrase, "generated passphrase", "Passphrase Generator"
            )
            if success:
                self.copy_button.setText("Copied!")
                QTimer.singleShot(2000, lambda: self.copy_button.setText("Copy to Clipboard"))
            else:
                QMessageBox.warning(self, "Copy Failed", "Failed to copy passphrase to clipboard.")
                
    def get_current_passphrase(self) -> str:
        """Get currently generated passphrase."""
        return self.passphrase_output.text()


class GenerationHistoryWidget(QListWidget):
    """
    Widget for displaying password generation history.
    
    Shows recently generated passwords and passphrases with
    timestamps and quick copy functionality.
    """
    
    def __init__(self, parent=None):
        """Initialize generation history widget."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.history = []
        self.max_history = 50
        
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup history widget UI."""
        self.setMaximumHeight(200)
        self.setAlternatingRowColors(True)
        
    def connect_signals(self):
        """Connect widget signals."""
        self.itemDoubleClicked.connect(self.copy_item)
        
    def add_generation(self, password: str, generation_type: str):
        """Add a generation to history."""
        from datetime import datetime
        
        timestamp = datetime.now()
        entry = {
            'password': password,
            'type': generation_type,
            'timestamp': timestamp,
            'length': len(password)
        }
        
        self.history.insert(0, entry)
        
        # Limit history size
        if len(self.history) > self.max_history:
            self.history = self.history[:self.max_history]
            
        self.refresh_display()
        
    def refresh_display(self):
        """Refresh the history display."""
        self.clear()
        
        for entry in self.history:
            timestamp_str = entry['timestamp'].strftime('%H:%M:%S')
            display_text = f"[{timestamp_str}] {entry['type']} - {entry['length']} chars"
            
            item = QListWidgetItem(display_text)
            item.setData(Qt.UserRole, entry)
            self.addItem(item)
            
    def copy_item(self, item):
        """Copy selected item to clipboard."""
        entry = item.data(Qt.UserRole)
        if entry:
            success = clipboard_manager.copy_password_entry_field(
                entry['password'], f"history {entry['type']}", "Generation History"
            )
            if success:
                QMessageBox.information(self, "Copied", "Password copied to clipboard!")
                
    def clear_history(self):
        """Clear generation history."""
        self.history.clear()
        self.clear()


class PasswordGeneratorDialog(QDialog):
    """
    Main password generator dialog.
    
    Provides comprehensive password and passphrase generation
    with tabbed interface and generation history.
    """
    
    def __init__(self, parent=None):
        """Initialize password generator dialog."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        
        # UI components
        self.tab_widget = None
        self.password_tab = None
        self.passphrase_tab = None
        self.history_widget = None
        self.button_box = None
        
        self.setup_dialog()
        self.setup_ui()
        self.connect_signals()
        
    def setup_dialog(self):
        """Setup dialog properties."""
        self.setWindowTitle("SentinelPass - Password Generator")
        self.setModal(True)
        self.setMinimumSize(600, 700)
        self.resize(700, 800)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
    def setup_ui(self):
        """Setup password generator dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header_label = QLabel("Password Generator")
        header_label.setStyleSheet(
            f"font-size: 18pt; font-weight: bold; "
            f"color: {theme_manager.get_color('secondary')}; "
            f"margin: 10px 0;"
        )
        layout.addWidget(header_label)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Password generator tab
        self.password_tab = PasswordGeneratorTab()
        self.tab_widget.addTab(self.password_tab, "🔐 Password")
        
        # Passphrase generator tab
        self.passphrase_tab = PassphraseGeneratorTab()
        self.tab_widget.addTab(self.passphrase_tab, "📝 Passphrase")
        
        layout.addWidget(self.tab_widget)
        
        # History section
        history_group = QGroupBox("Generation History")
        history_layout = QVBoxLayout(history_group)
        
        self.history_widget = GenerationHistoryWidget()
        history_layout.addWidget(self.history_widget)
        
        # History buttons
        history_button_layout = QHBoxLayout()
        
        clear_history_button = QPushButton("Clear History")
        clear_history_button.clicked.connect(self.history_widget.clear_history)
        history_button_layout.addWidget(clear_history_button)
        
        history_button_layout.addStretch()
        history_layout.addLayout(history_button_layout)
        
        layout.addWidget(history_group)
        
        # Button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.Close)
        layout.addWidget(self.button_box)
        
    def connect_signals(self):
        """Connect dialog signals."""
        # Tab signals
        self.password_tab.password_generated.connect(
            lambda pwd: self.history_widget.add_generation(pwd, "Password")
        )
        self.passphrase_tab.passphrase_generated.connect(
            lambda pwd: self.history_widget.add_generation(pwd, "Passphrase")
        )
        
        # Button box
        self.button_box.rejected.connect(self.reject)
        
    def get_current_generation(self) -> Optional[str]:
        """Get currently generated password/passphrase."""
        current_tab = self.tab_widget.currentWidget()
        
        if current_tab == self.password_tab:
            return self.password_tab.get_current_password()
        elif current_tab == self.passphrase_tab:
            return self.passphrase_tab.get_current_passphrase()
        else:
            return None
