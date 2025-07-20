"""
Application settings and configuration for SentinelPass Password Manager.

This module contains all configuration constants, settings, and application
parameters used throughout the SentinelPass application.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import os
from pathlib import Path


class AppSettings:
    """
    Central configuration class for SentinelPass application settings.
    
    This class manages all application settings including security parameters,
    file paths, UI settings, and feature flags.
    """
    
    # Application Information
    APP_NAME = "SentinelPass"
    APP_VERSION = "1.0.0"
    APP_AUTHOR = "SentinelPass Project"
    APP_DESCRIPTION = "Professional Password Manager with AES-256 Encryption"
    
    # File and Directory Paths
    BASE_DIR = Path(__file__).parent.parent
    CONFIG_DIR = BASE_DIR / "config"
    DATA_DIR = BASE_DIR / "data"
    BACKUP_DIR = BASE_DIR / "backups"
    LOG_DIR = BASE_DIR / "logs"
    
    # Database Configuration
    DATABASE_NAME = "securepass.db"
    DATABASE_PATH = DATA_DIR / DATABASE_NAME
    
    # Security Settings
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    KEY_DERIVATION_ALGORITHM = "PBKDF2"
    KEY_DERIVATION_ITERATIONS = 100000  # OWASP recommended minimum
    SALT_LENGTH = 32  # 256 bits
    IV_LENGTH = 12    # 96 bits for GCM
    TAG_LENGTH = 16   # 128 bits for GCM
    
    # Master Password Requirements
    MIN_MASTER_PASSWORD_LENGTH = 12
    REQUIRE_UPPERCASE = True
    REQUIRE_LOWERCASE = True
    REQUIRE_DIGITS = True
    REQUIRE_SPECIAL_CHARS = True
    
    # Session Management
    SESSION_TIMEOUT_MINUTES = 15  # Auto-lock after inactivity
    CLIPBOARD_CLEAR_SECONDS = 30  # Clear clipboard after copy
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 5
    
    # Password Generator Defaults
    DEFAULT_PASSWORD_LENGTH = 16
    DEFAULT_INCLUDE_UPPERCASE = True
    DEFAULT_INCLUDE_LOWERCASE = True
    DEFAULT_INCLUDE_DIGITS = True
    DEFAULT_INCLUDE_SYMBOLS = True
    DEFAULT_EXCLUDE_AMBIGUOUS = True
    
    # UI Settings
    WINDOW_MIN_WIDTH = 1000
    WINDOW_MIN_HEIGHT = 700
    WINDOW_DEFAULT_WIDTH = 1200
    WINDOW_DEFAULT_HEIGHT = 800
    
    # Theme Settings
    DEFAULT_THEME = "modern_dark"
    AVAILABLE_THEMES = ["modern_dark", "modern_light", "classic"]
    
    # Google Drive Integration
    GOOGLE_CREDENTIALS_FILE = CONFIG_DIR / "credentials.json"
    GOOGLE_TOKEN_FILE = CONFIG_DIR / "token.json"
    GOOGLE_SCOPES = ['https://www.googleapis.com/auth/drive.file']
    BACKUP_FOLDER_NAME = "SentinelPass_Backups"
    
    # Backup Settings
    AUTO_BACKUP_ENABLED = True
    AUTO_BACKUP_INTERVAL_HOURS = 24
    MAX_LOCAL_BACKUPS = 10
    MAX_CLOUD_BACKUPS = 5
    BACKUP_ENCRYPTION_ENABLED = True
    
    # Logging Configuration
    LOG_LEVEL = "INFO"
    LOG_FILE_MAX_SIZE = 10 * 1024 * 1024  # 10MB
    LOG_FILE_BACKUP_COUNT = 5
    
    # Feature Flags
    ENABLE_GOOGLE_DRIVE_BACKUP = True
    ENABLE_AUTO_BACKUP = True
    ENABLE_PASSWORD_STRENGTH_METER = True
    ENABLE_BREACH_CHECK = False  # Future feature
    ENABLE_TWO_FACTOR_AUTH = False  # Future feature
    
    # Development Settings
    DEBUG_MODE = False
    ENABLE_LOGGING = True
    SHOW_DEBUG_INFO = False
    
    def __init__(self):
        """Initialize application settings and create necessary directories."""
        self._create_directories()
        self._load_user_settings()
        
    def _create_directories(self):
        """Create necessary application directories if they don't exist."""
        directories = [
            self.DATA_DIR,
            self.BACKUP_DIR,
            self.LOG_DIR,
            self.CONFIG_DIR
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            
    def _load_user_settings(self):
        """Load user-specific settings from configuration file."""
        # This method can be extended to load settings from a config file
        # For now, we use default settings
        pass
        
    @property
    def database_path(self):
        """Get the full path to the database file."""
        return str(self.DATABASE_PATH)
        
    @property
    def google_credentials_path(self):
        """Get the path to Google Drive credentials file."""
        return str(self.GOOGLE_CREDENTIALS_FILE)
        
    @property
    def google_token_path(self):
        """Get the path to Google Drive token file."""
        return str(self.GOOGLE_TOKEN_FILE)
        
    @property
    def backup_directory(self):
        """Get the backup directory path."""
        return str(self.BACKUP_DIR)
        
    def get_log_file_path(self):
        """Get the path for the application log file."""
        return str(self.LOG_DIR / "securepass.log")
        
    def is_google_drive_configured(self):
        """Check if Google Drive credentials are configured."""
        return self.GOOGLE_CREDENTIALS_FILE.exists()
        
    def validate_master_password(self, password):
        """
        Validate master password against security requirements.
        
        Args:
            password (str): The password to validate
            
        Returns:
            tuple: (is_valid, error_messages)
        """
        errors = []
        
        if len(password) < self.MIN_MASTER_PASSWORD_LENGTH:
            errors.append(f"Password must be at least {self.MIN_MASTER_PASSWORD_LENGTH} characters long")
            
        if self.REQUIRE_UPPERCASE and not any(c.isupper() for c in password):
            errors.append("Password must contain at least one uppercase letter")
            
        if self.REQUIRE_LOWERCASE and not any(c.islower() for c in password):
            errors.append("Password must contain at least one lowercase letter")
            
        if self.REQUIRE_DIGITS and not any(c.isdigit() for c in password):
            errors.append("Password must contain at least one digit")
            
        if self.REQUIRE_SPECIAL_CHARS and not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            errors.append("Password must contain at least one special character")
            
        return len(errors) == 0, errors


# Global settings instance
settings = AppSettings()
