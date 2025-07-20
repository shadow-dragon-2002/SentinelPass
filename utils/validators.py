"""
Input validation utilities for SentinelPass Password Manager.

This module provides comprehensive validation functions for user inputs,
passwords, URLs, email addresses, and other data types used throughout
the application.

Security Features:
- Input sanitization and validation
- Password strength validation
- URL and email format validation
- SQL injection prevention
- XSS prevention for text inputs

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import re
import urllib.parse
from typing import Tuple, List, Optional, Any, Dict
import logging

from config.settings import settings


class ValidationError(Exception):
    """Custom exception for validation errors."""
    pass


class InputValidator:
    """
    Comprehensive input validation class.
    
    This class provides various validation methods for different types of
    user inputs to ensure data integrity and security.
    """
    
    def __init__(self):
        """Initialize the input validator."""
        self.logger = logging.getLogger(__name__)
        
        # Regex patterns for validation
        self.email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        self.url_pattern = re.compile(
            r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?$'
        )
        
        # Dangerous characters for XSS prevention
        self.dangerous_chars = ['<', '>', '"', "'", '&', '\x00']
        
        # SQL injection patterns
        self.sql_patterns = [
            r'(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)',
            r'(--|#|/\*|\*/)',
            r'(\bOR\b.*=.*\bOR\b)',
            r'(\bAND\b.*=.*\bAND\b)',
            r'(\'.*\bOR\b.*\')',
            r'(\".*\bOR\b.*\")'
        ]
        
        self.logger.info("InputValidator initialized")
        
    def validate_password_strength(self, password: str) -> Tuple[bool, List[str], Dict[str, Any]]:
        """
        Validate password strength against security requirements.
        
        Args:
            password (str): Password to validate
            
        Returns:
            Tuple[bool, List[str], Dict[str, Any]]: 
                (is_valid, error_messages, strength_info)
        """
        errors = []
        strength_info = {
            'length': len(password),
            'has_uppercase': False,
            'has_lowercase': False,
            'has_digits': False,
            'has_special': False,
            'has_common_patterns': False,
            'entropy_bits': 0.0
        }
        
        try:
            # Check minimum length
            if len(password) < settings.MIN_MASTER_PASSWORD_LENGTH:
                errors.append(f"Password must be at least {settings.MIN_MASTER_PASSWORD_LENGTH} characters long")
                
            # Check character requirements
            if settings.REQUIRE_UPPERCASE:
                if re.search(r'[A-Z]', password):
                    strength_info['has_uppercase'] = True
                else:
                    errors.append("Password must contain at least one uppercase letter")
                    
            if settings.REQUIRE_LOWERCASE:
                if re.search(r'[a-z]', password):
                    strength_info['has_lowercase'] = True
                else:
                    errors.append("Password must contain at least one lowercase letter")
                    
            if settings.REQUIRE_DIGITS:
                if re.search(r'\d', password):
                    strength_info['has_digits'] = True
                else:
                    errors.append("Password must contain at least one digit")
                    
            if settings.REQUIRE_SPECIAL_CHARS:
                if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
                    strength_info['has_special'] = True
                else:
                    errors.append("Password must contain at least one special character")
                    
            # Check for common patterns
            common_patterns = self._check_common_patterns(password)
            if common_patterns:
                strength_info['has_common_patterns'] = True
                errors.extend(common_patterns)
                
            # Calculate entropy (simplified)
            strength_info['entropy_bits'] = self._calculate_password_entropy(password)
            
            is_valid = len(errors) == 0
            return is_valid, errors, strength_info
            
        except Exception as e:
            self.logger.error(f"Password validation failed: {str(e)}")
            return False, ["Password validation failed"], strength_info
            
    def _check_common_patterns(self, password: str) -> List[str]:
        """Check for common password patterns."""
        errors = []
        password_lower = password.lower()
        
        # Common weak passwords
        common_passwords = [
            'password', '123456', 'qwerty', 'abc123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master',
            'password123', 'admin123', 'root', 'toor'
        ]
        
        for common in common_passwords:
            if common in password_lower:
                errors.append(f"Password contains common pattern: {common}")
                
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234', 'abcd']
        for pattern in keyboard_patterns:
            if pattern in password_lower:
                errors.append(f"Password contains keyboard pattern: {pattern}")
                
        # Check for repetitive characters
        if re.search(r'(.)\1{2,}', password):
            errors.append("Password contains repetitive characters")
            
        # Check for sequential characters
        if self._has_sequential_chars(password):
            errors.append("Password contains sequential characters")
            
        return errors
        
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters in password."""
        for i in range(len(password) - 2):
            char1, char2, char3 = password[i:i+3]
            
            # Check for ascending sequence
            if ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1:
                return True
                
            # Check for descending sequence
            if ord(char2) == ord(char1) - 1 and ord(char3) == ord(char2) - 1:
                return True
                
        return False
        
    def _calculate_password_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0
            
        import math
        
        # Determine character set size
        charset_size = 0
        
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
            charset_size += 32
            
        if charset_size == 0:
            return 0.0
            
        # Calculate entropy: log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return entropy
        
    def validate_email(self, email: str) -> Tuple[bool, Optional[str]]:
        """
        Validate email address format.
        
        Args:
            email (str): Email address to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            if not email:
                return False, "Email address is required"
                
            if len(email) > 254:  # RFC 5321 limit
                return False, "Email address is too long"
                
            if not self.email_pattern.match(email):
                return False, "Invalid email address format"
                
            # Check for dangerous characters
            if any(char in email for char in self.dangerous_chars):
                return False, "Email contains invalid characters"
                
            return True, None
            
        except Exception as e:
            self.logger.error(f"Email validation failed: {str(e)}")
            return False, "Email validation failed"
            
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """
        Validate URL format and security.
        
        Args:
            url (str): URL to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            if not url:
                return True, None  # URL is optional
                
            if len(url) > 2048:  # Reasonable URL length limit
                return False, "URL is too long"
                
            # Basic URL format validation
            try:
                parsed = urllib.parse.urlparse(url)
                if not parsed.scheme or not parsed.netloc:
                    return False, "Invalid URL format"
                    
                # Only allow HTTP and HTTPS
                if parsed.scheme.lower() not in ['http', 'https']:
                    return False, "Only HTTP and HTTPS URLs are allowed"
                    
            except Exception:
                return False, "Invalid URL format"
                
            # Check for dangerous characters
            if any(char in url for char in ['<', '>', '"', "'"]):
                return False, "URL contains invalid characters"
                
            return True, None
            
        except Exception as e:
            self.logger.error(f"URL validation failed: {str(e)}")
            return False, "URL validation failed"
            
    def validate_text_input(self, text: str, field_name: str = "Input", 
                           max_length: int = 1000, allow_empty: bool = True) -> Tuple[bool, Optional[str]]:
        """
        Validate general text input for security and format.
        
        Args:
            text (str): Text to validate
            field_name (str): Name of the field for error messages
            max_length (int): Maximum allowed length
            allow_empty (bool): Whether empty input is allowed
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            if not text:
                if not allow_empty:
                    return False, f"{field_name} is required"
                return True, None
                
            if len(text) > max_length:
                return False, f"{field_name} is too long (maximum {max_length} characters)"
                
            # Check for null bytes
            if '\x00' in text:
                return False, f"{field_name} contains invalid characters"
                
            # Check for potential SQL injection
            if self._contains_sql_injection(text):
                return False, f"{field_name} contains potentially dangerous content"
                
            return True, None
            
        except Exception as e:
            self.logger.error(f"Text validation failed: {str(e)}")
            return False, f"{field_name} validation failed"
            
    def _contains_sql_injection(self, text: str) -> bool:
        """Check for potential SQL injection patterns."""
        text_upper = text.upper()
        
        for pattern in self.sql_patterns:
            if re.search(pattern, text_upper, re.IGNORECASE):
                return True
                
        return False
        
    def sanitize_text_input(self, text: str) -> str:
        """
        Sanitize text input by removing/escaping dangerous characters.
        
        Args:
            text (str): Text to sanitize
            
        Returns:
            str: Sanitized text
        """
        if not text:
            return ""
            
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Remove or escape dangerous characters
        replacements = {
            '<': '<',
            '>': '>',
            '"': '"',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
            
        return text.strip()
        
    def validate_filename(self, filename: str) -> Tuple[bool, Optional[str]]:
        """
        Validate filename for security and format.
        
        Args:
            filename (str): Filename to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        try:
            if not filename:
                return False, "Filename is required"
                
            if len(filename) > 255:
                return False, "Filename is too long"
                
            # Check for invalid characters
            invalid_chars = ['<', '>', ':', '"', '|', '?', '*', '/', '\\', '\x00']
            if any(char in filename for char in invalid_chars):
                return False, "Filename contains invalid characters"
                
            # Check for reserved names (Windows)
            reserved_names = [
                'CON', 'PRN', 'AUX', 'NUL',
                'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9'
            ]
            
            name_without_ext = filename.split('.')[0].upper()
            if name_without_ext in reserved_names:
                return False, "Filename uses a reserved name"
                
            # Check for leading/trailing spaces or dots
            if filename != filename.strip(' .'):
                return False, "Filename cannot start or end with spaces or dots"
                
            return True, None
            
        except Exception as e:
            self.logger.error(f"Filename validation failed: {str(e)}")
            return False, "Filename validation failed"
            
    def validate_integer(self, value: Any, field_name: str = "Value", 
                        min_value: Optional[int] = None, 
                        max_value: Optional[int] = None) -> Tuple[bool, Optional[str], Optional[int]]:
        """
        Validate integer input.
        
        Args:
            value: Value to validate
            field_name (str): Name of the field for error messages
            min_value (int, optional): Minimum allowed value
            max_value (int, optional): Maximum allowed value
            
        Returns:
            Tuple[bool, Optional[str], Optional[int]]: (is_valid, error_message, parsed_value)
        """
        try:
            # Try to convert to integer
            if isinstance(value, str):
                if not value.strip():
                    return False, f"{field_name} is required", None
                try:
                    int_value = int(value.strip())
                except ValueError:
                    return False, f"{field_name} must be a valid integer", None
            elif isinstance(value, (int, float)):
                int_value = int(value)
            else:
                return False, f"{field_name} must be a valid integer", None
                
            # Check range
            if min_value is not None and int_value < min_value:
                return False, f"{field_name} must be at least {min_value}", None
                
            if max_value is not None and int_value > max_value:
                return False, f"{field_name} must be at most {max_value}", None
                
            return True, None, int_value
            
        except Exception as e:
            self.logger.error(f"Integer validation failed: {str(e)}")
            return False, f"{field_name} validation failed", None
            
    def validate_category(self, category: str) -> Tuple[bool, Optional[str]]:
        """
        Validate password entry category.
        
        Args:
            category (str): Category to validate
            
        Returns:
            Tuple[bool, Optional[str]]: (is_valid, error_message)
        """
        if not category:
            return True, None  # Category is optional, will default to "General"
            
        # Validate as text input
        is_valid, error = self.validate_text_input(
            category, 
            "Category", 
            max_length=50, 
            allow_empty=True
        )
        
        if not is_valid:
            return is_valid, error
            
        # Additional category-specific validation
        if len(category.strip()) == 0:
            return True, None
            
        # Check for reasonable category name
        if not re.match(r'^[a-zA-Z0-9\s\-_]+$', category):
            return False, "Category can only contain letters, numbers, spaces, hyphens, and underscores"
            
        return True, None
        
    def get_validation_summary(self, validations: List[Tuple[bool, Optional[str]]]) -> Tuple[bool, List[str]]:
        """
        Get summary of multiple validation results.
        
        Args:
            validations: List of validation results
            
        Returns:
            Tuple[bool, List[str]]: (all_valid, error_messages)
        """
        errors = []
        all_valid = True
        
        for is_valid, error_message in validations:
            if not is_valid:
                all_valid = False
                if error_message:
                    errors.append(error_message)
                    
        return all_valid, errors


# Global validator instance
input_validator = InputValidator()
