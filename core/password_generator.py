"""
Advanced password generator module for SentinelPass Password Manager.

This module provides comprehensive password and passphrase generation capabilities
with customizable options for length, character sets, and security requirements.
It uses cryptographically secure random number generation for maximum security.

Features:
- Secure random password generation
- Passphrase generation with word lists
- Customizable character sets and length
- Password strength assessment
- Entropy calculation
- Multiple generation algorithms

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import secrets
import string
import re
import math
from typing import List, Dict, Tuple, Optional, Set
from enum import Enum
import logging

from config.settings import settings


class PasswordStrength(Enum):
    """Enumeration for password strength levels."""
    VERY_WEAK = 1
    WEAK = 2
    FAIR = 3
    GOOD = 4
    STRONG = 5
    VERY_STRONG = 6


class GeneratorError(Exception):
    """Custom exception for password generator errors."""
    pass


class PasswordGenerator:
    """
    Advanced password generator with multiple algorithms and customization options.
    
    This class provides secure password generation using cryptographically strong
    random number generation and various customization options for different
    security requirements.
    """
    
    # Character sets for password generation
    LOWERCASE = string.ascii_lowercase
    UPPERCASE = string.ascii_uppercase
    DIGITS = string.digits
    SYMBOLS = "!@#$%^&*()_+-=[]{}|;:,.<>?"
    AMBIGUOUS_CHARS = "0O1lI|`"
    
    # Common word list for passphrase generation
    WORD_LIST = [
        "ability", "absence", "academy", "account", "accused", "achieve", "acquire", "address",
        "advance", "adviser", "advocate", "against", "airline", "airport", "alcohol", "already",
        "amazing", "ancient", "another", "anxiety", "anxious", "anybody", "anymore", "anywhere",
        "approve", "arrange", "article", "assault", "attempt", "attract", "auction", "average",
        "balance", "barrier", "battery", "bedroom", "benefit", "between", "bicycle", "billion",
        "brother", "brought", "builder", "burning", "cabinet", "caliber", "capable", "capital",
        "captain", "capture", "careful", "carrier", "catalog", "ceiling", "central", "century",
        "certain", "chamber", "channel", "chapter", "charity", "chicken", "circuit", "citizen",
        "classic", "climate", "clothes", "collect", "college", "combine", "comfort", "command",
        "comment", "company", "compare", "compete", "complex", "concept", "concern", "conduct",
        "confirm", "connect", "consent", "consist", "contact", "contain", "content", "contest",
        "context", "control", "convert", "correct", "council", "counter", "country", "courage",
        "creative", "crystal", "culture", "current", "cutting", "dancing", "dealing", "decided",
        "decline", "default", "deliver", "density", "deposit", "desktop", "despite", "destroy",
        "develop", "diamond", "digital", "discuss", "disease", "display", "distant", "diverse",
        "drawing", "driving", "dynamic", "eastern", "economy", "edition", "element", "emotion",
        "emperor", "enhance", "evening", "example", "excited", "exclude", "execute", "exhibit",
        "explain", "explore", "express", "extreme", "factory", "failure", "fantasy", "fashion",
        "feature", "federal", "feeling", "fiction", "fifteen", "finance", "finding", "fishing",
        "fitness", "foreign", "forever", "formula", "fortune", "forward", "freedom", "friends",
        "further", "gallery", "general", "genetic", "genuine", "getting", "greater", "grocery",
        "growing", "habitat", "hanging", "heading", "healthy", "hearing", "heating", "helpful",
        "highway", "history", "holiday", "housing", "however", "hundred", "hunting", "husband",
        "imagine", "improve", "include", "initial", "inquiry", "insight", "install", "instant",
        "instead", "intense", "interim", "involve", "journal", "journey", "justice", "justify",
        "kitchen", "landing", "largely", "lasting", "laundry", "lawsuit", "leading", "learned",
        "leather", "leisure", "library", "license", "limited", "listing", "machine", "manager",
        "married", "massive", "maximum", "meaning", "measure", "medical", "meeting", "mention",
        "message", "mineral", "minimum", "missing", "mission", "mistake", "mixture", "monitor",
        "morning", "musical", "mystery", "natural", "neither", "network", "neutral", "nothing",
        "nuclear", "nursing", "obvious", "offense", "officer", "ongoing", "opening", "operate",
        "opinion", "optical", "organic", "outdoor", "outlook", "outside", "overall", "package",
        "painted", "parking", "partial", "partner", "passage", "passion", "patient", "pattern",
        "payment", "penalty", "perfect", "perform", "perhaps", "picture", "plastic", "popular",
        "portion", "poverty", "precise", "predict", "premier", "prepare", "present", "prevent",
        "primary", "printer", "privacy", "private", "problem", "process", "produce", "product",
        "profile", "program", "project", "promise", "protect", "protest", "provide", "publish",
        "purpose", "pushing", "qualify", "quality", "quarter", "radical", "railway", "readily",
        "reality", "receipt", "receive", "recover", "reflect", "regular", "related", "release",
        "remains", "removal", "replace", "request", "require", "reserve", "resolve", "respect",
        "respond", "restore", "retired", "revenue", "reverse", "routine", "running", "satisfy",
        "science", "scratch", "section", "segment", "serious", "service", "session", "setting",
        "several", "shelter", "sheriff", "showing", "similar", "sitting", "society", "somehow",
        "someone", "speaker", "special", "station", "storage", "strange", "stretch", "student",
        "subject", "succeed", "success", "suggest", "summary", "support", "suppose", "surface",
        "surgery", "surplus", "survive", "suspect", "sustain", "teacher", "telecom", "telling",
        "tension", "theater", "therapy", "thereby", "thought", "through", "tonight", "totally",
        "towards", "traffic", "trained", "transit", "trouble", "turning", "typical", "uniform",
        "unknown", "unusual", "upgrade", "utility", "variety", "vehicle", "venture", "version",
        "veteran", "village", "visible", "waiting", "walking", "warning", "weather", "wedding",
        "weekend", "welcome", "welfare", "western", "whereas", "whether", "willing", "winning",
        "without", "working", "writing", "written"
    ]
    
    def __init__(self):
        """Initialize the password generator."""
        self.logger = logging.getLogger(__name__)
        self.logger.info("PasswordGenerator initialized")
        
    def generate_password(self, 
                         length: int = 16,
                         include_uppercase: bool = True,
                         include_lowercase: bool = True,
                         include_digits: bool = True,
                         include_symbols: bool = True,
                         exclude_ambiguous: bool = True,
                         custom_symbols: Optional[str] = None,
                         min_uppercase: int = 1,
                         min_lowercase: int = 1,
                         min_digits: int = 1,
                         min_symbols: int = 1) -> str:
        """
        Generate a secure random password with specified criteria.
        
        Args:
            length (int): Password length
            include_uppercase (bool): Include uppercase letters
            include_lowercase (bool): Include lowercase letters
            include_digits (bool): Include digits
            include_symbols (bool): Include symbols
            exclude_ambiguous (bool): Exclude ambiguous characters
            custom_symbols (str, optional): Custom symbol set
            min_uppercase (int): Minimum uppercase letters
            min_lowercase (int): Minimum lowercase letters
            min_digits (int): Minimum digits
            min_symbols (int): Minimum symbols
            
        Returns:
            str: Generated password
            
        Raises:
            GeneratorError: If generation parameters are invalid
        """
        try:
            # Validate parameters
            if length < 4:
                raise GeneratorError("Password length must be at least 4 characters")
                
            if not any([include_uppercase, include_lowercase, include_digits, include_symbols]):
                raise GeneratorError("At least one character type must be included")
                
            # Build character set
            charset = ""
            required_chars = []
            
            if include_lowercase:
                chars = self.LOWERCASE
                if exclude_ambiguous:
                    chars = ''.join(c for c in chars if c not in self.AMBIGUOUS_CHARS)
                charset += chars
                if min_lowercase > 0:
                    required_chars.extend(secrets.choice(chars) for _ in range(min_lowercase))
                    
            if include_uppercase:
                chars = self.UPPERCASE
                if exclude_ambiguous:
                    chars = ''.join(c for c in chars if c not in self.AMBIGUOUS_CHARS)
                charset += chars
                if min_uppercase > 0:
                    required_chars.extend(secrets.choice(chars) for _ in range(min_uppercase))
                    
            if include_digits:
                chars = self.DIGITS
                if exclude_ambiguous:
                    chars = ''.join(c for c in chars if c not in self.AMBIGUOUS_CHARS)
                charset += chars
                if min_digits > 0:
                    required_chars.extend(secrets.choice(chars) for _ in range(min_digits))
                    
            if include_symbols:
                chars = custom_symbols if custom_symbols else self.SYMBOLS
                if exclude_ambiguous:
                    chars = ''.join(c for c in chars if c not in self.AMBIGUOUS_CHARS)
                charset += chars
                if min_symbols > 0:
                    required_chars.extend(secrets.choice(chars) for _ in range(min_symbols))
                    
            if len(required_chars) > length:
                raise GeneratorError("Minimum character requirements exceed password length")
                
            # Generate password
            password_chars = required_chars[:]
            remaining_length = length - len(required_chars)
            
            # Fill remaining positions with random characters
            for _ in range(remaining_length):
                password_chars.append(secrets.choice(charset))
                
            # Shuffle the password to avoid predictable patterns
            for i in range(len(password_chars)):
                j = secrets.randbelow(len(password_chars))
                password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
                
            password = ''.join(password_chars)
            
            self.logger.info(f"Generated password of length {length}")
            return password
            
        except Exception as e:
            self.logger.error(f"Password generation failed: {str(e)}")
            raise GeneratorError(f"Failed to generate password: {str(e)}")
            
    def generate_passphrase(self,
                           word_count: int = 4,
                           separator: str = "-",
                           include_numbers: bool = True,
                           capitalize_words: bool = True,
                           custom_words: Optional[List[str]] = None) -> str:
        """
        Generate a secure passphrase using random words.
        
        Args:
            word_count (int): Number of words in passphrase
            separator (str): Word separator character
            include_numbers (bool): Include random numbers
            capitalize_words (bool): Capitalize first letter of each word
            custom_words (List[str], optional): Custom word list
            
        Returns:
            str: Generated passphrase
            
        Raises:
            GeneratorError: If generation parameters are invalid
        """
        try:
            if word_count < 2:
                raise GeneratorError("Passphrase must contain at least 2 words")
                
            # Use custom word list or default
            word_list = custom_words if custom_words else self.WORD_LIST
            
            if len(word_list) < word_count:
                raise GeneratorError("Not enough words in word list")
                
            # Select random words
            selected_words = []
            used_indices = set()
            
            for _ in range(word_count):
                while True:
                    index = secrets.randbelow(len(word_list))
                    if index not in used_indices:
                        used_indices.add(index)
                        word = word_list[index]
                        
                        if capitalize_words:
                            word = word.capitalize()
                            
                        selected_words.append(word)
                        break
                        
            # Add random numbers if requested
            if include_numbers:
                # Insert 1-2 random numbers
                num_count = secrets.randbelow(2) + 1
                for _ in range(num_count):
                    number = str(secrets.randbelow(100))
                    position = secrets.randbelow(len(selected_words) + 1)
                    selected_words.insert(position, number)
                    
            passphrase = separator.join(selected_words)
            
            self.logger.info(f"Generated passphrase with {word_count} words")
            return passphrase
            
        except Exception as e:
            self.logger.error(f"Passphrase generation failed: {str(e)}")
            raise GeneratorError(f"Failed to generate passphrase: {str(e)}")
            
    def generate_pin(self, length: int = 6) -> str:
        """
        Generate a secure numeric PIN.
        
        Args:
            length (int): PIN length
            
        Returns:
            str: Generated PIN
        """
        try:
            if length < 4:
                raise GeneratorError("PIN must be at least 4 digits")
                
            pin = ''.join(secrets.choice(self.DIGITS) for _ in range(length))
            
            self.logger.info(f"Generated PIN of length {length}")
            return pin
            
        except Exception as e:
            self.logger.error(f"PIN generation failed: {str(e)}")
            raise GeneratorError(f"Failed to generate PIN: {str(e)}")
            
    def assess_password_strength(self, password: str) -> Tuple[PasswordStrength, float, Dict[str, bool]]:
        """
        Assess password strength and provide detailed analysis.
        
        Args:
            password (str): Password to assess
            
        Returns:
            Tuple[PasswordStrength, float, Dict[str, bool]]: 
                (strength_level, entropy_bits, criteria_met)
        """
        try:
            if not password:
                return PasswordStrength.VERY_WEAK, 0.0, {}
                
            # Check various criteria
            criteria = {
                'length_8_plus': len(password) >= 8,
                'length_12_plus': len(password) >= 12,
                'has_lowercase': bool(re.search(r'[a-z]', password)),
                'has_uppercase': bool(re.search(r'[A-Z]', password)),
                'has_digits': bool(re.search(r'\d', password)),
                'has_symbols': bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password)),
                'no_common_patterns': not self._has_common_patterns(password),
                'no_repetition': not self._has_excessive_repetition(password),
                'no_sequential': not self._has_sequential_chars(password)
            }
            
            # Calculate entropy
            entropy = self._calculate_entropy(password)
            
            # Determine strength level
            score = sum(criteria.values())
            
            if entropy < 25 or score < 3:
                strength = PasswordStrength.VERY_WEAK
            elif entropy < 35 or score < 4:
                strength = PasswordStrength.WEAK
            elif entropy < 45 or score < 5:
                strength = PasswordStrength.FAIR
            elif entropy < 55 or score < 6:
                strength = PasswordStrength.GOOD
            elif entropy < 65 or score < 7:
                strength = PasswordStrength.STRONG
            else:
                strength = PasswordStrength.VERY_STRONG
                
            return strength, entropy, criteria
            
        except Exception as e:
            self.logger.error(f"Password strength assessment failed: {str(e)}")
            return PasswordStrength.VERY_WEAK, 0.0, {}
            
    def _calculate_entropy(self, password: str) -> float:
        """Calculate password entropy in bits."""
        if not password:
            return 0.0
            
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
        
    def _has_common_patterns(self, password: str) -> bool:
        """Check for common password patterns."""
        password_lower = password.lower()
        
        # Common patterns
        common_patterns = [
            'password', '123456', 'qwerty', 'abc123', 'admin',
            'letmein', 'welcome', 'monkey', 'dragon', 'master'
        ]
        
        for pattern in common_patterns:
            if pattern in password_lower:
                return True
                
        return False
        
    def _has_excessive_repetition(self, password: str) -> bool:
        """Check for excessive character repetition."""
        if len(password) < 3:
            return False
            
        # Check for 3+ consecutive identical characters
        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                return True
                
        return False
        
    def _has_sequential_chars(self, password: str) -> bool:
        """Check for sequential characters."""
        if len(password) < 3:
            return False
            
        # Check for sequential characters (ascending or descending)
        for i in range(len(password) - 2):
            char1, char2, char3 = password[i:i+3]
            
            # Check if characters are sequential
            if (ord(char2) == ord(char1) + 1 and ord(char3) == ord(char2) + 1) or \
               (ord(char2) == ord(char1) - 1 and ord(char3) == ord(char2) - 1):
                return True
                
        return False
        
    def get_generation_presets(self) -> Dict[str, Dict]:
        """
        Get predefined password generation presets.
        
        Returns:
            Dict[str, Dict]: Available presets with their configurations
        """
        return {
            'high_security': {
                'length': 20,
                'include_uppercase': True,
                'include_lowercase': True,
                'include_digits': True,
                'include_symbols': True,
                'exclude_ambiguous': True,
                'min_uppercase': 2,
                'min_lowercase': 2,
                'min_digits': 2,
                'min_symbols': 2
            },
            'medium_security': {
                'length': 16,
                'include_uppercase': True,
                'include_lowercase': True,
                'include_digits': True,
                'include_symbols': True,
                'exclude_ambiguous': True,
                'min_uppercase': 1,
                'min_lowercase': 1,
                'min_digits': 1,
                'min_symbols': 1
            },
            'basic_security': {
                'length': 12,
                'include_uppercase': True,
                'include_lowercase': True,
                'include_digits': True,
                'include_symbols': False,
                'exclude_ambiguous': True,
                'min_uppercase': 1,
                'min_lowercase': 1,
                'min_digits': 1,
                'min_symbols': 0
            },
            'alphanumeric_only': {
                'length': 16,
                'include_uppercase': True,
                'include_lowercase': True,
                'include_digits': True,
                'include_symbols': False,
                'exclude_ambiguous': True,
                'min_uppercase': 1,
                'min_lowercase': 1,
                'min_digits': 1,
                'min_symbols': 0
            },
            'memorable_passphrase': {
                'word_count': 4,
                'separator': '-',
                'include_numbers': True,
                'capitalize_words': True
            }
        }
        
    def validate_generation_params(self, **params) -> Tuple[bool, List[str]]:
        """
        Validate password generation parameters.
        
        Args:
            **params: Generation parameters to validate
            
        Returns:
            Tuple[bool, List[str]]: (is_valid, error_messages)
        """
        errors = []
        
        # Check length
        length = params.get('length', 16)
        if length < 4:
            errors.append("Password length must be at least 4 characters")
        elif length > 128:
            errors.append("Password length cannot exceed 128 characters")
            
        # Check character type inclusion
        char_types = [
            params.get('include_uppercase', True),
            params.get('include_lowercase', True),
            params.get('include_digits', True),
            params.get('include_symbols', True)
        ]
        
        if not any(char_types):
            errors.append("At least one character type must be included")
            
        # Check minimum requirements
        min_total = (
            params.get('min_uppercase', 0) +
            params.get('min_lowercase', 0) +
            params.get('min_digits', 0) +
            params.get('min_symbols', 0)
        )
        
        if min_total > length:
            errors.append("Minimum character requirements exceed password length")
            
        return len(errors) == 0, errors


# Global password generator instance
password_generator = PasswordGenerator()
