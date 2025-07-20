"""
Test script for SentinelPass Password Manager.

This script provides basic testing functionality to verify that the
password manager components work correctly before full deployment.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import logging
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test that all modules can be imported successfully."""
    print("Testing imports...")
    
    try:
        # Test core modules
        from config.settings import settings
        print("✓ Settings imported")
        
        from core.encryption import crypto_manager
        print("✓ Encryption imported")
        
        from core.database import DatabaseManager, PasswordEntry
        print("✓ Database imported")
        
        from core.password_generator import password_generator
        print("✓ Password generator imported")
        
        from core.backup_manager import backup_manager
        print("✓ Backup manager imported")
        
        # Test auth modules
        from auth.master_auth import auth_manager
        print("✓ Master auth imported")
        
        from auth.google_auth import google_auth_manager
        print("✓ Google auth imported")
        
        # Test utils modules
        from utils.validators import input_validator
        print("✓ Validators imported")
        
        from utils.clipboard import clipboard_manager
        print("✓ Clipboard imported")
        
        from utils.security import security_monitor
        print("✓ Security imported")
        
        print("✓ All core modules imported successfully")
        
        # Test UI modules (may fail if PyQt5 not installed)
        try:
            from ui.styles import theme_manager
            from ui.setup_wizard import SetupWizard
            from ui.login_dialog import LoginDialog
            from ui.main_window import MainWindow
            from ui.password_list import PasswordListWidget
            from ui.password_form import PasswordFormDialog
            from ui.generator_dialog import PasswordGeneratorTab
            from ui.backup_dialog import BackupDialog
            
            print("✓ All UI modules imported successfully")
            
        except ImportError as e:
            print(f"⚠ UI modules import failed (PyQt5 may not be installed): {e}")
            
        return True
        
    except ImportError as e:
        print(f"✗ Import failed: {e}")
        return False


def test_encryption():
    """Test encryption functionality."""
    print("\nTesting encryption...")
    
    try:
        from core.encryption import crypto_manager
        
        # Test password hashing
        password = "TestPassword123!"
        password_hash, salt = crypto_manager.hash_password(password)
        
        # Test password verification
        is_valid = crypto_manager.verify_password(password, password_hash, salt)
        assert is_valid, "Password verification failed"
        
        # Test data encryption/decryption
        test_data = "This is sensitive test data"
        encrypted_data = crypto_manager.encrypt_data(test_data, password)
        decrypted_data = crypto_manager.decrypt_data(encrypted_data, password)
        
        assert decrypted_data.decode('utf-8') == test_data, "Data encryption/decryption failed"
        
        print("✓ Encryption tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Encryption test failed: {e}")
        return False


def test_password_generator():
    """Test password generator functionality."""
    print("\nTesting password generator...")
    
    try:
        from core.password_generator import password_generator
        
        # Test password generation
        password = password_generator.generate_password(
            length=16,
            include_uppercase=True,
            include_lowercase=True,
            include_digits=True,
            include_symbols=True
        )
        
        assert len(password) == 16, f"Password length incorrect: {len(password)}"
        assert any(c.isupper() for c in password), "No uppercase letters"
        assert any(c.islower() for c in password), "No lowercase letters"
        assert any(c.isdigit() for c in password), "No digits"
        
        # Test passphrase generation
        passphrase = password_generator.generate_passphrase(
            word_count=4,
            separator="-",
            include_numbers=True,
            capitalize_words=True
        )
        
        assert "-" in passphrase, "Passphrase separator not found"
        
        # Test password strength assessment
        strength_level, entropy, criteria = password_generator.assess_password_strength(password)
        assert entropy > 0, "Password entropy calculation failed"
        
        print("✓ Password generator tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Password generator test failed: {e}")
        return False


def test_validation():
    """Test input validation functionality."""
    print("\nTesting validation...")
    
    try:
        from utils.validators import input_validator
        
        # Test password strength validation
        weak_password = "123"
        strong_password = "MyStr0ng!P@ssw0rd"
        
        is_valid_weak, errors_weak, _ = input_validator.validate_password_strength(weak_password)
        is_valid_strong, errors_strong, _ = input_validator.validate_password_strength(strong_password)
        
        assert not is_valid_weak, "Weak password should not be valid"
        assert is_valid_strong, "Strong password should be valid"
        
        # Test email validation
        valid_email = "test@example.com"
        invalid_email = "invalid-email"
        
        is_valid_email, _ = input_validator.validate_email(valid_email)
        is_invalid_email, _ = input_validator.validate_email(invalid_email)
        
        assert is_valid_email, "Valid email should pass validation"
        assert not is_invalid_email, "Invalid email should fail validation"
        
        # Test URL validation
        valid_url = "https://example.com"
        invalid_url = "not-a-url"
        
        is_valid_url, _ = input_validator.validate_url(valid_url)
        is_invalid_url, _ = input_validator.validate_url(invalid_url)
        
        assert is_valid_url, "Valid URL should pass validation"
        assert not is_invalid_url, "Invalid URL should fail validation"
        
        print("✓ Validation tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Validation test failed: {e}")
        return False


def test_database():
    """Test database functionality."""
    print("\nTesting database...")
    
    try:
        from core.database import DatabaseManager, PasswordEntry
        
        # Create test database
        test_db_path = "test_securepass.db"
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            
        # Initialize database manager
        db_manager = DatabaseManager()
        db_manager.db_path = test_db_path
        
        # Initialize database
        master_password = "TestMasterPassword123!"
        success = db_manager.initialize_database(master_password)
        assert success, "Database initialization failed"
        
        # Test adding password entry
        from datetime import datetime, timezone
        test_entry = PasswordEntry(
            title="Test Entry",
            username="testuser",
            password="testpassword123",
            url="https://test.com",
            notes="Test notes",
            category="Test"
        )
        
        entry_id = db_manager.add_password_entry(test_entry)
        assert entry_id is not None, "Failed to add password entry"
        
        # Test retrieving password entry
        retrieved_entry = db_manager.get_password_entry(entry_id)
        assert retrieved_entry is not None, "Failed to retrieve password entry"
        assert retrieved_entry.title == test_entry.title, "Retrieved entry title mismatch"
        assert retrieved_entry.username == test_entry.username, "Retrieved entry username mismatch"
        assert retrieved_entry.password == test_entry.password, "Retrieved entry password mismatch"
        
        # Test getting all entries
        all_entries = db_manager.get_all_password_entries()
        assert len(all_entries) == 1, f"Expected 1 entry, got {len(all_entries)}"
        
        # Test search
        search_results = db_manager.search_password_entries("Test")
        assert len(search_results) == 1, f"Expected 1 search result, got {len(search_results)}"
        
        # Test updating entry
        retrieved_entry.title = "Updated Test Entry"
        update_success = db_manager.update_password_entry(retrieved_entry)
        assert update_success, "Failed to update password entry"
        
        # Test deleting entry
        delete_success = db_manager.delete_password_entry(entry_id)
        assert delete_success, "Failed to delete password entry"
        
        # Cleanup
        db_manager.close()
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            
        print("✓ Database tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Database test failed: {e}")
        # Cleanup on error
        try:
            if 'db_manager' in locals():
                db_manager.close()
            if os.path.exists(test_db_path):
                os.remove(test_db_path)
        except:
            pass
        return False


def test_settings():
    """Test settings and configuration."""
    print("\nTesting settings...")
    
    try:
        from config.settings import settings
        
        # Test basic settings access
        assert settings.APP_NAME == "SentinelPass", "App name mismatch"
        assert settings.MIN_MASTER_PASSWORD_LENGTH >= 8, "Minimum password length too short"
        assert settings.ENCRYPTION_ALGORITHM == "AES-256-GCM", "Encryption algorithm mismatch"
        
        # Test password validation
        test_password = "TestPassword123!"
        is_valid, errors = settings.validate_master_password(test_password)
        assert is_valid, f"Password validation failed: {errors}"
        
        print("✓ Settings tests passed")
        return True
        
    except Exception as e:
        print(f"✗ Settings test failed: {e}")
        return False


def test_ui_basic():
    """Test basic UI functionality (if PyQt5 is available)."""
    print("\nTesting basic UI...")
    
    try:
        from PyQt5.QtWidgets import QApplication
        from ui.styles import theme_manager
        
        # Test theme manager
        available_themes = theme_manager.get_available_themes()
        assert "dark" in available_themes, "Dark theme not available"
        assert "light" in available_themes, "Light theme not available"
        
        # Test color retrieval
        primary_color = theme_manager.get_color('primary')
        assert primary_color.startswith('#'), "Color format invalid"
        
        print("✓ Basic UI tests passed")
        return True
        
    except ImportError:
        print("⚠ UI tests skipped (PyQt5 not available)")
        return True
    except Exception as e:
        print(f"✗ UI test failed: {e}")
        return False


def run_all_tests():
    """Run all tests and report results."""
    print("=" * 50)
    print("SentinelPass Password Manager - Test Suite")
    print("=" * 50)
    
    tests = [
        ("Import Tests", test_imports),
        ("Settings Tests", test_settings),
        ("Encryption Tests", test_encryption),
        ("Password Generator Tests", test_password_generator),
        ("Validation Tests", test_validation),
        ("Database Tests", test_database),
        ("Basic UI Tests", test_ui_basic),
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\n{test_name}:")
        print("-" * len(test_name))
        
        try:
            if test_func():
                passed += 1
        except Exception as e:
            print(f"✗ {test_name} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! SentinelPass is ready to use.")
        return True
    else:
        print(f"⚠ {total - passed} tests failed. Please check the issues above.")
        return False


def main():
    """Main test function."""
    # Setup logging
    logging.basicConfig(
        level=logging.WARNING,  # Reduce log noise during testing
        format='%(levelname)s: %(message)s'
    )
    
    # Run tests
    success = run_all_tests()
    
    if success:
        print("\n" + "=" * 50)
        print("🚀 SentinelPass is ready to launch!")
        print("Run 'python main.py' to start the application.")
        print("=" * 50)
        return 0
    else:
        print("\n" + "=" * 50)
        print("❌ Some tests failed. Please fix issues before using SentinelPass.")
        print("=" * 50)
        return 1


if __name__ == "__main__":
    sys.exit(main())
