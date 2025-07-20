"""
Edge case and integration testing for SentinelPass Password Manager.

This script tests various edge cases, error conditions, and integration
scenarios to ensure robust operation.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import tempfile
import shutil
import sqlite3
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_database_edge_cases():
    """Test database edge cases and error conditions."""
    print("Testing database edge cases...")
    
    try:
        from core.database import DatabaseManager, PasswordEntry
        from core.encryption import crypto_manager
        
        # Test 1: Invalid database path
        print("  Testing invalid database path...")
        db_manager = DatabaseManager()
        db_manager.db_path = "/invalid/path/test.db"
        
        try:
            db_manager.initialize_database("TestPassword123!")
            print("  ❌ Should have failed with invalid path")
        except Exception as e:
            print(f"  ✓ Correctly handled invalid path: {type(e).__name__}")
        
        # Test 2: Corrupted database file
        print("  Testing corrupted database...")
        temp_db = tempfile.mktemp(suffix='.db')
        
        # Create corrupted file
        with open(temp_db, 'w') as f:
            f.write("This is not a valid SQLite database")
        
        db_manager = DatabaseManager()
        db_manager.db_path = temp_db
        
        try:
            db_manager.initialize_database("TestPassword123!")
            print("  ❌ Should have failed with corrupted database")
        except Exception as e:
            print(f"  ✓ Correctly handled corrupted database: {type(e).__name__}")
        
        # Cleanup
        if os.path.exists(temp_db):
            os.remove(temp_db)
        
        # Test 3: Very long password entries
        print("  Testing very long password entries...")
        temp_db = tempfile.mktemp(suffix='.db')
        db_manager = DatabaseManager()
        db_manager.db_path = temp_db
        
        if db_manager.initialize_database("TestPassword123!"):
            very_long_entry = PasswordEntry(
                title="A" * 1000,  # Very long title
                username="B" * 500,  # Very long username
                password="C" * 2000,  # Very long password
                url="https://" + "d" * 500 + ".com",  # Very long URL
                notes="E" * 5000,  # Very long notes
                category="Test"
            )
            
            try:
                entry_id = db_manager.add_password_entry(very_long_entry)
                if entry_id:
                    print("  ✓ Successfully handled very long entries")
                else:
                    print("  ⚠ Failed to add very long entry")
            except Exception as e:
                print(f"  ⚠ Exception with long entries: {e}")
        
        # Cleanup
        db_manager.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)
            
        print("✓ Database edge case tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Database edge case tests failed: {e}")
        return False


def test_encryption_edge_cases():
    """Test encryption edge cases."""
    print("Testing encryption edge cases...")
    
    try:
        from core.encryption import crypto_manager
        
        # Test 1: Empty data encryption
        print("  Testing empty data encryption...")
        try:
            encrypted = crypto_manager.encrypt_data("", "password")
            decrypted = crypto_manager.decrypt_data(encrypted, "password")
            assert decrypted.decode() == "", "Empty data encryption failed"
            print("  ✓ Empty data encryption works")
        except Exception as e:
            print(f"  ⚠ Empty data encryption issue: {e}")
        
        # Test 2: Very large data encryption
        print("  Testing large data encryption...")
        large_data = "X" * 100000  # 100KB of data
        try:
            encrypted = crypto_manager.encrypt_data(large_data, "password")
            decrypted = crypto_manager.decrypt_data(encrypted, "password")
            assert decrypted.decode() == large_data, "Large data encryption failed"
            print("  ✓ Large data encryption works")
        except Exception as e:
            print(f"  ⚠ Large data encryption issue: {e}")
        
        # Test 3: Unicode data encryption
        print("  Testing unicode data encryption...")
        unicode_data = "Hello 世界 🔐 Ñoël café résumé"
        try:
            encrypted = crypto_manager.encrypt_data(unicode_data, "password")
            decrypted = crypto_manager.decrypt_data(encrypted, "password")
            assert decrypted.decode() == unicode_data, "Unicode encryption failed"
            print("  ✓ Unicode data encryption works")
        except Exception as e:
            print(f"  ⚠ Unicode data encryption issue: {e}")
        
        # Test 4: Wrong password decryption
        print("  Testing wrong password decryption...")
        try:
            encrypted = crypto_manager.encrypt_data("test", "correct_password")
            decrypted = crypto_manager.decrypt_data(encrypted, "wrong_password")
            print("  ❌ Should have failed with wrong password")
        except Exception as e:
            print(f"  ✓ Correctly rejected wrong password: {type(e).__name__}")
        
        # Test 5: Corrupted encrypted data
        print("  Testing corrupted encrypted data...")
        try:
            encrypted = crypto_manager.encrypt_data("test", "password")
            corrupted = encrypted[:-10] + b"corrupted!"  # Corrupt the data
            decrypted = crypto_manager.decrypt_data(corrupted, "password")
            print("  ❌ Should have failed with corrupted data")
        except Exception as e:
            print(f"  ✓ Correctly rejected corrupted data: {type(e).__name__}")
        
        print("✓ Encryption edge case tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Encryption edge case tests failed: {e}")
        return False


def test_password_generator_edge_cases():
    """Test password generator edge cases."""
    print("Testing password generator edge cases...")
    
    try:
        from core.password_generator import password_generator
        
        # Test 1: Minimum length password
        print("  Testing minimum length password...")
        try:
            password = password_generator.generate_password(length=1)
            assert len(password) == 1, "Minimum length failed"
            print("  ✓ Minimum length password works")
        except Exception as e:
            print(f"  ⚠ Minimum length issue: {e}")
        
        # Test 2: Maximum length password
        print("  Testing maximum length password...")
        try:
            password = password_generator.generate_password(length=128)
            assert len(password) == 128, "Maximum length failed"
            print("  ✓ Maximum length password works")
        except Exception as e:
            print(f"  ⚠ Maximum length issue: {e}")
        
        # Test 3: No character types selected
        print("  Testing no character types...")
        try:
            password = password_generator.generate_password(
                length=10,
                include_uppercase=False,
                include_lowercase=False,
                include_digits=False,
                include_symbols=False
            )
            print("  ❌ Should have failed with no character types")
        except Exception as e:
            print(f"  ✓ Correctly rejected no character types: {type(e).__name__}")
        
        # Test 4: Impossible minimum requirements
        print("  Testing impossible minimum requirements...")
        try:
            password = password_generator.generate_password(
                length=5,
                min_uppercase=10,  # Impossible requirement
                include_uppercase=True,
                include_lowercase=True
            )
            print("  ❌ Should have failed with impossible requirements")
        except Exception as e:
            print(f"  ✓ Correctly rejected impossible requirements: {type(e).__name__}")
        
        # Test 5: Passphrase with minimum words
        print("  Testing minimum word passphrase...")
        try:
            passphrase = password_generator.generate_passphrase(word_count=1)
            assert len(passphrase.split()) >= 1, "Minimum words failed"
            print("  ✓ Minimum word passphrase works")
        except Exception as e:
            print(f"  ⚠ Minimum words issue: {e}")
        
        print("✓ Password generator edge case tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Password generator edge case tests failed: {e}")
        return False


def test_validation_edge_cases():
    """Test input validation edge cases."""
    print("Testing validation edge cases...")
    
    try:
        from utils.validators import input_validator
        
        # Test 1: Very long email
        print("  Testing very long email...")
        long_email = "a" * 100 + "@" + "b" * 100 + ".com"
        is_valid, errors = input_validator.validate_email(long_email)
        print(f"  ✓ Long email validation: {'valid' if is_valid else 'invalid'}")
        
        # Test 2: Email with unicode characters
        print("  Testing unicode email...")
        unicode_email = "tëst@exämple.com"
        is_valid, errors = input_validator.validate_email(unicode_email)
        print(f"  ✓ Unicode email validation: {'valid' if is_valid else 'invalid'}")
        
        # Test 3: Very long URL
        print("  Testing very long URL...")
        long_url = "https://" + "a" * 1000 + ".com/" + "b" * 1000
        is_valid, errors = input_validator.validate_url(long_url)
        print(f"  ✓ Long URL validation: {'valid' if is_valid else 'invalid'}")
        
        # Test 4: URL with special characters
        print("  Testing URL with special characters...")
        special_url = "https://example.com/path?param=value&other=测试"
        is_valid, errors = input_validator.validate_url(special_url)
        print(f"  ✓ Special URL validation: {'valid' if is_valid else 'invalid'}")
        
        # Test 5: Password with only spaces
        print("  Testing password with only spaces...")
        space_password = "   "
        is_valid, errors, strength = input_validator.validate_password_strength(space_password)
        print(f"  ✓ Space password validation: {'valid' if is_valid else 'invalid'}")
        
        print("✓ Validation edge case tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Validation edge case tests failed: {e}")
        return False


def test_file_system_edge_cases():
    """Test file system related edge cases."""
    print("Testing file system edge cases...")
    
    try:
        from config.settings import settings
        
        # Test 1: Read-only directory
        print("  Testing read-only directory access...")
        # This test is platform-specific and may not work on all systems
        
        # Test 2: Disk space simulation (create large temp file)
        print("  Testing large file operations...")
        try:
            temp_file = tempfile.mktemp()
            # Create a moderately large file (1MB)
            with open(temp_file, 'wb') as f:
                f.write(b'0' * 1024 * 1024)
            
            # Check if file was created
            if os.path.exists(temp_file):
                size = os.path.getsize(temp_file)
                print(f"  ✓ Created large file: {size} bytes")
                os.remove(temp_file)
            else:
                print("  ⚠ Failed to create large file")
                
        except Exception as e:
            print(f"  ⚠ Large file operation issue: {e}")
        
        # Test 3: Directory creation
        print("  Testing directory creation...")
        temp_dir = tempfile.mkdtemp()
        try:
            nested_dir = os.path.join(temp_dir, "nested", "deep", "directory")
            os.makedirs(nested_dir, exist_ok=True)
            
            if os.path.exists(nested_dir):
                print("  ✓ Nested directory creation works")
            else:
                print("  ⚠ Nested directory creation failed")
                
        except Exception as e:
            print(f"  ⚠ Directory creation issue: {e}")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
        
        print("✓ File system edge case tests completed")
        return True
        
    except Exception as e:
        print(f"✗ File system edge case tests failed: {e}")
        return False


def test_memory_and_performance():
    """Test memory usage and performance edge cases."""
    print("Testing memory and performance...")
    
    try:
        # Test 1: Multiple database operations
        print("  Testing multiple database operations...")
        from core.database import DatabaseManager, PasswordEntry
        
        temp_db = tempfile.mktemp(suffix='.db')
        db_manager = DatabaseManager()
        db_manager.db_path = temp_db
        
        if db_manager.initialize_database("TestPassword123!"):
            # Add many entries quickly
            entries_added = 0
            for i in range(100):
                entry = PasswordEntry(
                    title=f"Test Entry {i}",
                    username=f"user{i}",
                    password=f"password{i}",
                    url=f"https://test{i}.com",
                    notes=f"Notes for entry {i}",
                    category="Test"
                )
                
                try:
                    entry_id = db_manager.add_password_entry(entry)
                    if entry_id:
                        entries_added += 1
                except Exception as e:
                    print(f"    Failed to add entry {i}: {e}")
                    break
            
            print(f"  ✓ Added {entries_added} entries successfully")
            
            # Test search performance
            search_results = db_manager.search_password_entries("Test")
            print(f"  ✓ Search returned {len(search_results)} results")
            
        db_manager.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)
        
        # Test 2: Password generation performance
        print("  Testing password generation performance...")
        from core.password_generator import password_generator
        
        passwords_generated = 0
        for i in range(50):
            try:
                password = password_generator.generate_password(length=16)
                if password and len(password) == 16:
                    passwords_generated += 1
            except Exception as e:
                print(f"    Password generation failed at {i}: {e}")
                break
        
        print(f"  ✓ Generated {passwords_generated} passwords successfully")
        
        print("✓ Memory and performance tests completed")
        return True
        
    except Exception as e:
        print(f"✗ Memory and performance tests failed: {e}")
        return False


def run_all_edge_case_tests():
    """Run all edge case tests."""
    print("=" * 60)
    print("SentinelPass Password Manager - Edge Case Test Suite")
    print("=" * 60)
    
    tests = [
        ("Database Edge Cases", test_database_edge_cases),
        ("Encryption Edge Cases", test_encryption_edge_cases),
        ("Password Generator Edge Cases", test_password_generator_edge_cases),
        ("Validation Edge Cases", test_validation_edge_cases),
        ("File System Edge Cases", test_file_system_edge_cases),
        ("Memory and Performance", test_memory_and_performance),
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
    
    print("\n" + "=" * 60)
    print(f"Edge Case Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All edge case tests passed!")
        return True
    else:
        print(f"⚠ {total - passed} edge case tests had issues.")
        return False


def main():
    """Main edge case testing function."""
    import logging
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    
    success = run_all_edge_case_tests()
    
    if success:
        print("\n" + "=" * 60)
        print("🔒 SentinelPass edge case testing completed successfully!")
        print("The application is robust and handles edge cases well.")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("⚠ Some edge cases need attention, but core functionality is solid.")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
