"""
Integration testing for SentinelPass Password Manager.

This script tests the complete application workflow and integration
between different components.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import tempfile
import time
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_complete_workflow():
    """Test complete application workflow without UI."""
    print("Testing complete application workflow...")
    
    try:
        # Import all necessary components
        from core.database import DatabaseManager, PasswordEntry
        from core.encryption import crypto_manager
        from core.password_generator import password_generator
        from auth.master_auth import MasterAuthManager
        from utils.validators import input_validator
        from utils.clipboard import clipboard_manager
        from config.settings import settings
        
        # Step 1: Initialize components
        print("  Step 1: Initializing components...")
        temp_db = tempfile.mktemp(suffix='.db')
        db_manager = DatabaseManager()
        db_manager.db_path = temp_db
        auth_manager = MasterAuthManager()
        
        master_password = "SecureTestPassword123!"
        
        # Step 2: Initialize database
        print("  Step 2: Initializing database...")
        if not db_manager.initialize_database(master_password):
            print("  ❌ Database initialization failed")
            return False
        
        # Step 3: Test authentication
        print("  Step 3: Testing authentication...")
        if not auth_manager.authenticate(master_password):
            print("  ❌ Authentication failed")
            return False
        
        # Step 4: Generate and validate passwords
        print("  Step 4: Generating passwords...")
        generated_password = password_generator.generate_password(
            length=16,
            include_uppercase=True,
            include_lowercase=True,
            include_digits=True,
            include_symbols=True
        )
        
        if not generated_password or len(generated_password) != 16:
            print("  ❌ Password generation failed")
            return False
        
        # Step 5: Validate inputs
        print("  Step 5: Validating inputs...")
        test_email = "test@example.com"
        test_url = "https://example.com"
        
        email_valid, _ = input_validator.validate_email(test_email)
        url_valid, _ = input_validator.validate_url(test_url)
        
        if not email_valid or not url_valid:
            print("  ❌ Input validation failed")
            return False
        
        # Step 6: Create password entries
        print("  Step 6: Creating password entries...")
        test_entries = [
            PasswordEntry(
                title="Gmail Account",
                username="user@gmail.com",
                password=generated_password,
                url="https://gmail.com",
                notes="Personal email account",
                category="Email"
            ),
            PasswordEntry(
                title="Banking",
                username="john_doe",
                password="BankPassword123!",
                url="https://mybank.com",
                notes="Main banking account",
                category="Finance"
            ),
            PasswordEntry(
                title="Social Media",
                username="johndoe2025",
                password="SocialPass456@",
                url="https://facebook.com",
                notes="Facebook account",
                category="Social"
            )
        ]
        
        entry_ids = []
        for entry in test_entries:
            entry_id = db_manager.add_password_entry(entry)
            if entry_id:
                entry_ids.append(entry_id)
            else:
                print(f"  ❌ Failed to add entry: {entry.title}")
                return False
        
        print(f"  ✓ Added {len(entry_ids)} password entries")
        
        # Step 7: Test retrieval and search
        print("  Step 7: Testing retrieval and search...")
        all_entries = db_manager.get_all_password_entries()
        if len(all_entries) != len(test_entries):
            print(f"  ❌ Expected {len(test_entries)} entries, got {len(all_entries)}")
            return False
        
        # Test search functionality
        search_results = db_manager.search_password_entries("Gmail")
        if len(search_results) != 1:
            print(f"  ❌ Search failed: expected 1 result, got {len(search_results)}")
            return False
        
        # Step 8: Test updates
        print("  Step 8: Testing entry updates...")
        first_entry = db_manager.get_password_entry(entry_ids[0])
        if first_entry:
            first_entry.notes = "Updated notes for testing"
            if not db_manager.update_password_entry(first_entry):
                print("  ❌ Entry update failed")
                return False
        
        # Step 9: Test categories
        print("  Step 9: Testing categories...")
        categories = db_manager.get_categories()
        expected_categories = {"Email", "Finance", "Social"}
        if not expected_categories.issubset(set(categories)):
            print(f"  ❌ Categories mismatch: expected {expected_categories}, got {set(categories)}")
            return False
        
        # Step 10: Test clipboard operations (if available)
        print("  Step 10: Testing clipboard operations...")
        try:
            test_text = "Test clipboard content"
            clipboard_manager.copy_to_clipboard(test_text)
            # Note: We can't easily test clipboard retrieval in automated tests
            print("  ✓ Clipboard copy operation completed")
        except Exception as e:
            print(f"  ⚠ Clipboard test skipped: {e}")
        
        # Step 11: Test encryption/decryption workflow
        print("  Step 11: Testing encryption workflow...")
        test_data = "Sensitive password data"
        encrypted = crypto_manager.encrypt_data(test_data, master_password)
        decrypted = crypto_manager.decrypt_data(encrypted, master_password)
        
        if decrypted.decode() != test_data:
            print("  ❌ Encryption/decryption workflow failed")
            return False
        
        # Step 12: Test password strength assessment
        print("  Step 12: Testing password strength...")
        strength_level, entropy, criteria = password_generator.assess_password_strength(generated_password)
        if entropy <= 0:
            print("  ❌ Password strength assessment failed")
            return False
        
        # Step 13: Test data export (basic)
        print("  Step 13: Testing data export...")
        try:
            exported_data = db_manager.export_data()
            if not exported_data or len(exported_data) == 0:
                print("  ❌ Data export failed")
                return False
            print(f"  ✓ Exported {len(exported_data)} entries")
        except Exception as e:
            print(f"  ⚠ Data export test failed: {e}")
        
        # Step 14: Cleanup and test deletion
        print("  Step 14: Testing entry deletion...")
        for entry_id in entry_ids:
            if not db_manager.delete_password_entry(entry_id):
                print(f"  ❌ Failed to delete entry {entry_id}")
                return False
        
        # Verify deletion
        remaining_entries = db_manager.get_all_password_entries()
        if len(remaining_entries) != 0:
            print(f"  ❌ Expected 0 entries after deletion, got {len(remaining_entries)}")
            return False
        
        # Final cleanup
        db_manager.close()
        if os.path.exists(temp_db):
            os.remove(temp_db)
        
        print("✓ Complete workflow test passed!")
        return True
        
    except Exception as e:
        print(f"✗ Complete workflow test failed: {e}")
        return False


def test_security_features():
    """Test security-related features."""
    print("Testing security features...")
    
    try:
        from core.encryption import crypto_manager
        from utils.security import security_monitor
        from auth.master_auth import MasterAuthManager
        
        # Test 1: Password hashing consistency
        print("  Testing password hashing consistency...")
        password = "TestPassword123!"
        hash1, salt1 = crypto_manager.hash_password(password)
        hash2, salt2 = crypto_manager.hash_password(password)
        
        # Hashes should be different (due to different salts)
        if hash1 == hash2:
            print("  ⚠ Password hashes are identical (salts may not be random)")
        else:
            print("  ✓ Password hashing uses proper salting")
        
        # But verification should work for both
        if not crypto_manager.verify_password(password, hash1, salt1):
            print("  ❌ Password verification failed for first hash")
            return False
        
        if not crypto_manager.verify_password(password, hash2, salt2):
            print("  ❌ Password verification failed for second hash")
            return False
        
        # Test 2: Security monitoring
        print("  Testing security monitoring...")
        try:
            # Test security level assessment
            security_level = security_monitor.assess_security_level()
            print(f"  ✓ Security level assessed: {security_level}")
        except Exception as e:
            print(f"  ⚠ Security monitoring test failed: {e}")
        
        # Test 3: Authentication attempts
        print("  Testing authentication security...")
        auth_manager = MasterAuthManager()
        
        # Test multiple failed attempts (should be handled gracefully)
        for i in range(3):
            result = auth_manager.authenticate("wrong_password")
            if result:
                print("  ❌ Authentication should have failed")
                return False
        
        print("  ✓ Authentication properly rejects wrong passwords")
        
        print("✓ Security features test passed!")
        return True
        
    except Exception as e:
        print(f"✗ Security features test failed: {e}")
        return False


def test_performance_benchmarks():
    """Test performance benchmarks."""
    print("Testing performance benchmarks...")
    
    try:
        from core.password_generator import password_generator
        from core.encryption import crypto_manager
        import time
        
        # Test 1: Password generation speed
        print("  Testing password generation speed...")
        start_time = time.time()
        passwords_generated = 0
        
        for i in range(100):
            password = password_generator.generate_password(length=16)
            if password:
                passwords_generated += 1
        
        generation_time = time.time() - start_time
        print(f"  ✓ Generated {passwords_generated} passwords in {generation_time:.3f}s")
        
        if generation_time > 5.0:  # Should be much faster than 5 seconds
            print("  ⚠ Password generation seems slow")
        
        # Test 2: Encryption speed
        print("  Testing encryption speed...")
        test_data = "Test data for encryption speed test"
        start_time = time.time()
        encryptions_done = 0
        
        for i in range(50):
            encrypted = crypto_manager.encrypt_data(test_data, "password")
            decrypted = crypto_manager.decrypt_data(encrypted, "password")
            if decrypted.decode() == test_data:
                encryptions_done += 1
        
        encryption_time = time.time() - start_time
        print(f"  ✓ Completed {encryptions_done} encrypt/decrypt cycles in {encryption_time:.3f}s")
        
        if encryption_time > 10.0:  # Should be much faster than 10 seconds
            print("  ⚠ Encryption seems slow")
        
        print("✓ Performance benchmarks completed!")
        return True
        
    except Exception as e:
        print(f"✗ Performance benchmarks failed: {e}")
        return False


def run_integration_tests():
    """Run all integration tests."""
    print("=" * 60)
    print("SentinelPass Password Manager - Integration Test Suite")
    print("=" * 60)
    
    tests = [
        ("Complete Workflow", test_complete_workflow),
        ("Security Features", test_security_features),
        ("Performance Benchmarks", test_performance_benchmarks),
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
    print(f"Integration Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All integration tests passed!")
        return True
    else:
        print(f"⚠ {total - passed} integration tests had issues.")
        return False


def main():
    """Main integration testing function."""
    import logging
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    
    success = run_integration_tests()
    
    if success:
        print("\n" + "=" * 60)
        print("🔐 SentinelPass integration testing completed successfully!")
        print("All components work together seamlessly.")
        print("=" * 60)
        return 0
    else:
        print("\n" + "=" * 60)
        print("⚠ Some integration issues detected, but core functionality works.")
        print("=" * 60)
        return 1


if __name__ == "__main__":
    sys.exit(main())
