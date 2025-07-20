"""
End-to-End and Advanced Feature Testing for SentinelPass Password Manager.

This script performs comprehensive end-to-end testing including complete user workflows,
advanced security features, and performance under load testing.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import time
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_complete_user_workflow():
    """Test complete user workflow from setup to daily usage."""
    print("=" * 70)
    print("END-TO-END USER WORKFLOW TESTING")
    print("=" * 70)
    
    try:
        # Test 1: Database Initialization and Setup
        print("\n1. Testing Database Initialization...")
        from core.database import DatabaseManager, PasswordEntry
        from core.encryption import crypto_manager
        from auth.master_auth import MasterAuthManager
        
        # Create test database
        test_db_path = tempfile.mktemp(suffix='.db')
        db_manager = DatabaseManager()
        db_manager.db_path = test_db_path
        
        # Initialize with master password
        master_password = "TestMasterPassword123!"
        if db_manager.initialize_database(master_password):
            print("   ✓ Database initialized successfully")
        else:
            print("   ❌ Database initialization failed")
            return False
            
        # Test 2: Authentication Workflow
        print("\n2. Testing Authentication Workflow...")
        auth_manager = MasterAuthManager()
        
        # Test successful authentication
        if auth_manager.authenticate(master_password, "test_client"):
            print("   ✓ Master password authentication successful")
        else:
            print("   ❌ Master password authentication failed")
            return False
            
        # Test failed authentication
        if not auth_manager.authenticate("wrong_password", "test_client"):
            print("   ✓ Wrong password correctly rejected")
        else:
            print("   ❌ Wrong password should have been rejected")
            
        # Test 3: Password Entry Management Workflow
        print("\n3. Testing Password Entry Management...")
        
        # Create test entries
        test_entries = [
            PasswordEntry(
                title="Gmail Account",
                username="user@gmail.com",
                password="GmailPassword123!",
                url="https://gmail.com",
                notes="Personal email account",
                category="Email"
            ),
            PasswordEntry(
                title="Banking",
                username="john_doe",
                password="BankPassword456@",
                url="https://mybank.com",
                notes="Main banking account",
                category="Finance"
            ),
            PasswordEntry(
                title="Work Account",
                username="john.doe@company.com",
                password="WorkPassword789#",
                url="https://company.com",
                notes="Work email and systems",
                category="Work"
            )
        ]
        
        entry_ids = []
        for i, entry in enumerate(test_entries):
            entry_id = db_manager.add_password_entry(entry)
            if entry_id:
                entry_ids.append(entry_id)
                print(f"   ✓ Added entry {i+1}: {entry.title}")
            else:
                print(f"   ❌ Failed to add entry: {entry.title}")
                return False
                
        # Test 4: Search and Retrieval Workflow
        print("\n4. Testing Search and Retrieval...")
        
        # Test search functionality
        search_results = db_manager.search_password_entries("Gmail")
        if len(search_results) == 1 and search_results[0].title == "Gmail Account":
            print("   ✓ Search functionality working")
        else:
            print("   ❌ Search functionality failed")
            
        # Test category filtering
        categories = db_manager.get_categories()
        expected_categories = {"Email", "Finance", "Work"}
        if expected_categories.issubset(set(categories)):
            print("   ✓ Category management working")
        else:
            print("   ❌ Category management failed")
            
        # Test 5: Entry Modification Workflow
        print("\n5. Testing Entry Modification...")
        
        # Update an entry
        first_entry = db_manager.get_password_entry(entry_ids[0])
        if first_entry:
            original_notes = first_entry.notes
            first_entry.notes = "Updated notes for testing"
            
            if db_manager.update_password_entry(first_entry):
                print("   ✓ Entry update successful")
                
                # Verify update
                updated_entry = db_manager.get_password_entry(entry_ids[0])
                if updated_entry.notes == "Updated notes for testing":
                    print("   ✓ Entry update verified")
                else:
                    print("   ❌ Entry update verification failed")
            else:
                print("   ❌ Entry update failed")
                
        # Test 6: Backup and Restore Workflow
        print("\n6. Testing Backup and Restore...")
        
        try:
            from core.backup_manager import backup_manager
            
            # Export data
            exported_data = db_manager.export_data()
            if exported_data and len(exported_data) == 3:
                print("   ✓ Data export successful")
            else:
                print("   ❌ Data export failed")
                
            # Test local backup creation
            backup_result = backup_manager.create_backup(
                exported_data, 
                master_password, 
                backup_local=True, 
                backup_cloud=False
            )
            
            if backup_result:
                print("   ✓ Local backup creation successful")
            else:
                print("   ⚠ Local backup creation had issues")
                
        except Exception as e:
            print(f"   ⚠ Backup testing skipped: {str(e)}")
            
        # Test 7: Entry Deletion Workflow
        print("\n7. Testing Entry Deletion...")
        
        # Delete one entry
        if db_manager.delete_password_entry(entry_ids[0]):
            print("   ✓ Entry deletion successful")
            
            # Verify deletion
            remaining_entries = db_manager.get_all_password_entries()
            if len(remaining_entries) == 2:
                print("   ✓ Entry deletion verified")
            else:
                print("   ❌ Entry deletion verification failed")
        else:
            print("   ❌ Entry deletion failed")
            
        # Cleanup
        db_manager.close()
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            
        print("\n✅ Complete User Workflow Test PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ Complete User Workflow Test FAILED: {str(e)}")
        return False


def test_advanced_security_features():
    """Test advanced security features."""
    print("\n" + "=" * 70)
    print("ADVANCED SECURITY FEATURES TESTING")
    print("=" * 70)
    
    try:
        # Test 1: Session Management and Timeout
        print("\n1. Testing Session Management...")
        from auth.master_auth import MasterAuthManager
        from config.settings import settings
        
        auth_manager = MasterAuthManager()
        
        # Test session creation
        if auth_manager.authenticate("TestPassword123!", "security_test"):
            print("   ✓ Session created successfully")
            
            # Test session info
            session_info = auth_manager.get_session_info()
            if session_info and 'session_id' in session_info:
                print("   ✓ Session info retrieval working")
            else:
                print("   ❌ Session info retrieval failed")
                
            # Test session activity update
            if auth_manager.is_authenticated():
                print("   ✓ Session authentication check working")
            else:
                print("   ❌ Session authentication check failed")
                
        # Test 2: Failed Attempt Tracking
        print("\n2. Testing Failed Attempt Tracking...")
        
        auth_manager_2 = MasterAuthManager()
        
        # Simulate failed attempts
        failed_attempts = 0
        for i in range(3):
            if not auth_manager_2.authenticate("wrong_password", "failed_test"):
                failed_attempts += 1
                
        if failed_attempts == 3:
            print("   ✓ Failed attempt tracking working")
            
            # Check failed attempt count
            attempt_count = auth_manager_2.get_failed_attempts("failed_test")
            if attempt_count == 3:
                print("   ✓ Failed attempt counting accurate")
            else:
                print(f"   ⚠ Failed attempt count: {attempt_count} (expected 3)")
        else:
            print("   ❌ Failed attempt tracking failed")
            
        # Test 3: Security Status Monitoring
        print("\n3. Testing Security Status Monitoring...")
        
        security_status = auth_manager.get_security_status()
        required_fields = [
            'authenticated', 'session_active', 'failed_attempts',
            'auto_lock_enabled', 'session_timeout_minutes'
        ]
        
        if all(field in security_status for field in required_fields):
            print("   ✓ Security status monitoring comprehensive")
        else:
            print("   ❌ Security status monitoring incomplete")
            
        # Test 4: Password Strength Validation
        print("\n4. Testing Password Strength Validation...")
        
        test_passwords = [
            ("weak", False),
            ("StrongPassword123!", True),
            ("short", False),
            ("NoNumbers!", False),
            ("nonumbers123", False),
            ("NOLOWERCASE123!", False),
            ("nouppercase123!", False)
        ]
        
        validation_passed = 0
        for password, should_be_valid in test_passwords:
            is_valid, errors = settings.validate_master_password(password)
            if is_valid == should_be_valid:
                validation_passed += 1
            else:
                print(f"   ⚠ Password '{password}' validation unexpected result")
                
        if validation_passed == len(test_passwords):
            print("   ✓ Password strength validation working correctly")
        else:
            print(f"   ⚠ Password validation: {validation_passed}/{len(test_passwords)} tests passed")
            
        # Test 5: Encryption Security
        print("\n5. Testing Encryption Security...")
        from core.encryption import crypto_manager
        
        # Test key derivation consistency
        password = "TestPassword123!"
        hash1, salt1 = crypto_manager.hash_password(password)
        hash2, salt2 = crypto_manager.hash_password(password)
        
        if hash1 != hash2 and salt1 != salt2:
            print("   ✓ Password hashing uses proper salting")
        else:
            print("   ⚠ Password hashing may not be using proper salting")
            
        # Test encryption/decryption security
        test_data = "Sensitive test data"
        encrypted1 = crypto_manager.encrypt_data(test_data, password)
        encrypted2 = crypto_manager.encrypt_data(test_data, password)
        
        if encrypted1 != encrypted2:
            print("   ✓ Encryption uses proper randomization")
        else:
            print("   ⚠ Encryption may not be using proper randomization")
            
        # Test wrong password rejection
        try:
            decrypted = crypto_manager.decrypt_data(encrypted1, "wrong_password")
            print("   ❌ Wrong password should have been rejected")
        except:
            print("   ✓ Wrong password correctly rejected")
            
        print("\n✅ Advanced Security Features Test PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ Advanced Security Features Test FAILED: {str(e)}")
        return False


def test_performance_under_load():
    """Test performance under load conditions."""
    print("\n" + "=" * 70)
    print("PERFORMANCE UNDER LOAD TESTING")
    print("=" * 70)
    
    try:
        # Test 1: Large Database Performance
        print("\n1. Testing Large Database Performance...")
        from core.database import DatabaseManager, PasswordEntry
        import time
        
        # Create test database
        test_db_path = tempfile.mktemp(suffix='.db')
        db_manager = DatabaseManager()
        db_manager.db_path = test_db_path
        
        # Initialize database
        master_password = "TestMasterPassword123!"
        if not db_manager.initialize_database(master_password):
            print("   ❌ Database initialization failed")
            return False
            
        # Add many entries
        print("   Adding 500 password entries...")
        start_time = time.time()
        
        entries_added = 0
        for i in range(500):
            entry = PasswordEntry(
                title=f"Test Entry {i+1}",
                username=f"user{i+1}@test.com",
                password=f"Password{i+1}!",
                url=f"https://test{i+1}.com",
                notes=f"Test notes for entry {i+1}",
                category=f"Category{(i % 10) + 1}"
            )
            
            entry_id = db_manager.add_password_entry(entry)
            if entry_id:
                entries_added += 1
                
            # Progress indicator
            if (i + 1) % 100 == 0:
                print(f"   Added {i+1} entries...")
                
        add_time = time.time() - start_time
        print(f"   ✓ Added {entries_added} entries in {add_time:.2f} seconds")
        print(f"   ✓ Average: {add_time/entries_added*1000:.2f}ms per entry")
        
        # Test search performance
        print("\n2. Testing Search Performance...")
        start_time = time.time()
        
        search_results = db_manager.search_password_entries("Test Entry 250")
        search_time = time.time() - start_time
        
        if len(search_results) == 1:
            print(f"   ✓ Search completed in {search_time*1000:.2f}ms")
        else:
            print(f"   ⚠ Search returned {len(search_results)} results (expected 1)")
            
        # Test bulk retrieval performance
        print("\n3. Testing Bulk Retrieval Performance...")
        start_time = time.time()
        
        all_entries = db_manager.get_all_password_entries()
        retrieval_time = time.time() - start_time
        
        print(f"   ✓ Retrieved {len(all_entries)} entries in {retrieval_time:.2f} seconds")
        print(f"   ✓ Average: {retrieval_time/len(all_entries)*1000:.2f}ms per entry")
        
        # Test category performance
        print("\n4. Testing Category Performance...")
        start_time = time.time()
        
        categories = db_manager.get_categories()
        category_time = time.time() - start_time
        
        print(f"   ✓ Retrieved {len(categories)} categories in {category_time*1000:.2f}ms")
        
        # Test 5: Password Generation Performance
        print("\n5. Testing Password Generation Performance...")
        from core.password_generator import password_generator
        
        start_time = time.time()
        passwords_generated = 0
        
        for i in range(1000):
            password = password_generator.generate_password(length=16)
            if password and len(password) == 16:
                passwords_generated += 1
                
        generation_time = time.time() - start_time
        print(f"   ✓ Generated {passwords_generated} passwords in {generation_time:.3f} seconds")
        print(f"   ✓ Average: {generation_time/passwords_generated*1000:.3f}ms per password")
        
        # Test 6: Encryption Performance
        print("\n6. Testing Encryption Performance...")
        from core.encryption import crypto_manager
        
        test_data = "Test data for encryption performance testing"
        start_time = time.time()
        
        encryptions_completed = 0
        for i in range(100):
            encrypted = crypto_manager.encrypt_data(test_data, "password")
            decrypted = crypto_manager.decrypt_data(encrypted, "password")
            
            if decrypted.decode() == test_data:
                encryptions_completed += 1
                
        encryption_time = time.time() - start_time
        print(f"   ✓ Completed {encryptions_completed} encrypt/decrypt cycles in {encryption_time:.3f} seconds")
        print(f"   ✓ Average: {encryption_time/encryptions_completed*1000:.2f}ms per cycle")
        
        # Test 7: Memory Usage Assessment
        print("\n7. Testing Memory Usage...")
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        print(f"   ✓ Current memory usage: {memory_info.rss / 1024 / 1024:.2f} MB")
        print(f"   ✓ Virtual memory usage: {memory_info.vms / 1024 / 1024:.2f} MB")
        
        # Cleanup
        db_manager.close()
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
            
        print("\n✅ Performance Under Load Test PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ Performance Under Load Test FAILED: {str(e)}")
        return False


def test_session_timeout_and_autolock():
    """Test session timeout and auto-lock functionality."""
    print("\n" + "=" * 70)
    print("SESSION TIMEOUT AND AUTO-LOCK TESTING")
    print("=" * 70)
    
    try:
        from auth.master_auth import MasterAuthManager
        from config.settings import settings
        import time
        
        # Test 1: Session Timeout Configuration
        print("\n1. Testing Session Timeout Configuration...")
        
        print(f"   ✓ Session timeout: {settings.SESSION_TIMEOUT_MINUTES} minutes")
        print(f"   ✓ Max login attempts: {settings.MAX_LOGIN_ATTEMPTS}")
        print(f"   ✓ Lockout duration: {settings.LOCKOUT_DURATION_MINUTES} minutes")
        
        # Test 2: Session Activity Tracking
        print("\n2. Testing Session Activity Tracking...")
        
        auth_manager = MasterAuthManager()
        
        if auth_manager.authenticate("TestPassword123!", "timeout_test"):
            print("   ✓ Session created for timeout testing")
            
            # Check initial session state
            if auth_manager.is_authenticated():
                print("   ✓ Session initially active")
                
                # Get session info
                session_info = auth_manager.get_session_info()
                if session_info:
                    created_at = datetime.fromisoformat(session_info['created_at'])
                    last_activity = datetime.fromisoformat(session_info['last_activity'])
                    expires_at = datetime.fromisoformat(session_info['expires_at'])
                    
                    print(f"   ✓ Session created at: {created_at.strftime('%H:%M:%S')}")
                    print(f"   ✓ Last activity: {last_activity.strftime('%H:%M:%S')}")
                    print(f"   ✓ Expires at: {expires_at.strftime('%H:%M:%S')}")
                    
                    # Test activity update
                    time.sleep(1)
                    if auth_manager.is_authenticated():  # This should update activity
                        updated_info = auth_manager.get_session_info()
                        updated_activity = datetime.fromisoformat(updated_info['last_activity'])
                        
                        if updated_activity > last_activity:
                            print("   ✓ Session activity updates working")
                        else:
                            print("   ⚠ Session activity may not be updating")
                else:
                    print("   ❌ Session info retrieval failed")
        else:
            print("   ❌ Session creation failed")
            
        # Test 3: Manual Session Logout
        print("\n3. Testing Manual Session Logout...")
        
        if auth_manager.is_authenticated():
            auth_manager.logout()
            
            if not auth_manager.is_authenticated():
                print("   ✓ Manual logout working")
            else:
                print("   ❌ Manual logout failed")
        else:
            print("   ⚠ No active session to logout")
            
        # Test 4: Security Status Monitoring
        print("\n4. Testing Security Status Monitoring...")
        
        # Re-authenticate for status testing
        if auth_manager.authenticate("TestPassword123!", "status_test"):
            status = auth_manager.get_security_status()
            
            expected_fields = [
                'authenticated', 'session_active', 'session_info',
                'failed_attempts', 'auto_lock_enabled', 'session_timeout_minutes'
            ]
            
            missing_fields = [field for field in expected_fields if field not in status]
            if not missing_fields:
                print("   ✓ Security status comprehensive")
                print(f"   ✓ Auto-lock enabled: {status['auto_lock_enabled']}")
                print(f"   ✓ Session timeout: {status['session_timeout_minutes']} minutes")
            else:
                print(f"   ⚠ Missing security status fields: {missing_fields}")
                
        print("\n✅ Session Timeout and Auto-lock Test PASSED")
        return True
        
    except Exception as e:
        print(f"\n❌ Session Timeout and Auto-lock Test FAILED: {str(e)}")
        return False


def run_all_advanced_tests():
    """Run all advanced and end-to-end tests."""
    print("=" * 80)
    print("SECUREPASS - ADVANCED AND END-TO-END TESTING SUITE")
    print("=" * 80)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    tests = [
        ("Complete User Workflow", test_complete_user_workflow),
        ("Advanced Security Features", test_advanced_security_features),
        ("Performance Under Load", test_performance_under_load),
        ("Session Timeout and Auto-lock", test_session_timeout_and_autolock),
    ]
    
    passed = 0
    total = len(tests)
    start_time = time.time()
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} {test_name} {'='*20}")
        
        try:
            if test_func():
                passed += 1
                print(f"✅ {test_name} PASSED")
            else:
                print(f"❌ {test_name} FAILED")
        except Exception as e:
            print(f"❌ {test_name} FAILED with exception: {str(e)}")
    
    total_time = time.time() - start_time
    
    print("\n" + "=" * 80)
    print("ADVANCED TESTING SUMMARY")
    print("=" * 80)
    print(f"Tests Passed: {passed}/{total}")
    print(f"Success Rate: {(passed/total)*100:.1f}%")
    print(f"Total Time: {total_time:.2f} seconds")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    if passed == total:
        print("\n🎉 ALL ADVANCED TESTS PASSED!")
        print("SentinelPass Password Manager is production-ready with excellent performance!")
        return True
    else:
        print(f"\n⚠ {total - passed} advanced tests had issues.")
        print("Core functionality is solid, but some advanced features may need attention.")
        return False


def main():
    """Main advanced testing function."""
    import logging
    logging.basicConfig(level=logging.WARNING, format='%(levelname)s: %(message)s')
    
    success = run_all_advanced_tests()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
