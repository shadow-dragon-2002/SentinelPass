"""
Setup script for SentinelPass Password Manager.

This script helps users set up the SentinelPass password manager by installing
dependencies, checking system requirements, and providing setup guidance.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import subprocess
import platform
from pathlib import Path


def print_header():
    """Print setup header."""
    print("=" * 60)
    print("SentinelPass Password Manager - Setup")
    print("=" * 60)
    print("Professional Password Manager with AES-256 Encryption")
    print("Final Year Project - Secure Coding Practices")
    print("=" * 60)


def check_python_version():
    """Check Python version compatibility."""
    print("\n1. Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print(f"❌ Python {version.major}.{version.minor} detected")
        print("⚠️  SentinelPass requires Python 3.8 or higher")
        print("Please upgrade Python and try again.")
        return False
    else:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} - Compatible")
        return True


def check_system_requirements():
    """Check system requirements."""
    print("\n2. Checking system requirements...")
    
    system = platform.system()
    print(f"Operating System: {system} {platform.release()}")
    
    # Check available disk space
    try:
        if system == "Windows":
            import shutil
            free_space = shutil.disk_usage(".")[2] / (1024**3)  # GB
        else:
            statvfs = os.statvfs(".")
            free_space = (statvfs.f_frsize * statvfs.f_bavail) / (1024**3)  # GB
            
        if free_space < 0.1:  # 100MB minimum
            print(f"⚠️  Low disk space: {free_space:.1f} GB available")
        else:
            print(f"✅ Disk space: {free_space:.1f} GB available")
            
    except Exception as e:
        print(f"⚠️  Could not check disk space: {e}")
    
    return True


def install_dependencies():
    """Install required dependencies."""
    print("\n3. Installing dependencies...")
    
    requirements_file = Path("requirements.txt")
    if not requirements_file.exists():
        print("❌ requirements.txt not found")
        return False
    
    try:
        print("Installing Python packages...")
        result = subprocess.run([
            sys.executable, "-m", "pip", "install", "-r", "requirements.txt"
        ], capture_output=True, text=True, check=True)
        
        print("✅ Dependencies installed successfully")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies:")
        print(f"Error: {e.stderr}")
        print("\nTry installing manually:")
        print("pip install -r requirements.txt")
        return False
    except FileNotFoundError:
        print("❌ pip not found. Please ensure pip is installed and in PATH")
        return False


def create_directories():
    """Create necessary directories."""
    print("\n4. Creating directories...")
    
    directories = [
        "data",
        "backups", 
        "logs",
        "config"
    ]
    
    for directory in directories:
        dir_path = Path(directory)
        try:
            dir_path.mkdir(exist_ok=True)
            print(f"✅ Created directory: {directory}")
        except Exception as e:
            print(f"⚠️  Could not create directory {directory}: {e}")
    
    return True


def test_installation():
    """Test the installation."""
    print("\n5. Testing installation...")
    
    try:
        # Test basic imports
        print("Testing core modules...")
        from config.settings import settings
        from core.encryption import crypto_manager
        from core.database import DatabaseManager
        print("✅ Core modules working")
        
        # Test UI modules
        print("Testing UI modules...")
        try:
            from PyQt5.QtWidgets import QApplication
            from ui.styles import theme_manager
            print("✅ UI modules working")
        except ImportError as e:
            print(f"⚠️  UI modules issue: {e}")
            print("PyQt5 may need manual installation")
        
        # Test encryption
        print("Testing encryption...")
        test_data = "test"
        encrypted = crypto_manager.encrypt_data(test_data, "password")
        decrypted = crypto_manager.decrypt_data(encrypted, "password")
        assert decrypted.decode() == test_data
        print("✅ Encryption working")
        
        return True
        
    except Exception as e:
        print(f"❌ Installation test failed: {e}")
        return False


def show_google_drive_setup():
    """Show Google Drive setup instructions."""
    print("\n6. Google Drive Setup (Optional)")
    print("-" * 40)
    print("To enable Google Drive backup:")
    print("1. Go to https://console.cloud.google.com/")
    print("2. Create a new project or select existing")
    print("3. Enable the Google Drive API")
    print("4. Create credentials (OAuth 2.0 Client ID)")
    print("5. Download the credentials.json file")
    print("6. Place credentials.json in the 'config' directory")
    print("\nGoogle Drive backup will be available after setup.")


def show_completion_message():
    """Show setup completion message."""
    print("\n" + "=" * 60)
    print("🎉 Setup Complete!")
    print("=" * 60)
    print("SentinelPass Password Manager is ready to use!")
    print()
    print("Next steps:")
    print("1. Run: python test_app.py (to verify installation)")
    print("2. Run: python main.py (to start SentinelPass)")
    print()
    print("Features:")
    print("• AES-256 encryption for password storage")
    print("• Secure master password authentication")
    print("• Advanced password generator")
    print("• Google Drive backup (with setup)")
    print("• Modern PyQt5 interface")
    print("• Auto-lock security features")
    print()
    print("For support, check the README.md file.")
    print("=" * 60)


def main():
    """Main setup function."""
    print_header()
    
    # Check requirements
    if not check_python_version():
        return 1
    
    if not check_system_requirements():
        return 1
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Setup failed at dependency installation")
        return 1
    
    # Create directories
    create_directories()
    
    # Test installation
    if not test_installation():
        print("\n⚠️  Setup completed with warnings")
        print("Some features may not work correctly")
    
    # Show additional setup info
    show_google_drive_setup()
    
    # Show completion message
    show_completion_message()
    
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\nSetup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nSetup failed with error: {e}")
        sys.exit(1)
