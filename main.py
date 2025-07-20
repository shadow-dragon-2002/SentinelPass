#!/usr/bin/env python3
"""
SentinelPass - Professional Password Manager
Main application entry point

This module serves as the entry point for the SentinelPass password manager application.
It initializes the PyQt5 application, handles first-time setup, and manages the main
application lifecycle.

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config.settings import AppSettings
from core.database import DatabaseManager
from auth.master_auth import MasterAuthManager
from ui.setup_wizard import SetupWizard
from ui.login_dialog import LoginDialog
from ui.main_window import MainWindow


class SentinelPassApplication:
    """
    Main application class that manages the lifecycle of SentinelPass.
    
    This class handles:
    - Application initialization
    - First-time setup detection
    - Master password authentication
    - Main window management
    - Graceful shutdown
    """
    
    def __init__(self):
        """Initialize the SentinelPass application."""
        self.app = None
        self.main_window = None
        self.db_manager = None
        self.auth_manager = None
        self.settings = AppSettings()
        
        # Setup logging
        self._setup_logging()
        
    def _setup_logging(self):
        """Configure application logging."""
        log_level = logging.INFO  # Default to INFO level
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('securepass.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        self.logger.info("SentinelPass application starting...")
        
    def initialize(self):
        """Initialize the PyQt5 application and core components."""
        try:
            # Create QApplication instance
            self.app = QApplication(sys.argv)
            self.app.setApplicationName("SentinelPass")
            self.app.setApplicationVersion("1.0.0")
            self.app.setOrganizationName("SentinelPass Project")
            
            # Set application properties
            self.app.setAttribute(Qt.AA_EnableHighDpiScaling, True)
            self.app.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
            
            # Initialize core components
            self.db_manager = DatabaseManager()
            self.auth_manager = MasterAuthManager()
            
            self.logger.info("Application initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize application: {str(e)}")
            self._show_error("Initialization Error", 
                           f"Failed to initialize SentinelPass:\n{str(e)}")
            return False
    
    def run(self):
        """Run the main application loop."""
        if not self.initialize():
            return 1
            
        try:
            # Check if this is first time setup
            if self._is_first_time_setup():
                if not self._run_setup_wizard():
                    return 0  # User cancelled setup
                    
            # Authenticate user
            if not self._authenticate_user():
                return 0  # Authentication failed or cancelled
                
            # Show main window
            self._show_main_window()
            
            # Start event loop
            return self.app.exec_()
            
        except Exception as e:
            self.logger.error(f"Application error: {str(e)}")
            self._show_error("Application Error", 
                           f"An unexpected error occurred:\n{str(e)}")
            return 1
            
    def _is_first_time_setup(self):
        """Check if this is the first time the application is being run."""
        return not self.db_manager.is_initialized()
        
    def _run_setup_wizard(self):
        """Run the first-time setup wizard."""
        self.logger.info("Running first-time setup wizard")
        wizard = SetupWizard()
        
        if wizard.exec_() == SetupWizard.Accepted:
            # Setup completed successfully
            master_password = wizard.get_master_password()
            
            # Initialize database with master password
            if self.db_manager.initialize_database(master_password):
                self.logger.info("Database initialized successfully")
                return True
            else:
                self._show_error("Setup Error", "Failed to initialize database")
                return False
        else:
            # User cancelled setup
            self.logger.info("Setup cancelled by user")
            return False
            
    def _authenticate_user(self):
        """Authenticate the user with master password."""
        self.logger.info("Authenticating user")
        login_dialog = LoginDialog()
        
        if login_dialog.exec_() == LoginDialog.Accepted:
            master_password = login_dialog.get_password()
            
            if self.auth_manager.authenticate(master_password):
                self.logger.info("User authenticated successfully")
                
                # Connect to database with master password
                if self.db_manager.connect(master_password):
                    self.logger.info("Database connected successfully")
                    return True
                else:
                    self._show_error("Database Connection Failed", 
                                   "Failed to connect to the database")
                    return False
            else:
                self._show_error("Authentication Failed", 
                               "Invalid master password")
                return False
        else:
            # User cancelled login
            self.logger.info("Login cancelled by user")
            return False
            
    def _show_main_window(self):
        """Display the main application window."""
        self.logger.info("Showing main window")
        self.main_window = MainWindow(self.db_manager, self.auth_manager)
        self.main_window.show()
        
    def _show_error(self, title, message):
        """Display an error message to the user."""
        if self.app:
            QMessageBox.critical(None, title, message)
        else:
            print(f"ERROR - {title}: {message}")
            
    def cleanup(self):
        """Perform cleanup operations before application exit."""
        self.logger.info("Cleaning up application resources")
        
        if self.main_window:
            self.main_window.close()
            
        if self.db_manager:
            self.db_manager.close()
            
        self.logger.info("SentinelPass application shutdown complete")


def main():
    """Main entry point for the SentinelPass application."""
    # Create and run application
    app = SentinelPassApplication()
    
    try:
        exit_code = app.run()
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        exit_code = 0
    except Exception as e:
        print(f"Fatal error: {str(e)}")
        exit_code = 1
    finally:
        app.cleanup()
        
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
