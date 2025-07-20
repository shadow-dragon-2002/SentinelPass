"""
Main window for SentinelPass Password Manager.

This module provides the main application window with a modern interface
including password list, search functionality, toolbar, and integrated
access to all password management features.

Features:
- Modern tabbed interface
- Password list with search and filtering
- Quick copy functionality
- Integrated password generator
- Backup and settings access
- Auto-lock and security features

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import Optional, List, Dict, Any
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QToolBar, QStatusBar, QMenuBar, QMenu, QAction, QLabel,
    QLineEdit, QPushButton, QSplitter, QFrame, QMessageBox,
    QSystemTrayIcon, QApplication
)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QIcon, QKeySequence, QFont, QPixmap

from config.settings import settings
from core.database import DatabaseManager, PasswordEntry
from auth.master_auth import MasterAuthManager
from utils.clipboard import clipboard_manager
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager
from ui.password_list import PasswordListWidget
from ui.password_form import PasswordFormDialog
from ui.generator_dialog import PasswordGeneratorDialog
from ui.backup_dialog import BackupDialog


class MainWindow(QMainWindow):
    """
    Main application window for SentinelPass Password Manager.
    
    Provides the primary interface for password management including
    password list, search, quick actions, and access to all features.
    """
    
    # Signals
    password_copied = pyqtSignal(str)  # Password copied to clipboard
    entry_added = pyqtSignal(PasswordEntry)  # New entry added
    entry_updated = pyqtSignal(PasswordEntry)  # Entry updated
    entry_deleted = pyqtSignal(int)  # Entry deleted
    
    def __init__(self, db_manager: DatabaseManager, auth_manager: MasterAuthManager, parent=None):
        """
        Initialize main window.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
            auth_manager (MasterAuthManager): Authentication manager instance
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        self.auth_manager = auth_manager
        
        # UI components
        self.central_widget = None
        self.tab_widget = None
        self.password_list = None
        self.search_input = None
        self.status_bar = None
        self.toolbar = None
        self.menu_bar = None
        
        # Timers and threads
        self.auto_lock_timer = None
        self.status_update_timer = None
        
        # System tray
        self.tray_icon = None
        
        # State
        self.is_locked = False
        self.last_activity_time = None
        
        self.setup_window()
        self.setup_ui()
        self.setup_menu_bar()
        self.setup_toolbar()
        self.setup_status_bar()
        self.setup_system_tray()
        self.connect_signals()
        self.start_timers()
        
        # Load initial data
        self.refresh_password_list()
        
        self.logger.info("MainWindow initialized")
        
    def setup_window(self):
        """Setup main window properties."""
        self.setWindowTitle("SentinelPass - Password Manager")
        self.setMinimumSize(settings.WINDOW_MIN_WIDTH, settings.WINDOW_MIN_HEIGHT)
        self.resize(settings.WINDOW_DEFAULT_WIDTH, settings.WINDOW_DEFAULT_HEIGHT)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
        # Set window icon (placeholder)
        # self.setWindowIcon(QIcon(":/icons/securepass.png"))
        
    def setup_ui(self):
        """Setup the main user interface."""
        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        
        # Main layout
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(10, 10, 10, 10)
        main_layout.setSpacing(10)
        
        # Search section
        search_layout = self.create_search_section()
        main_layout.addLayout(search_layout)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.North)
        self.tab_widget.setMovable(False)
        
        # Password list tab
        self.password_list = PasswordListWidget(self.db_manager)
        self.tab_widget.addTab(self.password_list, "🔐 Passwords")
        
        # Connect password list signals
        self.password_list.entry_selected.connect(self.on_entry_selected)
        self.password_list.copy_username_requested.connect(self.copy_username)
        self.password_list.copy_password_requested.connect(self.copy_password)
        self.password_list.edit_entry_requested.connect(self.edit_entry)
        self.password_list.delete_entry_requested.connect(self.delete_entry)
        
        main_layout.addWidget(self.tab_widget)
        
    def create_search_section(self):
        """Create search section."""
        layout = QHBoxLayout()
        
        # Search label
        search_label = QLabel("🔍 Search:")
        search_label.setStyleSheet("font-weight: bold;")
        layout.addWidget(search_label)
        
        # Search input
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search passwords by title, username, or URL...")
        self.search_input.textChanged.connect(self.on_search_changed)
        layout.addWidget(self.search_input)
        
        # Clear search button
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self.clear_search)
        clear_button.setMaximumWidth(60)
        layout.addWidget(clear_button)
        
        return layout
        
    def setup_menu_bar(self):
        """Setup menu bar."""
        self.menu_bar = self.menuBar()
        
        # File menu
        file_menu = self.menu_bar.addMenu("&File")
        
        # Add password action
        add_action = QAction("&Add Password", self)
        add_action.setShortcut(QKeySequence.New)
        add_action.setStatusTip("Add a new password entry")
        add_action.triggered.connect(self.add_password)
        file_menu.addAction(add_action)
        
        file_menu.addSeparator()
        
        # Import/Export actions
        import_action = QAction("&Import...", self)
        import_action.setStatusTip("Import passwords from file")
        import_action.triggered.connect(self.import_passwords)
        file_menu.addAction(import_action)
        
        export_action = QAction("&Export...", self)
        export_action.setStatusTip("Export passwords to file")
        export_action.triggered.connect(self.export_passwords)
        file_menu.addAction(export_action)
        
        file_menu.addSeparator()
        
        # Lock action
        lock_action = QAction("&Lock", self)
        lock_action.setShortcut(QKeySequence("Ctrl+L"))
        lock_action.setStatusTip("Lock the application")
        lock_action.triggered.connect(self.lock_application)
        file_menu.addAction(lock_action)
        
        # Exit action
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.setStatusTip("Exit SentinelPass")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)
        
        # Tools menu
        tools_menu = self.menu_bar.addMenu("&Tools")
        
        # Password generator action
        generator_action = QAction("Password &Generator", self)
        generator_action.setShortcut(QKeySequence("Ctrl+G"))
        generator_action.setStatusTip("Open password generator")
        generator_action.triggered.connect(self.open_password_generator)
        tools_menu.addAction(generator_action)
        
        tools_menu.addSeparator()
        
        # Backup action
        backup_action = QAction("&Backup & Restore", self)
        backup_action.setShortcut(QKeySequence("Ctrl+B"))
        backup_action.setStatusTip("Backup and restore passwords")
        backup_action.triggered.connect(self.open_backup_dialog)
        tools_menu.addAction(backup_action)
        
        # Settings action
        settings_action = QAction("&Settings", self)
        settings_action.setStatusTip("Open application settings")
        settings_action.triggered.connect(self.open_settings)
        tools_menu.addAction(settings_action)
        
        # Help menu
        help_menu = self.menu_bar.addMenu("&Help")
        
        # About action
        about_action = QAction("&About", self)
        about_action.setStatusTip("About SentinelPass")
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
    def setup_toolbar(self):
        """Setup toolbar."""
        self.toolbar = QToolBar("Main Toolbar")
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.addToolBar(self.toolbar)
        
        # Add password action
        add_action = QAction("Add", self)
        add_action.setStatusTip("Add new password")
        add_action.triggered.connect(self.add_password)
        self.toolbar.addAction(add_action)
        
        self.toolbar.addSeparator()
        
        # Generator action
        generator_action = QAction("Generate", self)
        generator_action.setStatusTip("Password generator")
        generator_action.triggered.connect(self.open_password_generator)
        self.toolbar.addAction(generator_action)
        
        # Backup action
        backup_action = QAction("Backup", self)
        backup_action.setStatusTip("Backup & restore")
        backup_action.triggered.connect(self.open_backup_dialog)
        self.toolbar.addAction(backup_action)
        
        self.toolbar.addSeparator()
        
        # Lock action
        lock_action = QAction("Lock", self)
        lock_action.setStatusTip("Lock application")
        lock_action.triggered.connect(self.lock_application)
        self.toolbar.addAction(lock_action)
        
    def setup_status_bar(self):
        """Setup status bar."""
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Entry count label
        self.entry_count_label = QLabel("0 passwords")
        self.status_bar.addWidget(self.entry_count_label)
        
        # Spacer
        self.status_bar.addPermanentWidget(QLabel(""))
        
        # Security status label
        self.security_status_label = QLabel("🔒 Secure")
        self.security_status_label.setStyleSheet(f"color: {theme_manager.get_color('success')};")
        self.status_bar.addPermanentWidget(self.security_status_label)
        
        # Auto-lock timer label
        self.auto_lock_label = QLabel("")
        self.status_bar.addPermanentWidget(self.auto_lock_label)
        
    def setup_system_tray(self):
        """Setup system tray icon."""
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray_icon = QSystemTrayIcon(self)
            # self.tray_icon.setIcon(QIcon(":/icons/securepass.png"))
            
            # Tray menu
            tray_menu = QMenu()
            
            show_action = QAction("Show SentinelPass", self)
            show_action.triggered.connect(self.show_normal)
            tray_menu.addAction(show_action)
            
            tray_menu.addSeparator()
            
            lock_action = QAction("Lock", self)
            lock_action.triggered.connect(self.lock_application)
            tray_menu.addAction(lock_action)
            
            quit_action = QAction("Quit", self)
            quit_action.triggered.connect(self.close)
            tray_menu.addAction(quit_action)
            
            self.tray_icon.setContextMenu(tray_menu)
            self.tray_icon.activated.connect(self.on_tray_activated)
            self.tray_icon.show()
            
    def connect_signals(self):
        """Connect signals and slots."""
        # Authentication manager signals
        self.auth_manager.on_session_expired = self.on_session_expired
        self.auth_manager.on_auto_lock = self.on_auto_lock
        
        # Tab widget signals
        self.tab_widget.currentChanged.connect(self.on_tab_changed)
        
    def start_timers(self):
        """Start application timers."""
        # Status update timer
        self.status_update_timer = QTimer()
        self.status_update_timer.timeout.connect(self.update_status)
        self.status_update_timer.start(5000)  # Update every 5 seconds
        
    def on_search_changed(self, text):
        """Handle search text changes."""
        self.password_list.filter_entries(text)
        self.record_activity()
        
    def clear_search(self):
        """Clear search input."""
        self.search_input.clear()
        self.password_list.filter_entries("")
        self.record_activity()
        
    def on_entry_selected(self, entry: PasswordEntry):
        """Handle password entry selection."""
        self.record_activity()
        
    def copy_username(self, entry: PasswordEntry):
        """Copy username to clipboard."""
        if entry.username:
            success = clipboard_manager.copy_password_entry_field(
                entry.username, "username", entry.title
            )
            if success:
                self.show_status_message(f"Username copied for '{entry.title}'", 3000)
                self.password_copied.emit("username")
            else:
                self.show_status_message("Failed to copy username", 3000)
        else:
            self.show_status_message("No username to copy", 2000)
            
        self.record_activity()
        
    def copy_password(self, entry: PasswordEntry):
        """Copy password to clipboard."""
        success = clipboard_manager.copy_password_entry_field(
            entry.password, "password", entry.title
        )
        if success:
            self.show_status_message(f"Password copied for '{entry.title}'", 3000)
            self.password_copied.emit("password")
            
            # Log security event
            security_monitor.log_security_event(
                "password_copied",
                SecurityLevel.LOW,
                f"Password copied for entry: {entry.title}",
                "main_window"
            )
        else:
            self.show_status_message("Failed to copy password", 3000)
            
        self.record_activity()
        
    def add_password(self):
        """Add new password entry."""
        dialog = PasswordFormDialog(self.db_manager, parent=self)
        if dialog.exec_() == PasswordFormDialog.Accepted:
            entry = dialog.get_password_entry()
            if entry:
                self.refresh_password_list()
                self.entry_added.emit(entry)
                self.show_status_message(f"Added password for '{entry.title}'", 3000)
                
        self.record_activity()
        
    def edit_entry(self, entry: PasswordEntry):
        """Edit password entry."""
        dialog = PasswordFormDialog(self.db_manager, entry, parent=self)
        if dialog.exec_() == PasswordFormDialog.Accepted:
            updated_entry = dialog.get_password_entry()
            if updated_entry:
                self.refresh_password_list()
                self.entry_updated.emit(updated_entry)
                self.show_status_message(f"Updated password for '{updated_entry.title}'", 3000)
                
        self.record_activity()
        
    def delete_entry(self, entry: PasswordEntry):
        """Delete password entry."""
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete the password for '{entry.title}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if self.db_manager.delete_password_entry(entry.entry_id):
                    self.refresh_password_list()
                    self.entry_deleted.emit(entry.entry_id)
                    self.show_status_message(f"Deleted password for '{entry.title}'", 3000)
                    
                    # Log security event
                    security_monitor.log_security_event(
                        "password_deleted",
                        SecurityLevel.MEDIUM,
                        f"Password entry deleted: {entry.title}",
                        "main_window"
                    )
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete password entry.")
                    
            except Exception as e:
                self.logger.error(f"Failed to delete entry: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to delete password entry:\n{str(e)}")
                
        self.record_activity()
        
    def open_password_generator(self):
        """Open password generator dialog."""
        dialog = PasswordGeneratorDialog(parent=self)
        dialog.exec_()
        self.record_activity()
        
    def open_backup_dialog(self):
        """Open backup and restore dialog."""
        dialog = BackupDialog(self.db_manager, parent=self)
        dialog.exec_()
        self.record_activity()
        
    def open_settings(self):
        """Open settings dialog."""
        # TODO: Implement settings dialog
        QMessageBox.information(self, "Settings", "Settings dialog not yet implemented.")
        self.record_activity()
        
    def import_passwords(self):
        """Import passwords from file."""
        # TODO: Implement import functionality
        QMessageBox.information(self, "Import", "Import functionality not yet implemented.")
        self.record_activity()
        
    def export_passwords(self):
        """Export passwords to file."""
        # TODO: Implement export functionality
        QMessageBox.information(self, "Export", "Export functionality not yet implemented.")
        self.record_activity()
        
    def lock_application(self):
        """Lock the application."""
        self.auth_manager.logout()
        self.is_locked = True
        self.hide()
        
        # Show lock notification
        if self.tray_icon:
            self.tray_icon.showMessage(
                "SentinelPass Locked",
                "Application has been locked for security.",
                QSystemTrayIcon.Information,
                3000
            )
            
        # Log security event
        security_monitor.log_security_event(
            "application_locked",
            SecurityLevel.LOW,
            "Application manually locked by user",
            "main_window"
        )
        
    def on_session_expired(self):
        """Handle session expiration."""
        self.lock_application()
        
        if self.tray_icon:
            self.tray_icon.showMessage(
                "Session Expired",
                "Your session has expired due to inactivity.",
                QSystemTrayIcon.Warning,
                5000
            )
            
    def on_auto_lock(self):
        """Handle auto-lock."""
        self.lock_application()
        
    def on_tab_changed(self, index):
        """Handle tab change."""
        self.record_activity()
        
    def on_tray_activated(self, reason):
        """Handle system tray activation."""
        if reason == QSystemTrayIcon.DoubleClick:
            if self.is_locked:
                # TODO: Show login dialog
                pass
            else:
                self.show_normal()
                
    def show_normal(self):
        """Show window normally."""
        self.show()
        self.raise_()
        self.activateWindow()
        
    def refresh_password_list(self):
        """Refresh the password list."""
        try:
            self.password_list.refresh_entries()
            self.update_entry_count()
        except Exception as e:
            self.logger.error(f"Failed to refresh password list: {str(e)}")
            # Show user-friendly error message
            if "Database not connected" in str(e):
                QMessageBox.critical(
                    self, 
                    "Database Connection Error", 
                    "Failed to load password entries: Database not connected\n\n"
                    "Please restart the application and try again."
                )
            else:
                QMessageBox.critical(
                    self, 
                    "Error Loading Passwords", 
                    f"Failed to load password entries:\n{str(e)}"
                )
            
    def update_entry_count(self):
        """Update entry count in status bar."""
        try:
            entries = self.db_manager.get_all_password_entries()
            count = len(entries)
            self.entry_count_label.setText(f"{count} password{'s' if count != 1 else ''}")
        except Exception as e:
            self.logger.error(f"Failed to update entry count: {str(e)}")
            
    def update_status(self):
        """Update status bar information."""
        # Update auto-lock timer
        if self.auth_manager.is_authenticated():
            session_info = self.auth_manager.get_session_info()
            if session_info:
                # Calculate remaining time
                from datetime import datetime, timedelta
                expires_at = datetime.fromisoformat(session_info['expires_at'])
                remaining = expires_at - datetime.now()
                
                if remaining.total_seconds() > 0:
                    minutes = int(remaining.total_seconds() / 60)
                    self.auto_lock_label.setText(f"Auto-lock: {minutes}m")
                else:
                    self.auto_lock_label.setText("Auto-lock: expired")
            else:
                self.auto_lock_label.setText("")
        else:
            self.auto_lock_label.setText("")
            
    def record_activity(self):
        """Record user activity for auto-lock timer."""
        if self.auth_manager.is_authenticated():
            # This will update the session activity and restart auto-lock timer
            self.auth_manager.is_authenticated()
            
    def show_status_message(self, message: str, timeout: int = 2000):
        """Show message in status bar."""
        self.status_bar.showMessage(message, timeout)
        
    def show_about(self):
        """Show about dialog."""
        QMessageBox.about(
            self,
            "About SentinelPass",
            f"<h3>SentinelPass Password Manager</h3>"
            f"<p>Version {settings.APP_VERSION}</p>"
            f"<p>A professional password manager with military-grade encryption.</p>"
            f"<p><b>Features:</b></p>"
            f"<ul>"
            f"<li>AES-256 encryption</li>"
            f"<li>Secure password generation</li>"
            f"<li>Google Drive backup</li>"
            f"<li>Auto-lock security</li>"
            f"</ul>"
            f"<p>Created as a final year project demonstrating secure coding practices.</p>"
        )
        
    def closeEvent(self, event):
        """Handle close event."""
        if self.tray_icon and self.tray_icon.isVisible():
            # Minimize to tray instead of closing
            self.hide()
            event.ignore()
            
            if not hasattr(self, '_tray_message_shown'):
                self.tray_icon.showMessage(
                    "SentinelPass",
                    "Application minimized to system tray.",
                    QSystemTrayIcon.Information,
                    2000
                )
                self._tray_message_shown = True
        else:
            # Actually close the application
            self.cleanup()
            event.accept()
            
    def cleanup(self):
        """Cleanup resources before closing."""
        # Stop timers
        if self.status_update_timer:
            self.status_update_timer.stop()
            
        # Cleanup clipboard
        clipboard_manager.cleanup()
        
        # Cleanup authentication
        self.auth_manager.cleanup()
        
        # Close database
        if self.db_manager:
            self.db_manager.close()
            
        self.logger.info("MainWindow cleanup completed")
