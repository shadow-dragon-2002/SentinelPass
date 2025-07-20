"""
Backup and restore dialog for SentinelPass Password Manager.

This module provides a comprehensive backup and restore interface with
local and Google Drive backup options, encryption, and restore functionality.

Features:
- Local encrypted backup creation and restoration
- Google Drive backup with OAuth authentication
- Backup verification and integrity checks
- Automatic backup scheduling
- Backup history and management

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import List, Dict, Any, Optional
from datetime import datetime
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
    QGroupBox, QLabel, QPushButton, QListWidget, QListWidgetItem,
    QProgressBar, QTextEdit, QCheckBox, QSpinBox, QComboBox,
    QFileDialog, QMessageBox, QDialogButtonBox, QFrame,
    QSplitter, QFormLayout, QLineEdit
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread, QTimer
from PyQt5.QtGui import QFont, QIcon

from config.settings import settings
from core.database import DatabaseManager
from core.backup_manager import backup_manager, BackupMetadata
from auth.google_auth import google_auth_manager
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager


class BackupWorkerThread(QThread):
    """
    Worker thread for backup operations.
    
    Handles backup creation and restoration in a separate thread
    to prevent UI blocking during long operations.
    """
    
    # Signals
    progress_updated = pyqtSignal(int, str)
    backup_completed = pyqtSignal(bool, str)
    restore_completed = pyqtSignal(bool, str)
    
    def __init__(self, operation: str, **kwargs):
        """
        Initialize backup worker thread.
        
        Args:
            operation (str): Operation type ('backup' or 'restore')
            **kwargs: Operation-specific parameters
        """
        super().__init__()
        self.operation = operation
        self.params = kwargs
        self.logger = logging.getLogger(__name__)
        
    def run(self):
        """Run the backup operation."""
        try:
            if self.operation == 'backup':
                self._run_backup()
            elif self.operation == 'restore':
                self._run_restore()
        except Exception as e:
            self.logger.error(f"Backup operation failed: {str(e)}")
            if self.operation == 'backup':
                self.backup_completed.emit(False, str(e))
            else:
                self.restore_completed.emit(False, str(e))
                
    def _run_backup(self):
        """Run backup operation."""
        try:
            self.progress_updated.emit(10, "Preparing backup data...")
            
            data = self.params['data']
            master_password = self.params['master_password']
            backup_local = self.params.get('backup_local', True)
            backup_cloud = self.params.get('backup_cloud', False)
            
            self.progress_updated.emit(30, "Creating backup...")
            
            results = backup_manager.create_backup(
                data, master_password, backup_local, backup_cloud
            )
            
            self.progress_updated.emit(100, "Backup completed successfully!")
            self.backup_completed.emit(True, "Backup created successfully")
            
        except Exception as e:
            self.backup_completed.emit(False, str(e))
            
    def _run_restore(self):
        """Run restore operation."""
        try:
            self.progress_updated.emit(10, "Preparing restore...")
            
            backup_source = self.params['backup_source']
            master_password = self.params['master_password']
            is_cloud_backup = self.params.get('is_cloud_backup', False)
            
            self.progress_updated.emit(50, "Restoring data...")
            
            data = backup_manager.restore_backup(
                backup_source, master_password, is_cloud_backup
            )
            
            self.progress_updated.emit(100, "Restore completed successfully!")
            self.restore_completed.emit(True, "Data restored successfully")
            
        except Exception as e:
            self.restore_completed.emit(False, str(e))


class LocalBackupTab(QWidget):
    """
    Local backup management tab.
    
    Provides interface for creating, managing, and restoring
    local encrypted backups.
    """
    
    # Signals
    backup_requested = pyqtSignal(dict)
    restore_requested = pyqtSignal(str)
    
    def __init__(self, db_manager: DatabaseManager, parent=None):
        """Initialize local backup tab."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        
        # UI components
        self.backup_list = None
        self.create_backup_button = None
        self.restore_button = None
        self.delete_button = None
        self.auto_backup_checkbox = None
        self.backup_interval_spinbox = None
        
        self.setup_ui()
        self.connect_signals()
        self.refresh_backup_list()
        
    def setup_ui(self):
        """Setup local backup tab UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Create backup section
        create_group = self.create_backup_section()
        layout.addWidget(create_group)
        
        # Backup list section
        list_group = self.create_backup_list_section()
        layout.addWidget(list_group)
        
        # Auto backup section
        auto_group = self.create_auto_backup_section()
        layout.addWidget(auto_group)
        
    def create_backup_section(self):
        """Create backup creation section."""
        group = QGroupBox("Create Backup")
        layout = QVBoxLayout(group)
        
        # Description
        desc_label = QLabel(
            "Create an encrypted backup of your password database. "
            "Backups are stored locally and can be restored later."
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #6C757D; margin-bottom: 10px;")
        layout.addWidget(desc_label)
        
        # Create backup button
        button_layout = QHBoxLayout()
        self.create_backup_button = QPushButton("Create Local Backup")
        self.create_backup_button.setStyleSheet(
            f"QPushButton {{ "
            f"background-color: {theme_manager.get_color('success')}; "
            f"color: white; font-weight: bold; padding: 10px 20px; "
            f"}} "
            f"QPushButton:hover {{ "
            f"background-color: {theme_manager.get_color('success')}; "
            f"opacity: 0.8; "
            f"}}"
        )
        button_layout.addWidget(self.create_backup_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
        
    def create_backup_list_section(self):
        """Create backup list section."""
        group = QGroupBox("Local Backups")
        layout = QVBoxLayout(group)
        
        # Backup list
        self.backup_list = QListWidget()
        self.backup_list.setMinimumHeight(200)
        layout.addWidget(self.backup_list)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.restore_button = QPushButton("Restore Selected")
        self.restore_button.setEnabled(False)
        button_layout.addWidget(self.restore_button)
        
        self.delete_button = QPushButton("Delete Selected")
        self.delete_button.setEnabled(False)
        self.delete_button.setStyleSheet(
            f"QPushButton {{ background-color: {theme_manager.get_color('danger')}; color: white; }}"
        )
        button_layout.addWidget(self.delete_button)
        
        refresh_button = QPushButton("Refresh")
        button_layout.addWidget(refresh_button)
        refresh_button.clicked.connect(self.refresh_backup_list)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        return group
        
    def create_auto_backup_section(self):
        """Create automatic backup section."""
        group = QGroupBox("Automatic Backup")
        layout = QFormLayout(group)
        
        # Enable auto backup
        self.auto_backup_checkbox = QCheckBox("Enable automatic backups")
        self.auto_backup_checkbox.setChecked(settings.AUTO_BACKUP_ENABLED)
        layout.addRow(self.auto_backup_checkbox)
        
        # Backup interval
        self.backup_interval_spinbox = QSpinBox()
        self.backup_interval_spinbox.setRange(1, 168)  # 1 hour to 1 week
        self.backup_interval_spinbox.setValue(settings.AUTO_BACKUP_INTERVAL_HOURS)
        self.backup_interval_spinbox.setSuffix(" hours")
        layout.addRow("Backup interval:", self.backup_interval_spinbox)
        
        return group
        
    def connect_signals(self):
        """Connect UI signals."""
        self.create_backup_button.clicked.connect(self.create_backup)
        self.restore_button.clicked.connect(self.restore_backup)
        self.delete_button.clicked.connect(self.delete_backup)
        self.backup_list.itemSelectionChanged.connect(self.on_selection_changed)
        
    def refresh_backup_list(self):
        """Refresh the backup list."""
        try:
            self.backup_list.clear()
            
            backups = backup_manager.local_manager.list_backups()
            
            for backup in backups:
                item_text = (
                    f"{backup.filename}\n"
                    f"Created: {backup.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Size: {backup.size_bytes / 1024:.1f} KB\n"
                    f"Entries: {backup.entry_count}"
                )
                
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, backup)
                self.backup_list.addItem(item)
                
            if not backups:
                item = QListWidgetItem("No local backups found")
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
                self.backup_list.addItem(item)
                
        except Exception as e:
            self.logger.error(f"Failed to refresh backup list: {str(e)}")
            
    def on_selection_changed(self):
        """Handle backup selection changes."""
        has_selection = bool(self.backup_list.currentItem())
        selected_item = self.backup_list.currentItem()
        
        if selected_item and selected_item.data(Qt.UserRole):
            self.restore_button.setEnabled(True)
            self.delete_button.setEnabled(True)
        else:
            self.restore_button.setEnabled(False)
            self.delete_button.setEnabled(False)
            
    def create_backup(self):
        """Create a new local backup."""
        try:
            # Get current data
            data = self.db_manager.export_data()
            
            # Request backup creation
            backup_params = {
                'data': data,
                'backup_local': True,
                'backup_cloud': False
            }
            
            self.backup_requested.emit(backup_params)
            
        except Exception as e:
            self.logger.error(f"Failed to create backup: {str(e)}")
            QMessageBox.critical(self, "Backup Error", f"Failed to create backup:\n{str(e)}")
            
    def restore_backup(self):
        """Restore selected backup."""
        selected_item = self.backup_list.currentItem()
        if not selected_item or not selected_item.data(Qt.UserRole):
            return
            
        backup = selected_item.data(Qt.UserRole)
        
        # Confirm restoration
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Are you sure you want to restore from backup '{backup.filename}'?\n\n"
            "This will replace all current password entries with the backup data.\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            backup_path = str(settings.BACKUP_DIR / backup.filename)
            self.restore_requested.emit(backup_path)
            
    def delete_backup(self):
        """Delete selected backup."""
        selected_item = self.backup_list.currentItem()
        if not selected_item or not selected_item.data(Qt.UserRole):
            return
            
        backup = selected_item.data(Qt.UserRole)
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete backup '{backup.filename}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if backup_manager.local_manager.delete_backup(backup.filename):
                    self.refresh_backup_list()
                    QMessageBox.information(self, "Success", "Backup deleted successfully.")
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete backup.")
                    
            except Exception as e:
                self.logger.error(f"Failed to delete backup: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to delete backup:\n{str(e)}")


class CloudBackupTab(QWidget):
    """
    Google Drive backup management tab.
    
    Provides interface for Google Drive authentication,
    cloud backup creation, and restoration.
    """
    
    # Signals
    backup_requested = pyqtSignal(dict)
    restore_requested = pyqtSignal(str, bool)  # backup_id, is_cloud
    
    def __init__(self, db_manager: DatabaseManager, parent=None):
        """Initialize cloud backup tab."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        
        # UI components
        self.auth_status_label = None
        self.auth_button = None
        self.cloud_backup_list = None
        self.create_cloud_backup_button = None
        self.restore_cloud_button = None
        self.delete_cloud_button = None
        
        self.setup_ui()
        self.connect_signals()
        self.update_auth_status()
        
    def setup_ui(self):
        """Setup cloud backup tab UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Authentication section
        auth_group = self.create_auth_section()
        layout.addWidget(auth_group)
        
        # Create cloud backup section
        create_group = self.create_cloud_backup_section()
        layout.addWidget(create_group)
        
        # Cloud backup list section
        list_group = self.create_cloud_backup_list_section()
        layout.addWidget(list_group)
        
    def create_auth_section(self):
        """Create Google Drive authentication section."""
        group = QGroupBox("Google Drive Authentication")
        layout = QVBoxLayout(group)
        
        # Status label
        self.auth_status_label = QLabel("Checking authentication status...")
        layout.addWidget(self.auth_status_label)
        
        # Auth button
        button_layout = QHBoxLayout()
        self.auth_button = QPushButton("Authenticate with Google Drive")
        button_layout.addWidget(self.auth_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
        
    def create_cloud_backup_section(self):
        """Create cloud backup creation section."""
        group = QGroupBox("Create Cloud Backup")
        layout = QVBoxLayout(group)
        
        # Description
        desc_label = QLabel(
            "Create an encrypted backup and upload it to your Google Drive. "
            "Cloud backups provide additional protection and accessibility."
        )
        desc_label.setWordWrap(True)
        desc_label.setStyleSheet("color: #6C757D; margin-bottom: 10px;")
        layout.addWidget(desc_label)
        
        # Create backup button
        button_layout = QHBoxLayout()
        self.create_cloud_backup_button = QPushButton("Create Cloud Backup")
        self.create_cloud_backup_button.setEnabled(False)
        self.create_cloud_backup_button.setStyleSheet(
            f"QPushButton {{ "
            f"background-color: {theme_manager.get_color('secondary')}; "
            f"color: white; font-weight: bold; padding: 10px 20px; "
            f"}} "
            f"QPushButton:hover {{ "
            f"background-color: {theme_manager.get_color('secondary_light')}; "
            f"}}"
        )
        button_layout.addWidget(self.create_cloud_backup_button)
        button_layout.addStretch()
        
        layout.addLayout(button_layout)
        
        return group
        
    def create_cloud_backup_list_section(self):
        """Create cloud backup list section."""
        group = QGroupBox("Cloud Backups")
        layout = QVBoxLayout(group)
        
        # Cloud backup list
        self.cloud_backup_list = QListWidget()
        self.cloud_backup_list.setMinimumHeight(200)
        layout.addWidget(self.cloud_backup_list)
        
        # Action buttons
        button_layout = QHBoxLayout()
        
        self.restore_cloud_button = QPushButton("Restore Selected")
        self.restore_cloud_button.setEnabled(False)
        button_layout.addWidget(self.restore_cloud_button)
        
        self.delete_cloud_button = QPushButton("Delete Selected")
        self.delete_cloud_button.setEnabled(False)
        self.delete_cloud_button.setStyleSheet(
            f"QPushButton {{ background-color: {theme_manager.get_color('danger')}; color: white; }}"
        )
        button_layout.addWidget(self.delete_cloud_button)
        
        refresh_cloud_button = QPushButton("Refresh")
        button_layout.addWidget(refresh_cloud_button)
        refresh_cloud_button.clicked.connect(self.refresh_cloud_backup_list)
        
        button_layout.addStretch()
        layout.addLayout(button_layout)
        
        return group
        
    def connect_signals(self):
        """Connect UI signals."""
        self.auth_button.clicked.connect(self.authenticate_google_drive)
        self.create_cloud_backup_button.clicked.connect(self.create_cloud_backup)
        self.restore_cloud_button.clicked.connect(self.restore_cloud_backup)
        self.delete_cloud_button.clicked.connect(self.delete_cloud_backup)
        self.cloud_backup_list.itemSelectionChanged.connect(self.on_cloud_selection_changed)
        
    def update_auth_status(self):
        """Update Google Drive authentication status."""
        try:
            if google_auth_manager.is_authenticated():
                user_info = google_auth_manager.get_user_info()
                if user_info:
                    self.auth_status_label.setText(
                        f"✓ Authenticated as: {user_info.get('email', 'Unknown')}"
                    )
                    self.auth_status_label.setStyleSheet(f"color: {theme_manager.get_color('success')};")
                else:
                    self.auth_status_label.setText("✓ Authenticated with Google Drive")
                    self.auth_status_label.setStyleSheet(f"color: {theme_manager.get_color('success')};")
                    
                self.auth_button.setText("Re-authenticate")
                self.create_cloud_backup_button.setEnabled(True)
                self.refresh_cloud_backup_list()
            else:
                self.auth_status_label.setText("✗ Not authenticated with Google Drive")
                self.auth_status_label.setStyleSheet(f"color: {theme_manager.get_color('danger')};")
                self.auth_button.setText("Authenticate with Google Drive")
                self.create_cloud_backup_button.setEnabled(False)
                
        except Exception as e:
            self.logger.error(f"Failed to update auth status: {str(e)}")
            self.auth_status_label.setText("✗ Authentication status unknown")
            self.auth_status_label.setStyleSheet(f"color: {theme_manager.get_color('warning')};")
            
    def authenticate_google_drive(self):
        """Authenticate with Google Drive."""
        try:
            self.auth_button.setEnabled(False)
            self.auth_button.setText("Authenticating...")
            
            if google_auth_manager.authenticate():
                QMessageBox.information(
                    self, "Success", 
                    "Successfully authenticated with Google Drive!"
                )
            else:
                QMessageBox.warning(
                    self, "Authentication Failed", 
                    "Failed to authenticate with Google Drive."
                )
                
        except Exception as e:
            self.logger.error(f"Google Drive authentication failed: {str(e)}")
            QMessageBox.critical(
                self, "Authentication Error", 
                f"Authentication failed:\n{str(e)}"
            )
        finally:
            self.auth_button.setEnabled(True)
            self.update_auth_status()
            
    def refresh_cloud_backup_list(self):
        """Refresh cloud backup list."""
        if not google_auth_manager.is_authenticated():
            return
            
        try:
            self.cloud_backup_list.clear()
            
            backups = backup_manager.cloud_manager.list_cloud_backups()
            
            for backup in backups:
                created_time = datetime.fromisoformat(backup['createdTime'].replace('Z', '+00:00'))
                size_mb = int(backup.get('size', 0)) / (1024 * 1024)
                
                item_text = (
                    f"{backup['name']}\n"
                    f"Created: {created_time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                    f"Size: {size_mb:.1f} MB"
                )
                
                item = QListWidgetItem(item_text)
                item.setData(Qt.UserRole, backup)
                self.cloud_backup_list.addItem(item)
                
            if not backups:
                item = QListWidgetItem("No cloud backups found")
                item.setFlags(item.flags() & ~Qt.ItemIsSelectable)
                self.cloud_backup_list.addItem(item)
                
        except Exception as e:
            self.logger.error(f"Failed to refresh cloud backup list: {str(e)}")
            
    def on_cloud_selection_changed(self):
        """Handle cloud backup selection changes."""
        selected_item = self.cloud_backup_list.currentItem()
        
        if selected_item and selected_item.data(Qt.UserRole):
            self.restore_cloud_button.setEnabled(True)
            self.delete_cloud_button.setEnabled(True)
        else:
            self.restore_cloud_button.setEnabled(False)
            self.delete_cloud_button.setEnabled(False)
            
    def create_cloud_backup(self):
        """Create a new cloud backup."""
        try:
            # Get current data
            data = self.db_manager.export_data()
            
            # Request backup creation
            backup_params = {
                'data': data,
                'backup_local': True,  # Create local first, then upload
                'backup_cloud': True
            }
            
            self.backup_requested.emit(backup_params)
            
        except Exception as e:
            self.logger.error(f"Failed to create cloud backup: {str(e)}")
            QMessageBox.critical(self, "Backup Error", f"Failed to create cloud backup:\n{str(e)}")
            
    def restore_cloud_backup(self):
        """Restore selected cloud backup."""
        selected_item = self.cloud_backup_list.currentItem()
        if not selected_item or not selected_item.data(Qt.UserRole):
            return
            
        backup = selected_item.data(Qt.UserRole)
        
        # Confirm restoration
        reply = QMessageBox.question(
            self,
            "Confirm Restore",
            f"Are you sure you want to restore from cloud backup '{backup['name']}'?\n\n"
            "This will replace all current password entries with the backup data.\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            self.restore_requested.emit(backup['id'], True)
            
    def delete_cloud_backup(self):
        """Delete selected cloud backup."""
        selected_item = self.cloud_backup_list.currentItem()
        if not selected_item or not selected_item.data(Qt.UserRole):
            return
            
        backup = selected_item.data(Qt.UserRole)
        
        # Confirm deletion
        reply = QMessageBox.question(
            self,
            "Confirm Deletion",
            f"Are you sure you want to delete cloud backup '{backup['name']}'?\n\n"
            "This action cannot be undone.",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            try:
                if backup_manager.cloud_manager.delete_cloud_backup(backup['id']):
                    self.refresh_cloud_backup_list()
                    QMessageBox.information(self, "Success", "Cloud backup deleted successfully.")
                else:
                    QMessageBox.warning(self, "Error", "Failed to delete cloud backup.")
                    
            except Exception as e:
                self.logger.error(f"Failed to delete cloud backup: {str(e)}")
                QMessageBox.critical(self, "Error", f"Failed to delete cloud backup:\n{str(e)}")


class BackupDialog(QDialog):
    """
    Main backup and restore dialog.
    
    Provides comprehensive backup management interface with
    local and cloud backup options.
    """
    
    def __init__(self, db_manager: DatabaseManager, parent=None):
        """Initialize backup dialog."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        
        # Worker thread
        self.worker_thread = None
        
        # UI components
        self.tab_widget = None
        self.local_tab = None
        self.cloud_tab = None
        self.progress_bar = None
        self.status_label = None
        self.button_box = None
        
        self.setup_dialog()
        self.setup_ui()
        self.connect_signals()
        
    def setup_dialog(self):
        """Setup dialog properties."""
        self.setWindowTitle("SentinelPass - Backup & Restore")
        self.setModal(True)
        self.setMinimumSize(700, 600)
        self.resize(800, 700)
        
        # Apply theme
        self.setStyleSheet(theme_manager.stylesheet_generator.get_complete_stylesheet())
        
    def setup_ui(self):
        """Setup backup dialog UI."""
        layout = QVBoxLayout(self)
        layout.setSpacing(15)
        
        # Header
        header_label = QLabel("Backup & Restore")
        header_label.setStyleSheet(
            f"font-size: 18pt; font-weight: bold; "
            f"color: {theme_manager.get_color('secondary')}; "
            f"margin: 10px 0;"
        )
        layout.addWidget(header_label)
        
        # Tab widget
        self.tab_widget = QTabWidget()
        
        # Local backup tab
        self.local_tab = LocalBackupTab(self.db_manager)
        self.tab_widget.addTab(self.local_tab, "🗂️ Local Backups")
        
        # Cloud backup tab
        self.cloud_tab = CloudBackupTab(self.db_manager)
        self.tab_widget.addTab(self.cloud_tab, "☁️ Cloud Backups")
        
        layout.addWidget(self.tab_widget)
        
        # Progress section
        progress_group = QGroupBox("Operation Progress")
        progress_layout = QVBoxLayout(progress_group)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        progress_layout.addWidget(self.progress_bar)
        
        self.status_label = QLabel("")
        self.status_label.setVisible(False)
        progress_layout.addWidget(self.status_label)
        
        layout.addWidget(progress_group)
        
        # Button box
        self.button_box = QDialogButtonBox(QDialogButtonBox.Close)
        layout.addWidget(self.button_box)
        
    def connect_signals(self):
        """Connect dialog signals."""
        # Tab signals
        self.local_tab.backup_requested.connect(self.handle_backup_request)
        self.local_tab.restore_requested.connect(self.handle_restore_request)
        self.cloud_tab.backup_requested.connect(self.handle_backup_request)
        self.cloud_tab.restore_requested.connect(self.handle_cloud_restore_request)
        
        # Button box
        self.button_box.rejected.connect(self.reject)
        
    def handle_backup_request(self, params):
        """Handle backup request from tabs."""
        try:
            # Get master password
            from ui.login_dialog import LoginDialog
            login_dialog = LoginDialog(self)
            login_dialog.setWindowTitle("Master Password Required")
            
            if login_dialog.exec_() != LoginDialog.Accepted:
                return
                
            master_password = login_dialog.get_password()
            params['master_password'] = master_password
            
            # Start backup operation
            self.start_backup_operation(params)
            
        except Exception as e:
            self.logger.error(f"Backup request failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Backup request failed:\n{str(e)}")
            
    def handle_restore_request(self, backup_path):
        """Handle restore request from local tab."""
        self.handle_cloud_restore_request(backup_path, False)
        
    def handle_cloud_restore_request(self, backup_source, is_cloud):
        """Handle restore request."""
        try:
            # Get master password
            from ui.login_dialog import LoginDialog
            login_dialog = LoginDialog(self)
            login_dialog.setWindowTitle("Master Password Required")
            
            if login_dialog.exec_() != LoginDialog.Accepted:
                return
                
            master_password = login_dialog.get_password()
            
            # Start restore operation
            params = {
                'backup_source': backup_source,
                'master_password': master_password,
                'is_cloud_backup': is_cloud
            }
            
            self.start_restore_operation(params)
            
        except Exception as e:
            self.logger.error(f"Restore request failed: {str(e)}")
            QMessageBox.critical(self, "Error", f"Restore request failed:\n{str(e)}")
            
    def start_backup_operation(self, params):
        """Start backup operation in worker thread."""
        try:
            # Show progress
            self.progress_bar.setVisible(True)
            self.status_label.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText("Starting backup...")
            
            # Create worker thread
            self.worker_thread = BackupWorkerThread('backup', **params)
            self.worker_thread.progress_updated.connect(self.update_progress)
            self.worker_thread.backup_completed.connect(self.backup_completed)
            self.worker_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start backup operation: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to start backup:\n{str(e)}")
            
    def start_restore_operation(self, params):
        """Start restore operation in worker thread."""
        try:
            # Show progress
            self.progress_bar.setVisible(True)
            self.status_label.setVisible(True)
            self.progress_bar.setValue(0)
            self.status_label.setText("Starting restore...")
            
            # Create worker thread
            self.worker_thread = BackupWorkerThread('restore', **params)
            self.worker_thread.progress_updated.connect(self.update_progress)
            self.worker_thread.restore_completed.connect(self.restore_completed)
            self.worker_thread.start()
            
        except Exception as e:
            self.logger.error(f"Failed to start restore operation: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to start restore:\n{str(e)}")
            
    def update_progress(self, value, message):
        """Update progress display."""
        self.progress_bar.setValue(value)
        self.status_label.setText(message)
        
    def backup_completed(self, success, message):
        """Handle backup completion."""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        
        if success:
            QMessageBox.information(self, "Backup Complete", message)
            # Refresh backup lists
            self.local_tab.refresh_backup_list()
            if self.cloud_tab:
                self.cloud_tab.refresh_cloud_backup_list()
        else:
            QMessageBox.critical(self, "Backup Failed", f"Backup failed:\n{message}")
            
    def restore_completed(self, success, message):
        """Handle restore completion."""
        self.progress_bar.setVisible(False)
        self.status_label.setVisible(False)
        
        if success:
            QMessageBox.information(self, "Restore Complete", 
                                  f"{message}\n\nPlease restart SentinelPass to see the restored data.")
        else:
            QMessageBox.critical(self, "Restore Failed", f"Restore failed:\n{message}")
