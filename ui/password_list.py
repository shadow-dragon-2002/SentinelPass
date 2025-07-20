"""
Password list widget for SentinelPass Password Manager.

This module provides a comprehensive password list widget with search,
filtering, sorting, and quick action capabilities. It displays password
entries in a modern table format with security features.

Features:
- Modern table display with sorting
- Search and filtering capabilities
- Quick copy buttons for username/password
- Context menu with actions
- Secure display (passwords hidden by default)
- Category filtering and organization

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import logging
from typing import List, Optional, Dict, Any
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QMenu, QAction, QMessageBox, QLabel,
    QComboBox, QFrame, QSplitter, QGroupBox, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon, QColor, QPalette

from config.settings import settings
from core.database import DatabaseManager, PasswordEntry
from utils.security import security_monitor, SecurityLevel
from ui.styles import theme_manager


class PasswordTableWidget(QTableWidget):
    """
    Custom table widget for displaying password entries.
    
    Provides enhanced functionality for password display including
    secure password hiding, quick actions, and context menus.
    """
    
    # Signals
    entry_selected = pyqtSignal(PasswordEntry)
    copy_username_requested = pyqtSignal(PasswordEntry)
    copy_password_requested = pyqtSignal(PasswordEntry)
    edit_entry_requested = pyqtSignal(PasswordEntry)
    delete_entry_requested = pyqtSignal(PasswordEntry)
    
    def __init__(self, parent=None):
        """Initialize password table widget."""
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.entries: List[PasswordEntry] = []
        self.filtered_entries: List[PasswordEntry] = []
        
        self.setup_table()
        self.setup_context_menu()
        
    def setup_table(self):
        """Setup table properties and columns."""
        # Table properties
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QTableWidget.SingleSelection)
        self.setSortingEnabled(True)
        self.setShowGrid(False)
        self.verticalHeader().setVisible(False)
        
        # Columns
        columns = ["Title", "Username", "URL", "Category", "Updated", "Actions"]
        self.setColumnCount(len(columns))
        self.setHorizontalHeaderLabels(columns)
        
        # Header styling
        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignLeft)
        header.setSectionResizeMode(0, QHeaderView.Stretch)  # Title
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)  # Username
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)  # URL
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)  # Category
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)  # Updated
        header.setSectionResizeMode(5, QHeaderView.Fixed)  # Actions
        header.resizeSection(5, 150)  # Actions column width
        
        # Connect signals
        self.itemSelectionChanged.connect(self.on_selection_changed)
        self.itemDoubleClicked.connect(self.on_item_double_clicked)
        
    def setup_context_menu(self):
        """Setup context menu for table items."""
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self.show_context_menu)
        
    def show_context_menu(self, position):
        """Show context menu at position."""
        item = self.itemAt(position)
        if not item:
            return
            
        row = item.row()
        if row >= len(self.filtered_entries):
            return
            
        entry = self.filtered_entries[row]
        
        menu = QMenu(self)
        
        # Copy actions
        copy_username_action = QAction("Copy Username", self)
        copy_username_action.triggered.connect(lambda: self.copy_username_requested.emit(entry))
        menu.addAction(copy_username_action)
        
        copy_password_action = QAction("Copy Password", self)
        copy_password_action.triggered.connect(lambda: self.copy_password_requested.emit(entry))
        menu.addAction(copy_password_action)
        
        menu.addSeparator()
        
        # Edit action
        edit_action = QAction("Edit", self)
        edit_action.triggered.connect(lambda: self.edit_entry_requested.emit(entry))
        menu.addAction(edit_action)
        
        # Delete action
        delete_action = QAction("Delete", self)
        delete_action.triggered.connect(lambda: self.delete_entry_requested.emit(entry))
        menu.addAction(delete_action)
        
        menu.exec_(self.mapToGlobal(position))
        
    def load_entries(self, entries: List[PasswordEntry]):
        """Load password entries into table."""
        self.entries = entries
        self.filtered_entries = entries.copy()
        self.refresh_table()
        
    def refresh_table(self):
        """Refresh table display with current filtered entries."""
        self.setRowCount(len(self.filtered_entries))
        
        for row, entry in enumerate(self.filtered_entries):
            self.populate_row(row, entry)
            
        # Sort by title by default
        self.sortItems(0, Qt.AscendingOrder)
        
    def populate_row(self, row: int, entry: PasswordEntry):
        """Populate table row with entry data."""
        # Title
        title_item = QTableWidgetItem(entry.title)
        title_item.setFlags(title_item.flags() & ~Qt.ItemIsEditable)
        self.setItem(row, 0, title_item)
        
        # Username
        username_item = QTableWidgetItem(entry.username or "")
        username_item.setFlags(username_item.flags() & ~Qt.ItemIsEditable)
        self.setItem(row, 1, username_item)
        
        # URL
        url_item = QTableWidgetItem(entry.url or "")
        url_item.setFlags(url_item.flags() & ~Qt.ItemIsEditable)
        self.setItem(row, 2, url_item)
        
        # Category
        category_item = QTableWidgetItem(entry.category or "General")
        category_item.setFlags(category_item.flags() & ~Qt.ItemIsEditable)
        self.setItem(row, 3, category_item)
        
        # Updated date
        updated_text = entry.updated_at.strftime("%Y-%m-%d") if entry.updated_at else ""
        updated_item = QTableWidgetItem(updated_text)
        updated_item.setFlags(updated_item.flags() & ~Qt.ItemIsEditable)
        self.setItem(row, 4, updated_item)
        
        # Actions (buttons)
        actions_widget = self.create_actions_widget(entry)
        self.setCellWidget(row, 5, actions_widget)
        
    def create_actions_widget(self, entry: PasswordEntry) -> QWidget:
        """Create actions widget for table row."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(5, 2, 5, 2)
        layout.setSpacing(5)
        
        # Copy username button
        copy_user_btn = QPushButton("👤")
        copy_user_btn.setToolTip("Copy Username")
        copy_user_btn.setMaximumSize(25, 25)
        copy_user_btn.clicked.connect(lambda: self.copy_username_requested.emit(entry))
        layout.addWidget(copy_user_btn)
        
        # Copy password button
        copy_pass_btn = QPushButton("🔑")
        copy_pass_btn.setToolTip("Copy Password")
        copy_pass_btn.setMaximumSize(25, 25)
        copy_pass_btn.clicked.connect(lambda: self.copy_password_requested.emit(entry))
        layout.addWidget(copy_pass_btn)
        
        # Edit button
        edit_btn = QPushButton("✏️")
        edit_btn.setToolTip("Edit Entry")
        edit_btn.setMaximumSize(25, 25)
        edit_btn.clicked.connect(lambda: self.edit_entry_requested.emit(entry))
        layout.addWidget(edit_btn)
        
        layout.addStretch()
        return widget
        
    def filter_entries(self, search_text: str, category: str = ""):
        """Filter entries based on search text and category."""
        search_text = search_text.lower().strip()
        
        if not search_text and not category:
            self.filtered_entries = self.entries.copy()
        else:
            self.filtered_entries = []
            
            for entry in self.entries:
                # Check search text
                if search_text:
                    searchable_text = " ".join([
                        entry.title.lower(),
                        entry.username.lower() if entry.username else "",
                        entry.url.lower() if entry.url else "",
                        entry.notes.lower() if entry.notes else ""
                    ])
                    
                    if search_text not in searchable_text:
                        continue
                        
                # Check category
                if category and category != "All Categories":
                    if entry.category != category:
                        continue
                        
                self.filtered_entries.append(entry)
                
        self.refresh_table()
        
    def on_selection_changed(self):
        """Handle selection changes."""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_entries):
            entry = self.filtered_entries[current_row]
            self.entry_selected.emit(entry)
            
    def on_item_double_clicked(self, item):
        """Handle item double-click."""
        row = item.row()
        if 0 <= row < len(self.filtered_entries):
            entry = self.filtered_entries[row]
            self.edit_entry_requested.emit(entry)
            
    def get_selected_entry(self) -> Optional[PasswordEntry]:
        """Get currently selected entry."""
        current_row = self.currentRow()
        if 0 <= current_row < len(self.filtered_entries):
            return self.filtered_entries[current_row]
        return None


class CategoryListWidget(QListWidget):
    """
    Category list widget for filtering passwords by category.
    
    Displays available categories with entry counts and allows
    filtering the password list by selected category.
    """
    
    # Signals
    category_selected = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """Initialize category list widget."""
        super().__init__(parent)
        
        self.categories: Dict[str, int] = {}
        self.setup_widget()
        
    def setup_widget(self):
        """Setup widget properties."""
        self.setMaximumWidth(200)
        self.setMinimumWidth(150)
        
        # Connect signals
        self.itemClicked.connect(self.on_item_clicked)
        
    def load_categories(self, entries: List[PasswordEntry]):
        """Load categories from password entries."""
        # Count entries per category
        self.categories = {}
        for entry in entries:
            category = entry.category or "General"
            self.categories[category] = self.categories.get(category, 0) + 1
            
        self.refresh_categories()
        
    def refresh_categories(self):
        """Refresh category list display."""
        self.clear()
        
        # Add "All Categories" option
        total_count = sum(self.categories.values())
        all_item = QListWidgetItem(f"All Categories ({total_count})")
        all_item.setData(Qt.UserRole, "All Categories")
        self.addItem(all_item)
        
        # Add individual categories
        for category, count in sorted(self.categories.items()):
            item = QListWidgetItem(f"{category} ({count})")
            item.setData(Qt.UserRole, category)
            self.addItem(item)
            
        # Select "All Categories" by default
        self.setCurrentRow(0)
        
    def on_item_clicked(self, item):
        """Handle category item click."""
        category = item.data(Qt.UserRole)
        self.category_selected.emit(category)


class PasswordListWidget(QWidget):
    """
    Main password list widget combining table and category list.
    
    Provides a complete interface for viewing, searching, and managing
    password entries with category filtering and quick actions.
    """
    
    # Signals
    entry_selected = pyqtSignal(PasswordEntry)
    copy_username_requested = pyqtSignal(PasswordEntry)
    copy_password_requested = pyqtSignal(PasswordEntry)
    edit_entry_requested = pyqtSignal(PasswordEntry)
    delete_entry_requested = pyqtSignal(PasswordEntry)
    
    def __init__(self, db_manager: DatabaseManager, parent=None):
        """
        Initialize password list widget.
        
        Args:
            db_manager (DatabaseManager): Database manager instance
            parent: Parent widget
        """
        super().__init__(parent)
        
        self.logger = logging.getLogger(__name__)
        self.db_manager = db_manager
        
        # UI components
        self.password_table = None
        self.category_list = None
        self.stats_label = None
        
        # State
        self.current_search = ""
        self.current_category = "All Categories"
        
        self.setup_ui()
        self.connect_signals()
        
    def setup_ui(self):
        """Setup the password list UI."""
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)
        
        # Create splitter
        splitter = QSplitter(Qt.Horizontal)
        
        # Left panel - Categories
        left_panel = self.create_left_panel()
        splitter.addWidget(left_panel)
        
        # Right panel - Password table
        right_panel = self.create_right_panel()
        splitter.addWidget(right_panel)
        
        # Set splitter proportions
        splitter.setSizes([200, 800])
        splitter.setCollapsible(0, False)
        splitter.setCollapsible(1, False)
        
        layout.addWidget(splitter)
        
    def create_left_panel(self) -> QWidget:
        """Create left panel with categories."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Categories group
        categories_group = QGroupBox("Categories")
        categories_layout = QVBoxLayout(categories_group)
        
        # Category list
        self.category_list = CategoryListWidget()
        categories_layout.addWidget(self.category_list)
        
        layout.addWidget(categories_group)
        
        # Statistics
        stats_group = QGroupBox("Statistics")
        stats_layout = QVBoxLayout(stats_group)
        
        self.stats_label = QLabel("No entries")
        self.stats_label.setWordWrap(True)
        self.stats_label.setStyleSheet("padding: 10px;")
        stats_layout.addWidget(self.stats_label)
        
        layout.addWidget(stats_group)
        
        layout.addStretch()
        return panel
        
    def create_right_panel(self) -> QWidget:
        """Create right panel with password table."""
        panel = QWidget()
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Password table
        self.password_table = PasswordTableWidget()
        layout.addWidget(self.password_table)
        
        return panel
        
    def connect_signals(self):
        """Connect widget signals."""
        # Category list signals
        self.category_list.category_selected.connect(self.on_category_selected)
        
        # Password table signals
        self.password_table.entry_selected.connect(self.entry_selected.emit)
        self.password_table.copy_username_requested.connect(self.copy_username_requested.emit)
        self.password_table.copy_password_requested.connect(self.copy_password_requested.emit)
        self.password_table.edit_entry_requested.connect(self.edit_entry_requested.emit)
        self.password_table.delete_entry_requested.connect(self.delete_entry_requested.emit)
        
    def refresh_entries(self):
        """Refresh password entries from database."""
        try:
            entries = self.db_manager.get_all_password_entries()
            
            # Load into components
            self.password_table.load_entries(entries)
            self.category_list.load_categories(entries)
            
            # Update statistics
            self.update_statistics(entries)
            
            # Apply current filters
            self.apply_filters()
            
            self.logger.info(f"Loaded {len(entries)} password entries")
            
        except Exception as e:
            self.logger.error(f"Failed to refresh entries: {str(e)}")
            QMessageBox.critical(self, "Error", f"Failed to load password entries:\n{str(e)}")
            
    def filter_entries(self, search_text: str):
        """Filter entries by search text."""
        self.current_search = search_text
        self.apply_filters()
        
    def on_category_selected(self, category: str):
        """Handle category selection."""
        self.current_category = category
        self.apply_filters()
        
    def apply_filters(self):
        """Apply current search and category filters."""
        self.password_table.filter_entries(self.current_search, self.current_category)
        
        # Update statistics for filtered results
        filtered_count = len(self.password_table.filtered_entries)
        total_count = len(self.password_table.entries)
        
        if filtered_count != total_count:
            self.stats_label.setText(
                f"Showing {filtered_count} of {total_count} entries"
            )
        else:
            self.update_statistics(self.password_table.entries)
            
    def update_statistics(self, entries: List[PasswordEntry]):
        """Update statistics display."""
        if not entries:
            self.stats_label.setText("No password entries")
            return
            
        total_count = len(entries)
        
        # Count by category
        categories = {}
        for entry in entries:
            category = entry.category or "General"
            categories[category] = categories.get(category, 0) + 1
            
        # Recent entries (last 7 days)
        from datetime import datetime, timedelta, timezone
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        recent_count = sum(1 for entry in entries 
                          if entry.updated_at and entry.updated_at >= week_ago)
        
        stats_text = f"""
        <b>Total Entries:</b> {total_count}<br>
        <b>Categories:</b> {len(categories)}<br>
        <b>Recent Updates:</b> {recent_count}
        """
        
        self.stats_label.setText(stats_text)
        
    def get_selected_entry(self) -> Optional[PasswordEntry]:
        """Get currently selected password entry."""
        return self.password_table.get_selected_entry()
        
    def clear_selection(self):
        """Clear current selection."""
        self.password_table.clearSelection()
