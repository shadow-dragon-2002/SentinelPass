"""
Modern styling and themes for SentinelPass Password Manager.

This module provides comprehensive styling for the PyQt5 interface including
modern themes, color schemes, and consistent styling across all components.

Features:
- Modern dark and light themes
- Consistent color schemes
- Professional styling for all components
- Responsive design elements
- Custom widget styling

Author: Final Year Project
Date: 2025
License: Educational Use
"""

from typing import Dict, Any
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QPalette, QColor
from PyQt5.QtWidgets import QApplication

from config.settings import settings


class ModernTheme:
    """
    Modern theme configuration for SentinelPass.
    
    Provides color schemes, fonts, and styling constants for
    creating a modern, professional user interface.
    """
    
    # Color Schemes
    DARK_THEME = {
        'primary': '#2C3E50',           # Dark blue-gray
        'primary_light': '#34495E',     # Lighter blue-gray
        'primary_dark': '#1A252F',      # Darker blue-gray
        'secondary': '#3498DB',         # Blue
        'secondary_light': '#5DADE2',   # Light blue
        'secondary_dark': '#2980B9',    # Dark blue
        'accent': '#E74C3C',            # Red
        'accent_light': '#EC7063',      # Light red
        'success': '#27AE60',           # Green
        'warning': '#F39C12',           # Orange
        'danger': '#E74C3C',            # Red
        'background': '#1E1E1E',        # Very dark gray
        'surface': '#2D2D2D',           # Dark gray
        'surface_light': '#3D3D3D',     # Medium gray
        'text_primary': '#FFFFFF',      # White
        'text_secondary': '#B0B0B0',    # Light gray
        'text_disabled': '#666666',     # Medium gray
        'border': '#404040',            # Dark border
        'border_light': '#555555',      # Light border
        'shadow': '#000000',            # Black shadow
        'input_bg': '#2D2D2D',          # Input background
        'input_border': '#404040',      # Input border
        'input_focus': '#3498DB',       # Input focus color
        'button_bg': '#3498DB',         # Button background
        'button_hover': '#5DADE2',      # Button hover
        'button_pressed': '#2980B9',    # Button pressed
        'card_bg': '#2D2D2D',           # Card background
        'card_border': '#404040',       # Card border
        'tooltip_bg': '#1A1A1A',        # Tooltip background
        'tooltip_text': '#FFFFFF',      # Tooltip text
    }
    
    LIGHT_THEME = {
        'primary': '#2C3E50',           # Dark blue-gray
        'primary_light': '#34495E',     # Lighter blue-gray
        'primary_dark': '#1A252F',      # Darker blue-gray
        'secondary': '#3498DB',         # Blue
        'secondary_light': '#5DADE2',   # Light blue
        'secondary_dark': '#2980B9',    # Dark blue
        'accent': '#E74C3C',            # Red
        'accent_light': '#EC7063',      # Light red
        'success': '#27AE60',           # Green
        'warning': '#F39C12',           # Orange
        'danger': '#E74C3C',            # Red
        'background': '#FFFFFF',        # White
        'surface': '#F8F9FA',           # Very light gray
        'surface_light': '#FFFFFF',     # White
        'text_primary': '#2C3E50',      # Dark blue-gray
        'text_secondary': '#6C757D',    # Medium gray
        'text_disabled': '#ADB5BD',     # Light gray
        'border': '#DEE2E6',            # Light border
        'border_light': '#E9ECEF',      # Very light border
        'shadow': '#00000020',          # Light shadow
        'input_bg': '#FFFFFF',          # Input background
        'input_border': '#CED4DA',      # Input border
        'input_focus': '#3498DB',       # Input focus color
        'button_bg': '#3498DB',         # Button background
        'button_hover': '#5DADE2',      # Button hover
        'button_pressed': '#2980B9',    # Button pressed
        'card_bg': '#FFFFFF',           # Card background
        'card_border': '#DEE2E6',       # Card border
        'tooltip_bg': '#212529',        # Tooltip background
        'tooltip_text': '#FFFFFF',      # Tooltip text
    }
    
    # Font Configuration
    FONTS = {
        'primary': 'Segoe UI',
        'secondary': 'Arial',
        'monospace': 'Consolas',
        'fallback': ['Segoe UI', 'Arial', 'sans-serif']
    }
    
    # Size Configuration
    SIZES = {
        'font_small': 9,
        'font_normal': 10,
        'font_medium': 11,
        'font_large': 12,
        'font_xlarge': 14,
        'font_title': 16,
        'font_header': 18,
        'spacing_xs': 4,
        'spacing_sm': 8,
        'spacing_md': 12,
        'spacing_lg': 16,
        'spacing_xl': 24,
        'border_radius': 6,
        'border_width': 1,
        'shadow_blur': 10,
        'icon_small': 16,
        'icon_medium': 24,
        'icon_large': 32,
        'button_height': 32,
        'input_height': 32,
        'toolbar_height': 40,
        'sidebar_width': 250,
    }


class StyleSheetGenerator:
    """
    Generates CSS-like stylesheets for PyQt5 components.
    
    Creates consistent styling across all UI components using
    the defined theme colors and configuration.
    """
    
    def __init__(self, theme_name: str = "dark"):
        """
        Initialize stylesheet generator.
        
        Args:
            theme_name (str): Theme name ("dark" or "light")
        """
        self.theme_name = theme_name
        self.colors = ModernTheme.DARK_THEME if theme_name == "dark" else ModernTheme.LIGHT_THEME
        self.fonts = ModernTheme.FONTS
        self.sizes = ModernTheme.SIZES
        
    def get_main_window_style(self) -> str:
        """Get main window stylesheet."""
        return f"""
        QMainWindow {{
            background-color: {self.colors['background']};
            color: {self.colors['text_primary']};
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
        }}
        
        QMainWindow::separator {{
            background-color: {self.colors['border']};
            width: 1px;
            height: 1px;
        }}
        """
        
    def get_button_style(self) -> str:
        """Get button stylesheet."""
        return f"""
        QPushButton {{
            background-color: {self.colors['button_bg']};
            color: white;
            border: none;
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_sm']}px {self.sizes['spacing_md']}px;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
            font-weight: 500;
            min-height: {self.sizes['button_height']}px;
        }}
        
        QPushButton:hover {{
            background-color: {self.colors['button_hover']};
        }}
        
        QPushButton:pressed {{
            background-color: {self.colors['button_pressed']};
        }}
        
        QPushButton:disabled {{
            background-color: {self.colors['text_disabled']};
            color: {self.colors['background']};
        }}
        
        QPushButton.primary {{
            background-color: {self.colors['secondary']};
        }}
        
        QPushButton.primary:hover {{
            background-color: {self.colors['secondary_light']};
        }}
        
        QPushButton.secondary {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
        }}
        
        QPushButton.secondary:hover {{
            background-color: {self.colors['surface_light']};
        }}
        
        QPushButton.danger {{
            background-color: {self.colors['danger']};
        }}
        
        QPushButton.danger:hover {{
            background-color: {self.colors['accent_light']};
        }}
        
        QPushButton.success {{
            background-color: {self.colors['success']};
        }}
        """
        
    def get_input_style(self) -> str:
        """Get input field stylesheet."""
        return f"""
        QLineEdit, QTextEdit, QPlainTextEdit {{
            background-color: {self.colors['input_bg']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['input_border']};
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_sm']}px;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
            min-height: {self.sizes['input_height']}px;
        }}
        
        QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {{
            border-color: {self.colors['input_focus']};
            outline: none;
        }}
        
        QLineEdit:disabled, QTextEdit:disabled, QPlainTextEdit:disabled {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_disabled']};
            border-color: {self.colors['border']};
        }}
        
        QLineEdit[echoMode="2"] {{
            font-family: {self.fonts['monospace']};
        }}
        """
        
    def get_table_style(self) -> str:
        """Get table/list widget stylesheet."""
        return f"""
        QTableWidget, QListWidget, QTreeWidget {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            gridline-color: {self.colors['border']};
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
            selection-background-color: {self.colors['secondary']};
            selection-color: white;
            alternate-background-color: {self.colors['surface_light']};
        }}
        
        QTableWidget::item, QListWidget::item, QTreeWidget::item {{
            padding: {self.sizes['spacing_sm']}px;
            border: none;
        }}
        
        QTableWidget::item:selected, QListWidget::item:selected, QTreeWidget::item:selected {{
            background-color: {self.colors['secondary']};
            color: white;
        }}
        
        QTableWidget::item:hover, QListWidget::item:hover, QTreeWidget::item:hover {{
            background-color: {self.colors['surface_light']};
        }}
        
        QHeaderView::section {{
            background-color: {self.colors['primary']};
            color: white;
            padding: {self.sizes['spacing_sm']}px;
            border: none;
            font-weight: 600;
        }}
        """
        
    def get_dialog_style(self) -> str:
        """Get dialog stylesheet."""
        return f"""
        QDialog {{
            background-color: {self.colors['background']};
            color: {self.colors['text_primary']};
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
        }}
        
        QDialogButtonBox {{
            background-color: transparent;
        }}
        
        QDialogButtonBox QPushButton {{
            min-width: 80px;
        }}
        """
        
    def get_menu_style(self) -> str:
        """Get menu and menubar stylesheet."""
        return f"""
        QMenuBar {{
            background-color: {self.colors['primary']};
            color: white;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
            border: none;
        }}
        
        QMenuBar::item {{
            background-color: transparent;
            padding: {self.sizes['spacing_sm']}px {self.sizes['spacing_md']}px;
        }}
        
        QMenuBar::item:selected {{
            background-color: {self.colors['primary_light']};
        }}
        
        QMenu {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_xs']}px;
        }}
        
        QMenu::item {{
            padding: {self.sizes['spacing_sm']}px {self.sizes['spacing_md']}px;
            border-radius: {self.sizes['border_radius']}px;
        }}
        
        QMenu::item:selected {{
            background-color: {self.colors['secondary']};
            color: white;
        }}
        
        QMenu::separator {{
            height: 1px;
            background-color: {self.colors['border']};
            margin: {self.sizes['spacing_xs']}px;
        }}
        """
        
    def get_toolbar_style(self) -> str:
        """Get toolbar stylesheet."""
        return f"""
        QToolBar {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            spacing: {self.sizes['spacing_sm']}px;
            padding: {self.sizes['spacing_xs']}px;
        }}
        
        QToolBar::handle {{
            background-color: {self.colors['border']};
            width: 2px;
            margin: {self.sizes['spacing_xs']}px;
        }}
        
        QToolButton {{
            background-color: transparent;
            color: {self.colors['text_primary']};
            border: none;
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_sm']}px;
            min-width: {self.sizes['icon_medium']}px;
            min-height: {self.sizes['icon_medium']}px;
        }}
        
        QToolButton:hover {{
            background-color: {self.colors['surface_light']};
        }}
        
        QToolButton:pressed {{
            background-color: {self.colors['secondary']};
            color: white;
        }}
        """
        
    def get_tab_style(self) -> str:
        """Get tab widget stylesheet."""
        return f"""
        QTabWidget::pane {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
        }}
        
        QTabBar::tab {{
            background-color: {self.colors['background']};
            color: {self.colors['text_secondary']};
            border: 1px solid {self.colors['border']};
            border-bottom: none;
            border-top-left-radius: {self.sizes['border_radius']}px;
            border-top-right-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_sm']}px {self.sizes['spacing_md']}px;
            margin-right: 2px;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_normal']}pt;
        }}
        
        QTabBar::tab:selected {{
            background-color: {self.colors['surface']};
            color: {self.colors['text_primary']};
            border-bottom: 1px solid {self.colors['surface']};
        }}
        
        QTabBar::tab:hover {{
            background-color: {self.colors['surface_light']};
        }}
        """
        
    def get_scrollbar_style(self) -> str:
        """Get scrollbar stylesheet."""
        return f"""
        QScrollBar:vertical {{
            background-color: {self.colors['surface']};
            width: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:vertical {{
            background-color: {self.colors['border_light']};
            border-radius: 6px;
            min-height: 20px;
        }}
        
        QScrollBar::handle:vertical:hover {{
            background-color: {self.colors['text_disabled']};
        }}
        
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
            height: 0px;
        }}
        
        QScrollBar:horizontal {{
            background-color: {self.colors['surface']};
            height: 12px;
            border-radius: 6px;
        }}
        
        QScrollBar::handle:horizontal {{
            background-color: {self.colors['border_light']};
            border-radius: 6px;
            min-width: 20px;
        }}
        
        QScrollBar::handle:horizontal:hover {{
            background-color: {self.colors['text_disabled']};
        }}
        
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
            width: 0px;
        }}
        """
        
    def get_card_style(self) -> str:
        """Get card/frame stylesheet."""
        return f"""
        QFrame.card {{
            background-color: {self.colors['card_bg']};
            border: 1px solid {self.colors['card_border']};
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_md']}px;
        }}
        
        QGroupBox {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_medium']}pt;
            font-weight: 600;
            color: {self.colors['text_primary']};
            margin-top: {self.sizes['spacing_md']}px;
            padding-top: {self.sizes['spacing_md']}px;
        }}
        
        QGroupBox::title {{
            subcontrol-origin: margin;
            left: {self.sizes['spacing_md']}px;
            padding: 0 {self.sizes['spacing_sm']}px 0 {self.sizes['spacing_sm']}px;
        }}
        """
        
    def get_tooltip_style(self) -> str:
        """Get tooltip stylesheet."""
        return f"""
        QToolTip {{
            background-color: {self.colors['tooltip_bg']};
            color: {self.colors['tooltip_text']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            padding: {self.sizes['spacing_sm']}px;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_small']}pt;
        }}
        """
        
    def get_progress_style(self) -> str:
        """Get progress bar stylesheet."""
        return f"""
        QProgressBar {{
            background-color: {self.colors['surface']};
            border: 1px solid {self.colors['border']};
            border-radius: {self.sizes['border_radius']}px;
            text-align: center;
            font-family: {self.fonts['primary']};
            font-size: {self.sizes['font_small']}pt;
            color: {self.colors['text_primary']};
        }}
        
        QProgressBar::chunk {{
            background-color: {self.colors['secondary']};
            border-radius: {self.sizes['border_radius']}px;
        }}
        """
        
    def get_complete_stylesheet(self) -> str:
        """Get complete application stylesheet."""
        return "\n".join([
            self.get_main_window_style(),
            self.get_button_style(),
            self.get_input_style(),
            self.get_table_style(),
            self.get_dialog_style(),
            self.get_menu_style(),
            self.get_toolbar_style(),
            self.get_tab_style(),
            self.get_scrollbar_style(),
            self.get_card_style(),
            self.get_tooltip_style(),
            self.get_progress_style()
        ])


class ThemeManager:
    """
    Theme management for the application.
    
    Manages theme switching, persistence, and application
    of themes across the entire application.
    """
    
    def __init__(self):
        """Initialize theme manager."""
        self.current_theme = settings.DEFAULT_THEME
        self.stylesheet_generator = StyleSheetGenerator(self.current_theme)
        
    def set_theme(self, theme_name: str):
        """
        Set application theme.
        
        Args:
            theme_name (str): Theme name ("dark" or "light")
        """
        if theme_name in ["dark", "light"]:
            self.current_theme = theme_name
            self.stylesheet_generator = StyleSheetGenerator(theme_name)
            
    def apply_theme(self, app: QApplication):
        """
        Apply current theme to application.
        
        Args:
            app (QApplication): Application instance
        """
        stylesheet = self.stylesheet_generator.get_complete_stylesheet()
        app.setStyleSheet(stylesheet)
        
        # Set application font
        font = QFont(ModernTheme.FONTS['primary'], ModernTheme.SIZES['font_normal'])
        app.setFont(font)
        
    def get_color(self, color_name: str) -> str:
        """
        Get color value from current theme.
        
        Args:
            color_name (str): Color name
            
        Returns:
            str: Color value
        """
        colors = (ModernTheme.DARK_THEME if self.current_theme == "dark" 
                 else ModernTheme.LIGHT_THEME)
        return colors.get(color_name, '#000000')
        
    def get_available_themes(self) -> list:
        """Get list of available themes."""
        return ["dark", "light"]


# Global theme manager instance
theme_manager = ThemeManager()
