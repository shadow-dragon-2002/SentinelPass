"""
Google Drive OAuth authentication module for SentinelPass Password Manager.

This module handles Google Drive OAuth 2.0 authentication flow, token management,
and secure credential storage for Google Drive backup integration.

Security Features:
- OAuth 2.0 authorization code flow
- Secure token storage and refresh
- Automatic token refresh handling
- Credential validation and error handling
- Secure scope management

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import os
import json
import logging
from typing import Optional, Dict, Any, List, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Google OAuth imports
try:
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
    GOOGLE_AUTH_AVAILABLE = True
except ImportError:
    GOOGLE_AUTH_AVAILABLE = False
    logging.warning("Google authentication libraries not available")

from config.settings import settings


class GoogleAuthError(Exception):
    """Custom exception for Google authentication errors."""
    pass


class TokenExpiredError(Exception):
    """Custom exception for expired token errors."""
    pass


class GoogleAuthManager:
    """
    Comprehensive Google Drive OAuth authentication manager.
    
    This class handles all aspects of Google Drive authentication including
    OAuth flow, token management, credential storage, and API service creation.
    """
    
    def __init__(self):
        """Initialize the Google authentication manager."""
        self.logger = logging.getLogger(__name__)
        self.credentials: Optional[Credentials] = None
        self.service = None
        self.scopes = settings.GOOGLE_SCOPES
        self.credentials_file = settings.google_credentials_path
        self.token_file = settings.google_token_path
        
        if not GOOGLE_AUTH_AVAILABLE:
            self.logger.warning("Google authentication not available - missing dependencies")
            
        self.logger.info("GoogleAuthManager initialized")
        
    def is_available(self) -> bool:
        """
        Check if Google authentication is available.
        
        Returns:
            bool: True if Google auth libraries are available
        """
        return GOOGLE_AUTH_AVAILABLE
        
    def has_credentials_file(self) -> bool:
        """
        Check if Google credentials file exists.
        
        Returns:
            bool: True if credentials.json exists
        """
        return Path(self.credentials_file).exists()
        
    def is_authenticated(self) -> bool:
        """
        Check if user is currently authenticated with Google.
        
        Returns:
            bool: True if authenticated with valid credentials
        """
        if not GOOGLE_AUTH_AVAILABLE:
            return False
            
        try:
            # Load existing credentials
            if not self._load_credentials():
                return False
                
            # Check if credentials are valid
            if not self.credentials.valid:
                if self.credentials.expired and self.credentials.refresh_token:
                    # Try to refresh credentials
                    return self._refresh_credentials()
                else:
                    return False
                    
            return True
            
        except Exception as e:
            self.logger.error(f"Authentication check failed: {str(e)}")
            return False
            
    def authenticate(self, force_reauth: bool = False) -> bool:
        """
        Authenticate with Google Drive using OAuth flow.
        
        Args:
            force_reauth (bool): Force re-authentication even if already authenticated
            
        Returns:
            bool: True if authentication successful
            
        Raises:
            GoogleAuthError: If authentication fails
        """
        if not GOOGLE_AUTH_AVAILABLE:
            raise GoogleAuthError("Google authentication not available - missing dependencies")
            
        try:
            # Check if already authenticated and not forcing reauth
            if not force_reauth and self.is_authenticated():
                self.logger.info("Already authenticated with Google Drive")
                return True
                
            # Check for credentials file
            if not self.has_credentials_file():
                raise GoogleAuthError(
                    f"Google credentials file not found at {self.credentials_file}. "
                    "Please download credentials.json from Google Cloud Console and place it in the config directory."
                )
                
            # Load existing token if available
            creds = None
            if Path(self.token_file).exists() and not force_reauth:
                creds = self._load_credentials()
                
            # If no valid credentials, run OAuth flow
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    # Try to refresh
                    if self._refresh_credentials_object(creds):
                        self.credentials = creds
                    else:
                        creds = None
                        
                if not creds:
                    # Run OAuth flow
                    creds = self._run_oauth_flow()
                    
            # Save credentials
            self.credentials = creds
            self._save_credentials()
            
            # Create Drive service
            self._create_drive_service()
            
            self.logger.info("Google Drive authentication successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Google authentication failed: {str(e)}")
            raise GoogleAuthError(f"Authentication failed: {str(e)}")
            
    def _load_credentials(self) -> Optional[Credentials]:
        """Load credentials from token file."""
        try:
            if not Path(self.token_file).exists():
                return None
                
            creds = Credentials.from_authorized_user_file(self.token_file, self.scopes)
            return creds
            
        except Exception as e:
            self.logger.error(f"Failed to load credentials: {str(e)}")
            return None
            
    def _save_credentials(self):
        """Save credentials to token file."""
        try:
            if not self.credentials:
                return
                
            # Ensure config directory exists
            Path(self.token_file).parent.mkdir(parents=True, exist_ok=True)
            
            # Save credentials
            with open(self.token_file, 'w') as token:
                token.write(self.credentials.to_json())
                
            self.logger.info("Credentials saved successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {str(e)}")
            
    def _refresh_credentials(self) -> bool:
        """Refresh current credentials."""
        if not self.credentials:
            return False
            
        return self._refresh_credentials_object(self.credentials)
        
    def _refresh_credentials_object(self, creds: Credentials) -> bool:
        """Refresh credentials object."""
        try:
            creds.refresh(Request())
            self.logger.info("Credentials refreshed successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to refresh credentials: {str(e)}")
            return False
            
    def _run_oauth_flow(self) -> Credentials:
        """Run OAuth 2.0 authorization flow."""
        try:
            flow = InstalledAppFlow.from_client_secrets_file(
                self.credentials_file, 
                self.scopes
            )
            
            # Run local server flow
            creds = flow.run_local_server(
                port=0,
                prompt='consent',
                authorization_prompt_message='Please visit this URL to authorize the application: {url}',
                success_message='Authorization successful! You can close this window.',
                open_browser=True
            )
            
            self.logger.info("OAuth flow completed successfully")
            return creds
            
        except Exception as e:
            self.logger.error(f"OAuth flow failed: {str(e)}")
            raise GoogleAuthError(f"OAuth authorization failed: {str(e)}")
            
    def _create_drive_service(self):
        """Create Google Drive API service."""
        try:
            if not self.credentials:
                raise GoogleAuthError("No valid credentials available")
                
            self.service = build('drive', 'v3', credentials=self.credentials)
            self.logger.info("Google Drive service created successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to create Drive service: {str(e)}")
            raise GoogleAuthError(f"Failed to create Drive service: {str(e)}")
            
    def get_drive_service(self):
        """
        Get Google Drive API service.
        
        Returns:
            Google Drive API service object
            
        Raises:
            GoogleAuthError: If not authenticated or service unavailable
        """
        if not self.is_authenticated():
            raise GoogleAuthError("Not authenticated with Google Drive")
            
        if not self.service:
            self._create_drive_service()
            
        return self.service
        
    def revoke_authentication(self) -> bool:
        """
        Revoke Google authentication and delete stored credentials.
        
        Returns:
            bool: True if revocation successful
        """
        try:
            # Revoke credentials if available
            if self.credentials and self.credentials.valid:
                try:
                    self.credentials.revoke(Request())
                    self.logger.info("Google credentials revoked")
                except Exception as e:
                    self.logger.warning(f"Failed to revoke credentials: {str(e)}")
                    
            # Clear in-memory credentials
            self.credentials = None
            self.service = None
            
            # Delete token file
            token_path = Path(self.token_file)
            if token_path.exists():
                token_path.unlink()
                self.logger.info("Token file deleted")
                
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to revoke authentication: {str(e)}")
            return False
            
    def get_user_info(self) -> Optional[Dict[str, Any]]:
        """
        Get authenticated user information.
        
        Returns:
            Optional[Dict[str, Any]]: User information or None if not available
        """
        try:
            if not self.is_authenticated():
                return None
                
            service = self.get_drive_service()
            about = service.about().get(fields="user").execute()
            
            user_info = about.get('user', {})
            return {
                'display_name': user_info.get('displayName'),
                'email': user_info.get('emailAddress'),
                'photo_link': user_info.get('photoLink')
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get user info: {str(e)}")
            return None
            
    def test_connection(self) -> Tuple[bool, Optional[str]]:
        """
        Test Google Drive connection.
        
        Returns:
            Tuple[bool, Optional[str]]: (success, error_message)
        """
        try:
            if not self.is_authenticated():
                return False, "Not authenticated"
                
            service = self.get_drive_service()
            
            # Try to get about information
            about = service.about().get(fields="storageQuota,user").execute()
            
            user = about.get('user', {})
            quota = about.get('storageQuota', {})
            
            self.logger.info(f"Connection test successful for user: {user.get('emailAddress')}")
            return True, None
            
        except HttpError as e:
            error_msg = f"HTTP error {e.resp.status}: {e.error_details}"
            self.logger.error(f"Connection test failed: {error_msg}")
            return False, error_msg
        except Exception as e:
            error_msg = str(e)
            self.logger.error(f"Connection test failed: {error_msg}")
            return False, error_msg
            
    def get_storage_info(self) -> Optional[Dict[str, Any]]:
        """
        Get Google Drive storage information.
        
        Returns:
            Optional[Dict[str, Any]]: Storage information or None if not available
        """
        try:
            if not self.is_authenticated():
                return None
                
            service = self.get_drive_service()
            about = service.about().get(fields="storageQuota").execute()
            
            quota = about.get('storageQuota', {})
            
            return {
                'limit': int(quota.get('limit', 0)),
                'usage': int(quota.get('usage', 0)),
                'usage_in_drive': int(quota.get('usageInDrive', 0)),
                'usage_in_drive_trash': int(quota.get('usageInDriveTrash', 0))
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get storage info: {str(e)}")
            return None
            
    def get_auth_status(self) -> Dict[str, Any]:
        """
        Get comprehensive authentication status.
        
        Returns:
            Dict[str, Any]: Authentication status information
        """
        status = {
            'available': self.is_available(),
            'has_credentials_file': self.has_credentials_file(),
            'authenticated': False,
            'user_info': None,
            'storage_info': None,
            'credentials_valid': False,
            'credentials_expired': False,
            'last_refresh': None,
            'scopes': self.scopes
        }
        
        if self.is_authenticated():
            status['authenticated'] = True
            status['credentials_valid'] = self.credentials.valid if self.credentials else False
            status['credentials_expired'] = self.credentials.expired if self.credentials else True
            
            if self.credentials and hasattr(self.credentials, 'expiry'):
                status['expires_at'] = self.credentials.expiry.isoformat() if self.credentials.expiry else None
                
            # Get user info
            status['user_info'] = self.get_user_info()
            status['storage_info'] = self.get_storage_info()
            
        return status
        
    def setup_credentials_file(self, credentials_content: str) -> bool:
        """
        Setup credentials file from content.
        
        Args:
            credentials_content (str): JSON content of credentials file
            
        Returns:
            bool: True if setup successful
        """
        try:
            # Validate JSON content
            credentials_data = json.loads(credentials_content)
            
            # Basic validation
            if 'installed' not in credentials_data and 'web' not in credentials_data:
                raise GoogleAuthError("Invalid credentials format")
                
            # Ensure config directory exists
            Path(self.credentials_file).parent.mkdir(parents=True, exist_ok=True)
            
            # Write credentials file
            with open(self.credentials_file, 'w') as f:
                f.write(credentials_content)
                
            self.logger.info("Credentials file setup successfully")
            return True
            
        except json.JSONDecodeError:
            raise GoogleAuthError("Invalid JSON format in credentials")
        except Exception as e:
            self.logger.error(f"Failed to setup credentials file: {str(e)}")
            raise GoogleAuthError(f"Failed to setup credentials: {str(e)}")
            
    def cleanup(self):
        """Cleanup resources and clear credentials."""
        self.credentials = None
        self.service = None
        self.logger.info("GoogleAuthManager cleanup completed")


# Global Google authentication manager instance
google_auth_manager = GoogleAuthManager()
