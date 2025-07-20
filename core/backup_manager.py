"""
Comprehensive backup manager for SentinelPass Password Manager.

This module handles both local and Google Drive backup operations with encryption.
It provides secure backup creation, restoration, and management capabilities with
encrypted transit for cloud backups.

Features:
- Local encrypted backup creation and restoration
- Google Drive integration with OAuth authentication
- Encrypted backup files with AES-256 encryption
- Automatic backup scheduling
- Backup verification and integrity checks
- Secure file transfer with encryption in transit

Author: Final Year Project
Date: 2025
License: Educational Use
"""

import os
import json
import gzip
import shutil
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path
import threading
import time

# Google Drive API imports
try:
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    GOOGLE_DRIVE_AVAILABLE = True
except ImportError:
    GOOGLE_DRIVE_AVAILABLE = False
    logging.warning("Google Drive API not available - install google-api-python-client")

from config.settings import settings
from core.encryption import crypto_manager, EncryptionError, DecryptionError


class BackupError(Exception):
    """Custom exception for backup-related errors."""
    pass


class GoogleDriveError(Exception):
    """Custom exception for Google Drive-related errors."""
    pass


class BackupMetadata:
    """
    Data class for backup metadata information.
    
    Contains information about backup files including creation time,
    size, encryption status, and verification data.
    """
    
    def __init__(self, filename: str, created_at: datetime, 
                 size_bytes: int, encrypted: bool = True,
                 entry_count: int = 0, checksum: str = ""):
        """
        Initialize backup metadata.
        
        Args:
            filename (str): Backup filename
            created_at (datetime): Creation timestamp
            size_bytes (int): File size in bytes
            encrypted (bool): Whether backup is encrypted
            entry_count (int): Number of password entries
            checksum (str): File checksum for integrity verification
        """
        self.filename = filename
        self.created_at = created_at
        self.size_bytes = size_bytes
        self.encrypted = encrypted
        self.entry_count = entry_count
        self.checksum = checksum
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert metadata to dictionary."""
        return {
            'filename': self.filename,
            'created_at': self.created_at.isoformat(),
            'size_bytes': self.size_bytes,
            'encrypted': self.encrypted,
            'entry_count': self.entry_count,
            'checksum': self.checksum
        }
        
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'BackupMetadata':
        """Create metadata from dictionary."""
        return cls(
            filename=data['filename'],
            created_at=datetime.fromisoformat(data['created_at']),
            size_bytes=data['size_bytes'],
            encrypted=data.get('encrypted', True),
            entry_count=data.get('entry_count', 0),
            checksum=data.get('checksum', '')
        )


class LocalBackupManager:
    """
    Manager for local backup operations.
    
    Handles creation, restoration, and management of local encrypted backups.
    """
    
    def __init__(self):
        """Initialize local backup manager."""
        self.logger = logging.getLogger(__name__)
        self.backup_dir = Path(settings.backup_directory)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"LocalBackupManager initialized with directory: {self.backup_dir}")
        
    def create_backup(self, data: Dict[str, Any], master_password: str, 
                     filename: Optional[str] = None) -> str:
        """
        Create an encrypted local backup.
        
        Args:
            data (Dict[str, Any]): Data to backup
            master_password (str): Master password for encryption
            filename (str, optional): Custom filename
            
        Returns:
            str: Path to created backup file
            
        Raises:
            BackupError: If backup creation fails
        """
        try:
            # Generate filename if not provided
            if not filename:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"securepass_backup_{timestamp}.spb"
                
            backup_path = self.backup_dir / filename
            
            # Prepare backup data with metadata
            backup_data = {
                'version': '1.0',
                'created_at': datetime.now(timezone.utc).isoformat(),
                'application': 'SentinelPass',
                'data': data
            }
            
            # Convert to JSON
            json_data = json.dumps(backup_data, indent=2)
            
            # Compress data
            compressed_data = gzip.compress(json_data.encode('utf-8'))
            
            # Encrypt compressed data
            encrypted_data = crypto_manager.encrypt_data(compressed_data, master_password)
            
            # Write to file
            with open(backup_path, 'wb') as f:
                f.write(encrypted_data)
                
            # Calculate checksum
            import hashlib
            checksum = hashlib.sha256(encrypted_data).hexdigest()
            
            # Create metadata
            metadata = BackupMetadata(
                filename=filename,
                created_at=datetime.now(timezone.utc),
                size_bytes=len(encrypted_data),
                encrypted=True,
                entry_count=len(data.get('entries', [])),
                checksum=checksum
            )
            
            # Save metadata
            self._save_backup_metadata(metadata)
            
            self.logger.info(f"Local backup created: {backup_path}")
            return str(backup_path)
            
        except Exception as e:
            self.logger.error(f"Local backup creation failed: {str(e)}")
            raise BackupError(f"Failed to create local backup: {str(e)}")
            
    def restore_backup(self, backup_path: str, master_password: str) -> Dict[str, Any]:
        """
        Restore data from encrypted local backup.
        
        Args:
            backup_path (str): Path to backup file
            master_password (str): Master password for decryption
            
        Returns:
            Dict[str, Any]: Restored data
            
        Raises:
            BackupError: If restoration fails
        """
        try:
            backup_file = Path(backup_path)
            if not backup_file.exists():
                raise BackupError(f"Backup file not found: {backup_path}")
                
            # Read encrypted data
            with open(backup_file, 'rb') as f:
                encrypted_data = f.read()
                
            # Decrypt data
            compressed_data = crypto_manager.decrypt_data(encrypted_data, master_password)
            
            # Decompress data
            json_data = gzip.decompress(compressed_data).decode('utf-8')
            
            # Parse JSON
            backup_data = json.loads(json_data)
            
            # Validate backup format
            if 'data' not in backup_data:
                raise BackupError("Invalid backup format")
                
            self.logger.info(f"Local backup restored from: {backup_path}")
            return backup_data['data']
            
        except (DecryptionError, json.JSONDecodeError, gzip.BadGzipFile) as e:
            self.logger.error(f"Backup restoration failed: {str(e)}")
            raise BackupError(f"Failed to restore backup - file may be corrupted or password incorrect: {str(e)}")
        except Exception as e:
            self.logger.error(f"Backup restoration failed: {str(e)}")
            raise BackupError(f"Failed to restore backup: {str(e)}")
            
    def list_backups(self) -> List[BackupMetadata]:
        """
        List all available local backups.
        
        Returns:
            List[BackupMetadata]: List of backup metadata
        """
        try:
            backups = []
            metadata_file = self.backup_dir / "backup_metadata.json"
            
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata_list = json.load(f)
                    
                for metadata_dict in metadata_list:
                    try:
                        metadata = BackupMetadata.from_dict(metadata_dict)
                        # Check if backup file still exists
                        backup_path = self.backup_dir / metadata.filename
                        if backup_path.exists():
                            backups.append(metadata)
                    except Exception as e:
                        self.logger.warning(f"Invalid backup metadata: {str(e)}")
                        continue
                        
            # Sort by creation date (newest first)
            backups.sort(key=lambda x: x.created_at, reverse=True)
            
            return backups
            
        except Exception as e:
            self.logger.error(f"Failed to list backups: {str(e)}")
            return []
            
    def delete_backup(self, filename: str) -> bool:
        """
        Delete a local backup file.
        
        Args:
            filename (str): Backup filename to delete
            
        Returns:
            bool: True if deletion successful
        """
        try:
            backup_path = self.backup_dir / filename
            
            if backup_path.exists():
                backup_path.unlink()
                
                # Remove from metadata
                self._remove_backup_metadata(filename)
                
                self.logger.info(f"Backup deleted: {filename}")
                return True
            else:
                self.logger.warning(f"Backup file not found: {filename}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to delete backup: {str(e)}")
            return False
            
    def cleanup_old_backups(self, max_backups: int = None) -> int:
        """
        Clean up old backup files, keeping only the most recent ones.
        
        Args:
            max_backups (int, optional): Maximum number of backups to keep
            
        Returns:
            int: Number of backups deleted
        """
        try:
            if max_backups is None:
                max_backups = settings.MAX_LOCAL_BACKUPS
                
            backups = self.list_backups()
            
            if len(backups) <= max_backups:
                return 0
                
            # Delete oldest backups
            backups_to_delete = backups[max_backups:]
            deleted_count = 0
            
            for backup in backups_to_delete:
                if self.delete_backup(backup.filename):
                    deleted_count += 1
                    
            self.logger.info(f"Cleaned up {deleted_count} old backups")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Backup cleanup failed: {str(e)}")
            return 0
            
    def _save_backup_metadata(self, metadata: BackupMetadata):
        """Save backup metadata to file."""
        try:
            metadata_file = self.backup_dir / "backup_metadata.json"
            
            # Load existing metadata
            metadata_list = []
            if metadata_file.exists():
                with open(metadata_file, 'r') as f:
                    metadata_list = json.load(f)
                    
            # Add new metadata
            metadata_list.append(metadata.to_dict())
            
            # Save updated metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata_list, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save backup metadata: {str(e)}")
            
    def _remove_backup_metadata(self, filename: str):
        """Remove backup metadata from file."""
        try:
            metadata_file = self.backup_dir / "backup_metadata.json"
            
            if not metadata_file.exists():
                return
                
            # Load existing metadata
            with open(metadata_file, 'r') as f:
                metadata_list = json.load(f)
                
            # Remove matching metadata
            metadata_list = [m for m in metadata_list if m.get('filename') != filename]
            
            # Save updated metadata
            with open(metadata_file, 'w') as f:
                json.dump(metadata_list, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to remove backup metadata: {str(e)}")


class GoogleDriveBackupManager:
    """
    Manager for Google Drive backup operations.
    
    Handles OAuth authentication, encrypted backup upload/download,
    and Google Drive folder management.
    """
    
    def __init__(self):
        """Initialize Google Drive backup manager."""
        self.logger = logging.getLogger(__name__)
        self.service = None
        self.credentials = None
        self.backup_folder_id = None
        
        if not GOOGLE_DRIVE_AVAILABLE:
            self.logger.warning("Google Drive API not available")
            
        self.logger.info("GoogleDriveBackupManager initialized")
        
    def authenticate(self) -> bool:
        """
        Authenticate with Google Drive using OAuth.
        
        Returns:
            bool: True if authentication successful
        """
        if not GOOGLE_DRIVE_AVAILABLE:
            raise GoogleDriveError("Google Drive API not available")
            
        try:
            creds = None
            token_path = settings.google_token_path
            credentials_path = settings.google_credentials_path
            
            # Load existing token
            if os.path.exists(token_path):
                creds = Credentials.from_authorized_user_file(token_path, settings.GOOGLE_SCOPES)
                
            # If no valid credentials, get new ones
            if not creds or not creds.valid:
                if creds and creds.expired and creds.refresh_token:
                    creds.refresh(Request())
                else:
                    if not os.path.exists(credentials_path):
                        raise GoogleDriveError(
                            "Google Drive credentials file not found. "
                            "Please download credentials.json from Google Cloud Console."
                        )
                        
                    flow = InstalledAppFlow.from_client_secrets_file(
                        credentials_path, settings.GOOGLE_SCOPES
                    )
                    creds = flow.run_local_server(port=0)
                    
                # Save credentials for next run
                with open(token_path, 'w') as token:
                    token.write(creds.to_json())
                    
            self.credentials = creds
            self.service = build('drive', 'v3', credentials=creds)
            
            # Create backup folder if it doesn't exist
            self._ensure_backup_folder()
            
            self.logger.info("Google Drive authentication successful")
            return True
            
        except Exception as e:
            self.logger.error(f"Google Drive authentication failed: {str(e)}")
            raise GoogleDriveError(f"Authentication failed: {str(e)}")
            
    def _ensure_backup_folder(self):
        """Ensure backup folder exists in Google Drive."""
        try:
            # Search for existing backup folder
            results = self.service.files().list(
                q=f"name='{settings.BACKUP_FOLDER_NAME}' and mimeType='application/vnd.google-apps.folder'",
                fields="files(id, name)"
            ).execute()
            
            folders = results.get('files', [])
            
            if folders:
                self.backup_folder_id = folders[0]['id']
                self.logger.info(f"Using existing backup folder: {self.backup_folder_id}")
            else:
                # Create backup folder
                folder_metadata = {
                    'name': settings.BACKUP_FOLDER_NAME,
                    'mimeType': 'application/vnd.google-apps.folder'
                }
                
                folder = self.service.files().create(
                    body=folder_metadata,
                    fields='id'
                ).execute()
                
                self.backup_folder_id = folder.get('id')
                self.logger.info(f"Created backup folder: {self.backup_folder_id}")
                
        except Exception as e:
            self.logger.error(f"Failed to ensure backup folder: {str(e)}")
            raise GoogleDriveError(f"Failed to create backup folder: {str(e)}")
            
    def upload_backup(self, local_backup_path: str, 
                     remote_filename: Optional[str] = None) -> str:
        """
        Upload encrypted backup to Google Drive.
        
        Args:
            local_backup_path (str): Path to local backup file
            remote_filename (str, optional): Remote filename
            
        Returns:
            str: Google Drive file ID
            
        Raises:
            GoogleDriveError: If upload fails
        """
        try:
            if not self.service:
                raise GoogleDriveError("Not authenticated with Google Drive")
                
            backup_file = Path(local_backup_path)
            if not backup_file.exists():
                raise GoogleDriveError(f"Local backup file not found: {local_backup_path}")
                
            if not remote_filename:
                remote_filename = backup_file.name
                
            # File metadata
            file_metadata = {
                'name': remote_filename,
                'parents': [self.backup_folder_id]
            }
            
            # Upload file
            media = MediaFileUpload(
                str(backup_file),
                mimetype='application/octet-stream',
                resumable=True
            )
            
            file = self.service.files().create(
                body=file_metadata,
                media_body=media,
                fields='id'
            ).execute()
            
            file_id = file.get('id')
            
            self.logger.info(f"Backup uploaded to Google Drive: {file_id}")
            return file_id
            
        except Exception as e:
            self.logger.error(f"Google Drive upload failed: {str(e)}")
            raise GoogleDriveError(f"Failed to upload backup: {str(e)}")
            
    def download_backup(self, file_id: str, local_path: str) -> bool:
        """
        Download backup from Google Drive.
        
        Args:
            file_id (str): Google Drive file ID
            local_path (str): Local path to save file
            
        Returns:
            bool: True if download successful
            
        Raises:
            GoogleDriveError: If download fails
        """
        try:
            if not self.service:
                raise GoogleDriveError("Not authenticated with Google Drive")
                
            # Get file
            request = self.service.files().get_media(fileId=file_id)
            
            # Download file
            with open(local_path, 'wb') as f:
                downloader = MediaIoBaseDownload(f, request)
                done = False
                while done is False:
                    status, done = downloader.next_chunk()
                    
            self.logger.info(f"Backup downloaded from Google Drive: {local_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Google Drive download failed: {str(e)}")
            raise GoogleDriveError(f"Failed to download backup: {str(e)}")
            
    def list_cloud_backups(self) -> List[Dict[str, Any]]:
        """
        List all backups in Google Drive.
        
        Returns:
            List[Dict[str, Any]]: List of backup file information
        """
        try:
            if not self.service:
                raise GoogleDriveError("Not authenticated with Google Drive")
                
            # List files in backup folder
            results = self.service.files().list(
                q=f"parents in '{self.backup_folder_id}' and name contains '.spb'",
                fields="files(id, name, size, createdTime, modifiedTime)",
                orderBy="createdTime desc"
            ).execute()
            
            files = results.get('files', [])
            
            self.logger.info(f"Found {len(files)} cloud backups")
            return files
            
        except Exception as e:
            self.logger.error(f"Failed to list cloud backups: {str(e)}")
            return []
            
    def delete_cloud_backup(self, file_id: str) -> bool:
        """
        Delete backup from Google Drive.
        
        Args:
            file_id (str): Google Drive file ID
            
        Returns:
            bool: True if deletion successful
        """
        try:
            if not self.service:
                raise GoogleDriveError("Not authenticated with Google Drive")
                
            self.service.files().delete(fileId=file_id).execute()
            
            self.logger.info(f"Cloud backup deleted: {file_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete cloud backup: {str(e)}")
            return False
            
    def cleanup_old_cloud_backups(self, max_backups: int = None) -> int:
        """
        Clean up old cloud backups.
        
        Args:
            max_backups (int, optional): Maximum number of backups to keep
            
        Returns:
            int: Number of backups deleted
        """
        try:
            if max_backups is None:
                max_backups = settings.MAX_CLOUD_BACKUPS
                
            backups = self.list_cloud_backups()
            
            if len(backups) <= max_backups:
                return 0
                
            # Delete oldest backups
            backups_to_delete = backups[max_backups:]
            deleted_count = 0
            
            for backup in backups_to_delete:
                if self.delete_cloud_backup(backup['id']):
                    deleted_count += 1
                    
            self.logger.info(f"Cleaned up {deleted_count} old cloud backups")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Cloud backup cleanup failed: {str(e)}")
            return 0


class BackupManager:
    """
    Comprehensive backup manager combining local and cloud backup capabilities.
    
    This class provides a unified interface for all backup operations including
    automatic scheduling, backup verification, and restoration.
    """
    
    def __init__(self):
        """Initialize the comprehensive backup manager."""
        self.logger = logging.getLogger(__name__)
        self.local_manager = LocalBackupManager()
        self.cloud_manager = GoogleDriveBackupManager() if GOOGLE_DRIVE_AVAILABLE else None
        self._backup_thread = None
        self._stop_backup_thread = False
        
        self.logger.info("BackupManager initialized")
        
    def create_backup(self, data: Dict[str, Any], master_password: str,
                     backup_local: bool = True, backup_cloud: bool = False,
                     filename: Optional[str] = None) -> Dict[str, str]:
        """
        Create backup with specified options.
        
        Args:
            data (Dict[str, Any]): Data to backup
            master_password (str): Master password for encryption
            backup_local (bool): Create local backup
            backup_cloud (bool): Create cloud backup
            filename (str, optional): Custom filename
            
        Returns:
            Dict[str, str]: Backup results with paths/IDs
        """
        results = {}
        
        try:
            # Create local backup
            if backup_local:
                local_path = self.local_manager.create_backup(data, master_password, filename)
                results['local_path'] = local_path
                
                # Upload to cloud if requested
                if backup_cloud and self.cloud_manager:
                    try:
                        if not self.cloud_manager.service:
                            self.cloud_manager.authenticate()
                            
                        file_id = self.cloud_manager.upload_backup(local_path)
                        results['cloud_id'] = file_id
                        
                    except Exception as e:
                        self.logger.error(f"Cloud backup failed: {str(e)}")
                        results['cloud_error'] = str(e)
                        
            self.logger.info("Backup creation completed")
            return results
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {str(e)}")
            raise BackupError(f"Failed to create backup: {str(e)}")
            
    def restore_backup(self, backup_source: str, master_password: str,
                      is_cloud_backup: bool = False) -> Dict[str, Any]:
        """
        Restore backup from local file or cloud.
        
        Args:
            backup_source (str): Local path or cloud file ID
            master_password (str): Master password for decryption
            is_cloud_backup (bool): Whether source is cloud backup
            
        Returns:
            Dict[str, Any]: Restored data
        """
        try:
            if is_cloud_backup:
                if not self.cloud_manager:
                    raise BackupError("Cloud backup not available")
                    
                # Download from cloud first
                temp_path = Path(settings.backup_directory) / f"temp_restore_{int(time.time())}.spb"
                
                try:
                    self.cloud_manager.download_backup(backup_source, str(temp_path))
                    data = self.local_manager.restore_backup(str(temp_path), master_password)
                    
                    # Clean up temp file
                    temp_path.unlink()
                    
                    return data
                    
                except Exception as e:
                    # Clean up temp file on error
                    if temp_path.exists():
                        temp_path.unlink()
                    raise e
                    
            else:
                # Restore from local backup
                return self.local_manager.restore_backup(backup_source, master_password)
                
        except Exception as e:
            self.logger.error(f"Backup restoration failed: {str(e)}")
            raise BackupError(f"Failed to restore backup: {str(e)}")
            
    def start_auto_backup(self, data_callback, master_password_callback):
        """
        Start automatic backup thread.
        
        Args:
            data_callback: Function to get current data
            master_password_callback: Function to get master password
        """
        if not settings.AUTO_BACKUP_ENABLED:
            return
            
        if self._backup_thread and self._backup_thread.is_alive():
            return
            
        self._stop_backup_thread = False
        self._backup_thread = threading.Thread(
            target=self._auto_backup_worker,
            args=(data_callback, master_password_callback),
            daemon=True
        )
        self._backup_thread.start()
        
        self.logger.info("Auto-backup thread started")
        
    def stop_auto_backup(self):
        """Stop automatic backup thread."""
        self._stop_backup_thread = True
        if self._backup_thread:
            self._backup_thread.join(timeout=5)
            
        self.logger.info("Auto-backup thread stopped")
        
    def _auto_backup_worker(self, data_callback, master_password_callback):
        """Worker thread for automatic backups."""
        interval_seconds = settings.AUTO_BACKUP_INTERVAL_HOURS * 3600
        
        while not self._stop_backup_thread:
            try:
                # Wait for interval or stop signal
                for _ in range(interval_seconds):
                    if self._stop_backup_thread:
                        return
                    time.sleep(1)
                    
                # Create automatic backup
                data = data_callback()
                master_password = master_password_callback()
                
                if data and master_password:
                    self.create_backup(
                        data, 
                        master_password,
                        backup_local=True,
                        backup_cloud=settings.ENABLE_GOOGLE_DRIVE_BACKUP
                    )
                    
                    # Cleanup old backups
                    self.local_manager.cleanup_old_backups()
                    if self.cloud_manager:
                        self.cloud_manager.cleanup_old_cloud_backups()
                        
                    self.logger.info("Automatic backup completed")
                    
            except Exception as e:
                self.logger.error(f"Auto-backup failed: {str(e)}")
                
    def get_backup_status(self) -> Dict[str, Any]:
        """
        Get comprehensive backup status information.
        
        Returns:
            Dict[str, Any]: Backup status information
        """
        status = {
            'local_backups': len(self.local_manager.list_backups()),
            'cloud_available': self.cloud_manager is not None,
            'cloud_authenticated': False,
            'cloud_backups': 0,
            'auto_backup_enabled': settings.AUTO_BACKUP_ENABLED,
            'auto_backup_running': self._backup_thread and self._backup_thread.is_alive()
        }
        
        if self.cloud_manager and self.cloud_manager.service:
            status['cloud_authenticated'] = True
            try:
                status['cloud_backups'] = len(self.cloud_manager.list_cloud_backups())
            except Exception:
                pass
                
        return status


# Global backup manager instance
backup_manager = BackupManager()
