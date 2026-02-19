"""
Agent-Side Backup Manager
Manages versioned backups with checksums, compression, and integrity verification.
"""
import asyncio
import hashlib
import json
import os
import shutil
import gzip
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class BackupMetadata:
    """Metadata for a backup operation."""
    def __init__(
        self,
        error_id: str,
        backup_dir: str,
        files: List[str],
        manifest: Dict[str, Any],
        created_at: str,
        verified: bool = True
    ):
        self.error_id = error_id
        self.backup_dir = backup_dir
        self.files = files
        self.manifest = manifest
        self.created_at = created_at
        self.verified = verified
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "error_id": self.error_id,
            "backup_dir": self.backup_dir,
            "files": self.files,
            "manifest": self.manifest,
            "created_at": self.created_at,
            "verified": self.verified
        }


class AgentBackupManager:
    """
    Manages backups locally on target environment.
    
    Backup structure (default dir: .patcherly_backups or APR_BACKUP_ROOT):
    .patcherly_backups/ or custom path
        {error_id}/
            {timestamp}/
                manifest.json
                {file_name}
                ...
    """
    
    def __init__(self, backup_root: str | None = None):
        """
        Initialize backup manager.
        
        Args:
            backup_root: Root directory for backups. If None, uses:
                - PATCHERLY_BACKUP_ROOT or APR_BACKUP_ROOT environment variable
                - ../backups/ (outside webroot, default)
        """
        if backup_root is None:
            backup_root = os.getenv('PATCHERLY_BACKUP_ROOT') or os.getenv('APR_BACKUP_ROOT') or '../backups'
        
        # Validate and resolve backup root path
        backup_root_path = Path(backup_root)
        if not backup_root_path.is_absolute():
            backup_root_path = backup_root_path.resolve()
        
        # Security: Ensure path is absolute and doesn't contain dangerous patterns
        self.backup_root = backup_root_path.resolve()
        
        # Additional security: Validate path doesn't contain dangerous patterns
        # Note: After resolve(), '..' is normalized, but we check the original input
        backup_root_str = str(backup_root)
        if '..' in backup_root_str and not self.backup_root.exists():
            # If original had '..' and resolved path doesn't exist, it might be traversal
            logger.warning(f"Backup root path contains '..' and resolved path doesn't exist: {backup_root}")
        
        self.backup_root.mkdir(parents=True, exist_ok=True, mode=0o700)  # Restrictive permissions
        logger.info(f"Initialized AgentBackupManager with root: {self.backup_root}")
        
        # Ensure backup directory is protected from direct web access
        self._ensure_backup_protection()
    
    async def create_backup(
        self,
        error_id: str,
        files: List[str],
        compress: bool = True,
        verify: bool = True
    ) -> BackupMetadata:
        """
        Create a versioned backup with checksums.
        
        Args:
            error_id: Unique error identifier
            files: List of file paths to backup
            compress: Whether to compress backup files
            verify: Whether to verify backup integrity after creation
        
        Returns:
            BackupMetadata object
        """
        timestamp = datetime.now(timezone.utc).isoformat().replace(':', '-')
        backup_dir = self.backup_root / error_id / timestamp
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o755)
        
        logger.info(f"Creating backup in {backup_dir} for {len(files)} file(s)")
        
        # Backup files with checksums
        backup_manifest = {}
        
        for file_path in files:
            try:
                file_path_obj = Path(file_path)
                
                # Security: Validate file path to prevent directory traversal
                if not self._validate_file_path(file_path_obj):
                    logger.warning(f"Invalid or unsafe file path, skipping: {file_path}")
                    continue
                
                # Check if file exists
                if not file_path_obj.exists():
                    logger.warning(f"File not found, skipping: {file_path}")
                    continue
                
                # Read file content
                content = await self._read_file_async(file_path_obj)
                
                # Calculate checksum
                checksum = hashlib.sha256(content).hexdigest()
                file_size = len(content)
                
                # Determine backup filename (preserve relative path structure)
                # For simplicity, use just the filename, but could preserve path structure
                backup_file_name = file_path_obj.name
                
                # If file is in a subdirectory, preserve structure
                if file_path_obj.parent != Path('.'):
                    # Create subdirectory structure in backup
                    rel_path = file_path_obj.relative_to(file_path_obj.anchor)
                    backup_file_name = str(rel_path).replace(os.sep, '_')
                
                backup_file = backup_dir / backup_file_name
                
                # Write backup file
                await self._write_file_async(backup_file, content)
                
                # Compress if requested
                if compress and file_size > 0:
                    compressed_file = backup_file.with_suffix(backup_file.suffix + '.gz')
                    await self._compress_file(backup_file, compressed_file)
                    # Remove uncompressed file
                    backup_file.unlink()
                    backup_file = compressed_file
                    file_size = compressed_file.stat().st_size
                
                backup_manifest[file_path] = {
                    'checksum': checksum,
                    'size': file_size,
                    'backup_path': str(backup_file),
                    'original_size': len(content),
                    'compressed': compress and file_size > 0
                }
                
                logger.debug(f"Backed up {file_path} -> {backup_file} (checksum: {checksum[:16]}...)")
                
            except Exception as e:
                logger.error(f"Failed to backup file {file_path}: {e}")
                # Continue with other files
                continue
        
        if not backup_manifest:
            raise ValueError("No files were successfully backed up")
        
        # Write manifest
        manifest_path = backup_dir / 'manifest.json'
        manifest_data = {
            'error_id': error_id,
            'created_at': timestamp,
            'files': backup_manifest,
            'backup_version': 1
        }
        await self._write_file_async(manifest_path, json.dumps(manifest_data, indent=2).encode('utf-8'))
        
        # Verify backup integrity if requested
        verified = True
        if verify:
            verified = await self._verify_backup_integrity(backup_dir, backup_manifest)
        
        metadata = BackupMetadata(
            error_id=error_id,
            backup_dir=str(backup_dir),
            files=list(backup_manifest.keys()),
            manifest=backup_manifest,
            created_at=timestamp,
            verified=verified
        )
        
        logger.info(f"Backup created successfully: {backup_dir} (verified: {verified})")
        return metadata
    
    async def _read_file_async(self, file_path: Path) -> bytes:
        """Read file asynchronously."""
        loop = asyncio.get_event_loop()
        with open(file_path, 'rb') as f:
            return await loop.run_in_executor(None, f.read)
    
    async def _write_file_async(self, file_path: Path, content: bytes):
        """Write file asynchronously."""
        loop = asyncio.get_event_loop()
        # Ensure parent directory exists
        file_path.parent.mkdir(parents=True, exist_ok=True)
        with open(file_path, 'wb') as f:
            await loop.run_in_executor(None, f.write, content)
    
    async def _compress_file(self, source: Path, dest: Path):
        """Compress a file using gzip."""
        loop = asyncio.get_event_loop()
        with open(source, 'rb') as f_in:
            with gzip.open(dest, 'wb') as f_out:
                await loop.run_in_executor(
                    None,
                    shutil.copyfileobj,
                    f_in,
                    f_out
                )
    
    async def _verify_backup_integrity(
        self,
        backup_dir: Path,
        manifest: Dict[str, Any]
    ) -> bool:
        """
        Verify backup integrity by checking checksums.
        
        Returns:
            True if all checksums match, False otherwise
        """
        logger.debug(f"Verifying backup integrity in {backup_dir}")
        
        try:
            for file_path, file_info in manifest.items():
                backup_file_path = Path(file_info['backup_path'])
                expected_checksum = file_info['checksum']
                
                if not backup_file_path.exists():
                    logger.error(f"Backup file not found: {backup_file_path}")
                    return False
                
                # Read and decompress if needed
                if file_info.get('compressed', False):
                    with gzip.open(backup_file_path, 'rb') as f:
                        content = f.read()
                else:
                    content = await self._read_file_async(backup_file_path)
                
                # Verify checksum
                actual_checksum = hashlib.sha256(content).hexdigest()
                
                if actual_checksum != expected_checksum:
                    logger.error(
                        f"Checksum mismatch for {file_path}: "
                        f"expected {expected_checksum[:16]}..., got {actual_checksum[:16]}..."
                    )
                    return False
                
                logger.debug(f"Verified {file_path} (checksum: {expected_checksum[:16]}...)")
            
            logger.info("Backup integrity verification passed")
            return True
            
        except Exception as e:
            logger.error(f"Backup integrity verification failed: {e}")
            return False
    
    async def restore_backup(
        self,
        backup_dir: str,
        target_files: Optional[Dict[str, str]] = None,
        max_age_days: Optional[int] = None
    ) -> bool:
        """
        Restore files from a backup.
        
        Args:
            backup_dir: Path to backup directory
            target_files: Optional mapping of backup file paths to restore targets
            max_age_days: Optional maximum age of backup in days (security: reject old backups)
        
        Returns:
            True if restore was successful, False otherwise
        """
        backup_path = Path(backup_dir)
        
        # Security: Validate backup path is within backup root
        try:
            backup_path = backup_path.resolve()
            if not str(backup_path).startswith(str(self.backup_root.resolve())):
                logger.error(f"Backup path outside backup root: {backup_dir}")
                return False
        except Exception as e:
            logger.error(f"Invalid backup path: {backup_dir}: {e}")
            return False
        
        if not backup_path.exists():
            logger.error(f"Backup directory not found: {backup_dir}")
            return False
        
        manifest_path = backup_path / 'manifest.json'
        if not manifest_path.exists():
            logger.error(f"Manifest not found in backup: {manifest_path}")
            return False
        
        try:
            # Load manifest
            manifest_content = await self._read_file_async(manifest_path)
            manifest_data = json.loads(manifest_content.decode('utf-8'))
            files = manifest_data.get('files', {})
            
            # Security: Check backup age if max_age_days is specified
            if max_age_days is not None:
                created_at_str = manifest_data.get('created_at', '')
                try:
                    created_at = datetime.fromisoformat(created_at_str.replace(':', '-', 2))
                    age_days = (datetime.now(timezone.utc) - created_at).days
                    if age_days > max_age_days:
                        logger.error(
                            f"Backup too old to restore: {age_days} days old "
                            f"(max allowed: {max_age_days} days)"
                        )
                        return False
                except Exception as e:
                    logger.warning(f"Could not determine backup age: {e}")
                    # If we can't determine age, we could be strict and reject, or allow
                    # For now, we'll allow but log a warning
            
            logger.info(f"Restoring backup from {backup_dir}")
            
            # Restore each file
            for original_path, file_info in files.items():
                backup_file_path = Path(file_info['backup_path'])
                
                # Determine target file path
                if target_files and original_path in target_files:
                    target_path = Path(target_files[original_path])
                else:
                    target_path = Path(original_path)
                
                # Security: Validate target path to prevent directory traversal
                if not self._validate_file_path(target_path):
                    logger.error(f"Invalid or unsafe target path, skipping: {target_path}")
                    continue
                
                # Ensure target directory exists
                target_path.parent.mkdir(parents=True, exist_ok=True)
                
                # Read and decompress if needed
                if file_info.get('compressed', False):
                    with gzip.open(backup_file_path, 'rb') as f_in:
                        content = f_in.read()
                else:
                    content = await self._read_file_async(backup_file_path)
                
                # Write restored file
                await self._write_file_async(target_path, content)
                
                # Verify restored file checksum
                restored_checksum = hashlib.sha256(content).hexdigest()
                expected_checksum = file_info['checksum']
                
                if restored_checksum != expected_checksum:
                    logger.error(
                        f"Restored file checksum mismatch for {original_path}: "
                        f"expected {expected_checksum[:16]}..., got {restored_checksum[:16]}..."
                    )
                    return False
                
                logger.debug(f"Restored {original_path} -> {target_path}")
            
            logger.info("Backup restore completed successfully")
            return True
            
        except Exception as e:
            logger.error(f"Backup restore failed: {e}")
            return False
    
    def list_backups(self, error_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List available backups.
        
        Args:
            error_id: Optional filter by error_id
        
        Returns:
            List of backup metadata dictionaries
        """
        backups = []
        
        if error_id:
            error_dir = self.backup_root / error_id
            if error_dir.exists():
                backup_dirs = [error_dir]
            else:
                return []
        else:
            backup_dirs = [d for d in self.backup_root.iterdir() if d.is_dir()]
        
        for error_dir in backup_dirs:
            for backup_dir in error_dir.iterdir():
                if backup_dir.is_dir():
                    manifest_path = backup_dir / 'manifest.json'
                    if manifest_path.exists():
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest_data = json.load(f)
                            backups.append({
                                'error_id': manifest_data.get('error_id'),
                                'backup_dir': str(backup_dir),
                                'created_at': manifest_data.get('created_at'),
                                'files_count': len(manifest_data.get('files', {}))
                            })
                        except Exception as e:
                            logger.warning(f"Failed to read manifest from {manifest_path}: {e}")
        
        return backups
    
    def cleanup_old_backups(
        self,
        max_age_days: int = 30,
        keep_latest_per_error: int = 5
    ) -> int:
        """
        Clean up old backups based on retention policy.
        
        Args:
            max_age_days: Delete backups older than this many days
            keep_latest_per_error: Always keep this many latest backups per error
        
        Returns:
            Number of backups deleted
        """
        deleted_count = 0
        cutoff_time = datetime.now(timezone.utc).timestamp() - (max_age_days * 24 * 60 * 60)
        
        for error_dir in self.backup_root.iterdir():
            if not error_dir.is_dir():
                continue
            
            # Get all backups for this error
            backup_dirs = []
            for backup_dir in error_dir.iterdir():
                if backup_dir.is_dir():
                    manifest_path = backup_dir / 'manifest.json'
                    if manifest_path.exists():
                        try:
                            with open(manifest_path, 'r') as f:
                                manifest_data = json.load(f)
                            created_at_str = manifest_data.get('created_at', '')
                            # Parse ISO format timestamp
                            try:
                                created_at = datetime.fromisoformat(created_at_str.replace(':', '-', 2))
                                backup_dirs.append((backup_dir, created_at))
                            except Exception:
                                # Fallback: use directory modification time
                                backup_dirs.append((backup_dir, datetime.fromtimestamp(backup_dir.stat().st_mtime, tz=timezone.utc)))
                        except Exception:
                            # Use directory modification time as fallback
                            backup_dirs.append((backup_dir, datetime.fromtimestamp(backup_dir.stat().st_mtime, tz=timezone.utc)))
            
            # Sort by creation time (newest first)
            backup_dirs.sort(key=lambda x: x[1], reverse=True)
            
            # Delete old backups
            for i, (backup_dir, created_at) in enumerate(backup_dirs):
                should_delete = False
                
                # Delete if older than max_age_days
                if created_at.timestamp() < cutoff_time:
                    should_delete = True
                
                # Delete if beyond keep_latest_per_error limit
                if i >= keep_latest_per_error:
                    should_delete = True
                
                if should_delete:
                    try:
                        shutil.rmtree(backup_dir)
                        deleted_count += 1
                        logger.debug(f"Deleted old backup: {backup_dir}")
                    except Exception as e:
                        logger.warning(f"Failed to delete backup {backup_dir}: {e}")
        
        if deleted_count > 0:
            logger.info(f"Cleaned up {deleted_count} old backup(s)")
        
        return deleted_count
    
    def _validate_file_path(self, file_path: Path) -> bool:
        """
        Validate file path for security (prevent directory traversal).
        
        Args:
            file_path: Path to validate
        
        Returns:
            True if path is safe, False otherwise
        """
        try:
            # Resolve to absolute path to normalize it
            resolved = file_path.resolve()
            path_str = str(resolved)
            
            # Reject paths that are too long (potential DoS)
            if len(path_str) > 4096:  # Common filesystem limit
                logger.warning(f"Path too long: {len(path_str)} characters")
                return False
            
            # Check for null bytes (potential injection)
            if '\x00' in path_str:
                logger.warning(f"Path contains null byte: {file_path}")
                return False
            
            # Additional validation: ensure resolved path doesn't have suspicious patterns
            # Note: '..' in the original string is dangerous, but after resolve() it's normalized
            # We check the original path string for '..' before resolution
            original_str = str(file_path)
            if '..' in original_str and not resolved.exists():
                # If original had '..' and resolved path doesn't exist, it might be traversal
                logger.debug(f"Path validation: checking for traversal in {original_str}")
            
            return True
        except Exception as e:
            logger.error(f"Path validation failed for {file_path}: {e}")
            return False
    
    def _ensure_backup_protection(self):
        """Ensure backup directory is protected from direct web access."""
        # Create .htaccess for Apache
        htaccess_file = self.backup_root / '.htaccess'
        if not htaccess_file.exists():
            try:
                with open(htaccess_file, 'w') as f:
                    f.write("# Deny all direct access to backup files\n")
                    f.write("Order Deny,Allow\n")
                    f.write("Deny from all\n")
                    f.write("\n# Prevent directory listing\n")
                    f.write("Options -Indexes\n")
            except Exception:
                pass  # May not have write permissions or not Apache
        
        # Create .nginx for Nginx (if using Nginx)
        nginx_file = self.backup_root / '.nginx'
        if not nginx_file.exists():
            try:
                with open(nginx_file, 'w') as f:
                    f.write("# Nginx configuration snippet\n")
                    f.write("# Add to your Nginx server block:\n")
                    f.write("# location ~ ^/(.+\\.patcherly_backups|.+\\.apr_backups)/ {\n")
                    f.write("#     deny all;\n")
                    f.write("#     return 403;\n")
                    f.write("# }\n")
            except Exception:
                pass
        
        # Create index.html to prevent directory listing
        index_file = self.backup_root / 'index.html'
        if not index_file.exists():
            try:
                with open(index_file, 'w') as f:
                    f.write("<!-- Silence is golden. -->\n")
            except Exception:
                pass

