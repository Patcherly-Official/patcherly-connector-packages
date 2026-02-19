<?php
/**
 * Agent-Side Backup Manager (PHP/WordPress)
 * Manages versioned backups with checksums, compression, and integrity verification.
 * 
 * This is a WordPress-compatible version of the backup manager.
 */

if (!defined('ABSPATH')) { exit; }

class Patcherly_BackupManager {
    private $backupRoot;
    
    /**
     * Initialize backup manager.
     * 
     * @param string|null $backupRoot Root directory for backups. If null, uses:
     *   - PATCHERLY_BACKUP_ROOT or APR_BACKUP_ROOT environment variable
     *   - WordPress uploads directory (wp-content/uploads/patcherly_backups)
     *   Note: For better security, set PATCHERLY_BACKUP_ROOT to a path outside webroot
     */
    public function __construct($backupRoot = null) {
        if ($backupRoot === null) {
            $backupRoot = getenv('PATCHERLY_BACKUP_ROOT') ?: getenv('APR_BACKUP_ROOT');
            if (!$backupRoot) {
                // Fallback to WordPress uploads directory (inside webroot, but protected)
                $upload_dir = wp_upload_dir();
                $new_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'patcherly_backups';
                $legacy_path = $upload_dir['basedir'] . DIRECTORY_SEPARATOR . 'apr_backups';
                $this->backupRoot = (is_dir($legacy_path) && !is_dir($new_path)) ? $legacy_path : $new_path;
            } else {
                $this->backupRoot = realpath($backupRoot) ?: $backupRoot;
            }
        } else {
            $this->backupRoot = realpath($backupRoot) ?: $backupRoot;
        }
        
        if (!is_dir($this->backupRoot)) {
            wp_mkdir_p($this->backupRoot);
            // Set restrictive permissions
            @chmod($this->backupRoot, 0700);
        }
        
        // Ensure backup directory is protected from direct web access
        // This creates .htaccess in the BACKUP folder (wp-content/uploads/patcherly_backups/ or legacy apr_backups/),
        // NOT in the plugin folder. The plugin folder should NOT have an .htaccess file.
        $this->ensure_backup_protection();
    }
    
    /**
     * Ensure backup directory is protected from direct HTTP access.
     * Note: This only blocks HTTP requests. PHP filesystem operations (by the plugin)
     * and API requests (with proper authentication) can still access backups.
     * 
     * Updated on every plugin activation to ensure latest security rules.
     */
    private function ensure_backup_protection() {
        $htaccess_file = $this->backupRoot . DIRECTORY_SEPARATOR . '.htaccess';
        
        // ALWAYS overwrite .htaccess to ensure latest security rules
        $htaccess_content = "# Deny all access to backup directory\n";
        $htaccess_content .= "# This file should be placed in the backup root directory\n";
        $htaccess_content .= "# For WordPress, this is typically wp-content/uploads/patcherly_backups/\n";
        $htaccess_content .= "\n";
        $htaccess_content .= "<IfModule mod_authz_core.c>\n";
        $htaccess_content .= "    # Apache 2.4+\n";
        $htaccess_content .= "    Require all denied\n";
        $htaccess_content .= "</IfModule>\n";
        $htaccess_content .= "\n";
        $htaccess_content .= "<IfModule !mod_authz_core.c>\n";
        $htaccess_content .= "    # Apache 2.2\n";
        $htaccess_content .= "    Order deny,allow\n";
        $htaccess_content .= "    Deny from all\n";
        $htaccess_content .= "</IfModule>\n";
        $htaccess_content .= "\n";
        $htaccess_content .= "# Prevent directory listing\n";
        $htaccess_content .= "Options -Indexes\n";
        $htaccess_content .= "\n";
        $htaccess_content .= "# Prevent access to any files\n";
        $htaccess_content .= "<FilesMatch \".*\">\n";
        $htaccess_content .= "    Order allow,deny\n";
        $htaccess_content .= "    Deny from all\n";
        $htaccess_content .= "</FilesMatch>\n";
        
        @file_put_contents($htaccess_file, $htaccess_content);
        
        // Also create index.php to prevent directory listing
        $index_file = $this->backupRoot . DIRECTORY_SEPARATOR . 'index.php';
        if (!file_exists($index_file)) {
            @file_put_contents($index_file, "<?php\n// Silence is golden.\n");
        }
    }
    
    /**
     * Create a versioned backup with checksums.
     * 
     * @param string $errorId Unique error identifier
     * @param array $files List of file paths to backup
     * @param bool $compress Whether to compress backup files
     * @param bool $verify Whether to verify backup integrity after creation
     * @return array|WP_Error BackupMetadata array or WP_Error on failure
     */
    public function create_backup($errorId, $files, $compress = true, $verify = true) {
        $timestamp = date('Y-m-d\TH-i-s\Z', time());
        $backupDir = $this->backupRoot . DIRECTORY_SEPARATOR . sanitize_file_name($errorId) . DIRECTORY_SEPARATOR . $timestamp;
        
        if (!wp_mkdir_p($backupDir)) {
            return new WP_Error('backup_create_failed', 'Failed to create backup directory: ' . $backupDir);
        }
        
        error_log("Creating backup in {$backupDir} for " . count($files) . " file(s)");
        
        $backupManifest = [];
        
        foreach ($files as $filePath) {
            try {
                // Ensure file path is within WordPress root for security
                $wp_root = ABSPATH;
                $real_file = realpath($filePath);
                if ($real_file === false || strpos($real_file, $wp_root) !== 0) {
                    error_log("File path not within WordPress root, skipping: {$filePath}");
                    continue;
                }
                
                // Check if file exists
                if (!file_exists($real_file)) {
                    error_log("File not found, skipping: {$real_file}");
                    continue;
                }
                
                // Read file content
                $content = @file_get_contents($real_file);
                if ($content === false) {
                    error_log("Failed to read file: {$real_file}");
                    continue;
                }
                
                // Calculate checksum
                $checksum = hash('sha256', $content);
                $fileSize = strlen($content);
                
                // Determine backup filename
                $backupFileName = basename($real_file);
                $backupFile = $backupDir . DIRECTORY_SEPARATOR . sanitize_file_name($backupFileName);
                
                // Write backup file
                if (@file_put_contents($backupFile, $content) === false) {
                    error_log("Failed to write backup file: {$backupFile}");
                    continue;
                }
                
                $finalBackupFile = $backupFile;
                $finalSize = $fileSize;
                $wasCompressed = false;
                
                // Compress if requested
                if ($compress && $fileSize > 0) {
                    $compressedFile = $backupFile . '.gz';
                    $compressed = @gzencode($content, 9);
                    if ($compressed !== false) {
                        if (@file_put_contents($compressedFile, $compressed) !== false) {
                            // Remove uncompressed file
                            @unlink($backupFile);
                            $finalBackupFile = $compressedFile;
                            $finalSize = strlen($compressed);
                            $wasCompressed = true;
                        }
                    }
                }
                
                $backupManifest[$filePath] = [
                    'checksum' => $checksum,
                    'size' => $finalSize,
                    'backup_path' => $finalBackupFile,
                    'original_size' => $fileSize,
                    'compressed' => $wasCompressed
                ];
                
                error_log("Backed up {$filePath} -> {$finalBackupFile} (checksum: " . substr($checksum, 0, 16) . "...)");
                
            } catch (Exception $e) {
                error_log("Failed to backup file {$filePath}: " . $e->getMessage());
                // Continue with other files
                continue;
            }
        }
        
        if (empty($backupManifest)) {
            return new WP_Error('no_files_backed_up', 'No files were successfully backed up');
        }
        
        // Write manifest
        $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
        $manifestData = [
            'error_id' => $errorId,
            'created_at' => $timestamp,
            'files' => $backupManifest,
            'backup_version' => 1
        ];
        if (@file_put_contents($manifestPath, json_encode($manifestData, JSON_PRETTY_PRINT)) === false) {
            return new WP_Error('manifest_write_failed', 'Failed to write manifest file');
        }
        
        // Verify backup integrity if requested
        $verified = true;
        if ($verify) {
            $verified = $this->verify_backup_integrity($backupDir, $backupManifest);
        }
        
        $metadata = [
            'error_id' => $errorId,
            'backup_dir' => $backupDir,
            'files' => array_keys($backupManifest),
            'manifest' => $backupManifest,
            'created_at' => $timestamp,
            'verified' => $verified
        ];
        
        error_log("Backup created successfully: {$backupDir} (verified: " . ($verified ? 'true' : 'false') . ")");
        return $metadata;
    }
    
    /**
     * Verify backup integrity by checking checksums.
     * 
     * @param string $backupDir Path to backup directory
     * @param array $manifest Backup manifest
     * @return bool True if all checksums match
     */
    private function verify_backup_integrity($backupDir, $manifest) {
        error_log("Verifying backup integrity in {$backupDir}");
        
        try {
            foreach ($manifest as $filePath => $fileInfo) {
                $backupFilePath = $fileInfo['backup_path'];
                $expectedChecksum = $fileInfo['checksum'];
                
                if (!file_exists($backupFilePath)) {
                    error_log("Backup file not found: {$backupFilePath}");
                    return false;
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = @file_get_contents($backupFilePath);
                    if ($compressed === false) {
                        error_log("Failed to read compressed backup: {$backupFilePath}");
                        return false;
                    }
                    $content = @gzdecode($compressed);
                    if ($content === false) {
                        error_log("Failed to decompress backup: {$backupFilePath}");
                        return false;
                    }
                } else {
                    $content = @file_get_contents($backupFilePath);
                    if ($content === false) {
                        error_log("Failed to read backup: {$backupFilePath}");
                        return false;
                    }
                }
                
                // Verify checksum
                $actualChecksum = hash('sha256', $content);
                
                if ($actualChecksum !== $expectedChecksum) {
                    error_log(
                        "Checksum mismatch for {$filePath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($actualChecksum, 0, 16) . "..."
                    );
                    return false;
                }
                
                error_log("Verified {$filePath} (checksum: " . substr($expectedChecksum, 0, 16) . "...)");
            }
            
            error_log('Backup integrity verification passed');
            return true;
            
        } catch (Exception $e) {
            error_log('Backup integrity verification failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Restore files from a backup.
     * 
     * @param string $backupDir Path to backup directory
     * @param array|null $targetFiles Optional mapping of backup file paths to restore targets
     * @return bool|WP_Error True if restore was successful, WP_Error on failure
     */
    public function restore_backup($backupDir, $targetFiles = null) {
        if (!is_dir($backupDir)) {
            return new WP_Error('backup_dir_not_found', "Backup directory not found: {$backupDir}");
        }
        
        $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
        if (!file_exists($manifestPath)) {
            return new WP_Error('manifest_not_found', "Manifest not found in backup: {$manifestPath}");
        }
        
        try {
            // Load manifest
            $manifestContent = @file_get_contents($manifestPath);
            if ($manifestContent === false) {
                return new WP_Error('manifest_read_failed', 'Failed to read manifest file');
            }
            
            $manifestData = json_decode($manifestContent, true);
            if (!is_array($manifestData) || !isset($manifestData['files'])) {
                return new WP_Error('invalid_manifest', 'Invalid manifest format');
            }
            
            $files = $manifestData['files'];
            
            error_log("Restoring backup from {$backupDir}");
            
            $wp_root = ABSPATH;
            
            // Restore each file
            foreach ($files as $originalPath => $fileInfo) {
                $backupFilePath = $fileInfo['backup_path'];
                
                // Determine target file path
                if ($targetFiles && isset($targetFiles[$originalPath])) {
                    $targetPath = $targetFiles[$originalPath];
                } else {
                    $targetPath = $originalPath;
                }
                
                // Ensure target is within WordPress root for security
                $real_target = realpath(dirname($targetPath));
                if ($real_target === false || strpos($real_target, $wp_root) !== 0) {
                    error_log("Target path not within WordPress root, skipping: {$targetPath}");
                    continue;
                }
                
                // Ensure target directory exists
                $targetDir = dirname($targetPath);
                if (!wp_mkdir_p($targetDir)) {
                    error_log("Failed to create target directory: {$targetDir}");
                    continue;
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = @file_get_contents($backupFilePath);
                    if ($compressed === false) {
                        error_log("Failed to read compressed backup: {$backupFilePath}");
                        continue;
                    }
                    $content = @gzdecode($compressed);
                    if ($content === false) {
                        error_log("Failed to decompress backup: {$backupFilePath}");
                        continue;
                    }
                } else {
                    $content = @file_get_contents($backupFilePath);
                    if ($content === false) {
                        error_log("Failed to read backup: {$backupFilePath}");
                        continue;
                    }
                }
                
                // Write restored file
                if (@file_put_contents($targetPath, $content) === false) {
                    error_log("Failed to write restored file: {$targetPath}");
                    continue;
                }
                
                // Verify restored file checksum
                $restoredChecksum = hash('sha256', $content);
                $expectedChecksum = $fileInfo['checksum'];
                
                if ($restoredChecksum !== $expectedChecksum) {
                    error_log(
                        "Restored file checksum mismatch for {$originalPath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($restoredChecksum, 0, 16) . "..."
                    );
                    return new WP_Error('checksum_mismatch', "Checksum mismatch for {$originalPath}");
                }
                
                error_log("Restored {$originalPath} -> {$targetPath}");
            }
            
            error_log('Backup restore completed successfully');
            return true;
            
        } catch (Exception $e) {
            return new WP_Error('restore_failed', 'Backup restore failed: ' . $e->getMessage());
        }
    }
    
    /**
     * List available backups.
     * 
     * @param string|null $errorId Optional filter by error_id
     * @return array List of backup metadata arrays
     */
    public function list_backups($errorId = null) {
        $backups = [];
        
        if (!is_dir($this->backupRoot)) {
            return $backups;
        }
        
        $errorDirs = [];
        if ($errorId) {
            $errorDir = $this->backupRoot . DIRECTORY_SEPARATOR . sanitize_file_name($errorId);
            if (is_dir($errorDir)) {
                $errorDirs[] = $errorDir;
            } else {
                return $backups;
            }
        } else {
            $entries = @scandir($this->backupRoot);
            if ($entries === false) {
                return $backups;
            }
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $entryPath = $this->backupRoot . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($entryPath)) {
                    $errorDirs[] = $entryPath;
                }
            }
        }
        
        foreach ($errorDirs as $errorDir) {
            $entries = @scandir($errorDir);
            if ($entries === false) continue;
            
            foreach ($entries as $entry) {
                if ($entry === '.' || $entry === '..') continue;
                $backupDir = $errorDir . DIRECTORY_SEPARATOR . $entry;
                if (is_dir($backupDir)) {
                    $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
                    if (file_exists($manifestPath)) {
                        try {
                            $manifestContent = @file_get_contents($manifestPath);
                            if ($manifestContent !== false) {
                                $manifestData = json_decode($manifestContent, true);
                                if (is_array($manifestData)) {
                                    $backups[] = [
                                        'error_id' => $manifestData['error_id'] ?? null,
                                        'backup_dir' => $backupDir,
                                        'created_at' => $manifestData['created_at'] ?? null,
                                        'files_count' => count($manifestData['files'] ?? [])
                                    ];
                                }
                            }
                        } catch (Exception $e) {
                            error_log("Failed to read manifest from {$manifestPath}: " . $e->getMessage());
                        }
                    }
                }
            }
        }
        
        return $backups;
    }
    
    /**
     * Clean up old backups based on retention policy.
     * 
     * @param int $maxAgeDays Delete backups older than this many days
     * @param int $keepLatestPerError Always keep this many latest backups per error
     * @return int Number of backups deleted
     */
    public function cleanup_old_backups($maxAgeDays = 30, $keepLatestPerError = 5) {
        $deletedCount = 0;
        $cutoffTime = time() - ($maxAgeDays * 24 * 60 * 60);
        
        if (!is_dir($this->backupRoot)) {
            return $deletedCount;
        }
        
        $entries = @scandir($this->backupRoot);
        if ($entries === false) {
            return $deletedCount;
        }
        
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') continue;
            $errorDir = $this->backupRoot . DIRECTORY_SEPARATOR . $entry;
            if (!is_dir($errorDir)) continue;
            
            // Get all backups for this error
            $backupDirs = [];
            $backupEntries = @scandir($errorDir);
            if ($backupEntries === false) continue;
            
            foreach ($backupEntries as $backupEntry) {
                if ($backupEntry === '.' || $backupEntry === '..') continue;
                $backupDir = $errorDir . DIRECTORY_SEPARATOR . $backupEntry;
                if (is_dir($backupDir)) {
                    $manifestPath = $backupDir . DIRECTORY_SEPARATOR . 'manifest.json';
                    $createdAt = null;
                    if (file_exists($manifestPath)) {
                        try {
                            $manifestContent = @file_get_contents($manifestPath);
                            if ($manifestContent !== false) {
                                $manifestData = json_decode($manifestContent, true);
                                if (is_array($manifestData)) {
                                    $createdAtStr = $manifestData['created_at'] ?? '';
                                    // Parse ISO format timestamp
                                    try {
                                        // Replace colons with dashes for parsing
                                        $createdAtStr_parsed = str_replace('-', ':', str_replace('-', ':', $createdAtStr, 2), 1);
                                        $createdAt = strtotime($createdAtStr_parsed);
                                        if ($createdAt === false) {
                                            $createdAt = filemtime($backupDir);
                                        }
                                    } catch (Exception $e) {
                                        // Fallback: use directory modification time
                                        $createdAt = filemtime($backupDir);
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            // Use directory modification time as fallback
                            $createdAt = filemtime($backupDir);
                        }
                    } else {
                        $createdAt = filemtime($backupDir);
                    }
                    if ($createdAt) {
                        $backupDirs[] = ['path' => $backupDir, 'created_at' => $createdAt];
                    }
                }
            }
            
            // Sort by creation time (newest first)
            usort($backupDirs, function($a, $b) {
                return $b['created_at'] - $a['created_at'];
            });
            
            // Delete old backups
            foreach ($backupDirs as $i => $backupInfo) {
                $backupDir = $backupInfo['path'];
                $createdAt = $backupInfo['created_at'];
                $shouldDelete = false;
                
                // Delete if older than maxAgeDays
                if ($createdAt < $cutoffTime) {
                    $shouldDelete = true;
                }
                
                // Delete if beyond keepLatestPerError limit
                if ($i >= $keepLatestPerError) {
                    $shouldDelete = true;
                }
                
                if ($shouldDelete) {
                    try {
                        $this->delete_directory($backupDir);
                        $deletedCount++;
                        error_log("Deleted old backup: {$backupDir}");
                    } catch (Exception $e) {
                        error_log("Failed to delete backup {$backupDir}: " . $e->getMessage());
                    }
                }
            }
        }
        
        if ($deletedCount > 0) {
            error_log("Cleaned up {$deletedCount} old backup(s)");
        }
        
        return $deletedCount;
    }
    
    /**
     * Recursively delete a directory.
     * 
     * @param string $dir Directory path
     * @return bool True if successful
     */
    private function delete_directory($dir) {
        if (!is_dir($dir)) {
            return false;
        }
        
        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $filePath = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($filePath)) {
                $this->delete_directory($filePath);
            } else {
                @unlink($filePath);
            }
        }
        return @rmdir($dir);
    }
}

