<?php
/**
 * Pre-apply backup manager: versioned snapshots with checksums, compression, and verification.
 */

if (!defined('ABSPATH')) { exit; }

require_once __DIR__ . '/storage_paths.php';
require_once __DIR__ . '/filesystem_helpers.php';

class Patcherly_BackupManager {
    private $backupRoot;

    /**
     * @param string|null $backupRoot Root for backups; falls back to PATCHERLY_BACKUP_ROOT env then
     *                                wp-content/uploads/patcherly/backups. Prefer a path outside webroot.
     */
    public function __construct($backupRoot = null) {
        patcherly_ensure_storage_tree();
        if ($backupRoot === null) {
            $this->backupRoot = patcherly_backup_root();
        } else {
            $this->backupRoot = realpath($backupRoot) ?: $backupRoot;
        }
        if (!is_dir($this->backupRoot)) {
            wp_mkdir_p($this->backupRoot);
            if (function_exists('WP_Filesystem')) {
                if (defined('ABSPATH') && file_exists(ABSPATH . 'wp-admin/includes/file.php')) {
                    require_once ABSPATH . 'wp-admin/includes/file.php';
                }
                if (function_exists('WP_Filesystem') && WP_Filesystem()) {
                    global $wp_filesystem;
                    if ($wp_filesystem) {
                        $wp_filesystem->chmod($this->backupRoot, 0700);
                    }
                }
            }
        }
        patcherly_ensure_directory_protection($this->backupRoot);
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
        // gmdate() to anchor the timestamp in UTC regardless of the site's
        // configured timezone -- backup dir names must be stable for
        // rollback lookups.
        $timestamp = gmdate('Y-m-d\TH-i-s\Z', time());
        $backupDir = $this->backupRoot . DIRECTORY_SEPARATOR . sanitize_file_name($errorId) . DIRECTORY_SEPARATOR . $timestamp;
        
        if (!wp_mkdir_p($backupDir)) {
            return new WP_Error('backup_create_failed', 'Failed to create backup directory: ' . $backupDir);
        }
        
        patcherly_debug_log("Creating backup in {$backupDir} for " . count($files) . " file(s)");
        
        $backupManifest = [];
        
        foreach ($files as $filePath) {
            try {
                // Ensure file path is within WordPress root for security
                $wp_root = ABSPATH;
                $real_file = realpath($filePath);
                if ($real_file === false || strpos($real_file, $wp_root) !== 0) {
                    patcherly_debug_log("File path not within WordPress root, skipping: {$filePath}");
                    continue;
                }
                
                // Check if file exists
                if (!file_exists($real_file)) {
                    patcherly_debug_log("File not found, skipping: {$real_file}");
                    continue;
                }
                
                // Read file content
                $content = @file_get_contents($real_file);
                if ($content === false) {
                    patcherly_debug_log("Failed to read file: {$real_file}");
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
                    patcherly_debug_log("Failed to write backup file: {$backupFile}");
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
                            wp_delete_file($backupFile);
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
                
                patcherly_debug_log("Backed up {$filePath} -> {$finalBackupFile} (checksum: " . substr($checksum, 0, 16) . "...)");
                
            } catch (Exception $e) {
                patcherly_debug_log("Failed to backup file {$filePath}: " . $e->getMessage());
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
        
        patcherly_debug_log("Backup created successfully: {$backupDir} (verified: " . ($verified ? 'true' : 'false') . ")");
        return $metadata;
    }
    
    /** Verify backup integrity by recomputing SHA-256 checksums against the manifest. */
    private function verify_backup_integrity($backupDir, $manifest) {
        patcherly_debug_log("Verifying backup integrity in {$backupDir}");
        
        try {
            foreach ($manifest as $filePath => $fileInfo) {
                $backupFilePath = $fileInfo['backup_path'];
                $expectedChecksum = $fileInfo['checksum'];
                
                if (!file_exists($backupFilePath)) {
                    patcherly_debug_log("Backup file not found: {$backupFilePath}");
                    return false;
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = @file_get_contents($backupFilePath);
                    if ($compressed === false) {
                        patcherly_debug_log("Failed to read compressed backup: {$backupFilePath}");
                        return false;
                    }
                    $content = @gzdecode($compressed);
                    if ($content === false) {
                        patcherly_debug_log("Failed to decompress backup: {$backupFilePath}");
                        return false;
                    }
                } else {
                    $content = @file_get_contents($backupFilePath);
                    if ($content === false) {
                        patcherly_debug_log("Failed to read backup: {$backupFilePath}");
                        return false;
                    }
                }
                
                // Verify checksum
                $actualChecksum = hash('sha256', $content);
                
                if ($actualChecksum !== $expectedChecksum) {
                    patcherly_debug_log(
                        "Checksum mismatch for {$filePath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($actualChecksum, 0, 16) . "..."
                    );
                    return false;
                }
                
                patcherly_debug_log("Verified {$filePath} (checksum: " . substr($expectedChecksum, 0, 16) . "...)");
            }
            
            patcherly_debug_log('Backup integrity verification passed');
            return true;
            
        } catch (Exception $e) {
            patcherly_debug_log('Backup integrity verification failed: ' . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Restore files from a backup. $targetFiles optionally remaps original paths to alternate targets.
     *
     * @return bool|WP_Error
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
            
            patcherly_debug_log("Restoring backup from {$backupDir}");
            
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
                    patcherly_debug_log("Target path not within WordPress root, skipping: {$targetPath}");
                    continue;
                }
                
                // Ensure target directory exists
                $targetDir = dirname($targetPath);
                if (!wp_mkdir_p($targetDir)) {
                    patcherly_debug_log("Failed to create target directory: {$targetDir}");
                    continue;
                }
                
                // Read and decompress if needed
                if ($fileInfo['compressed']) {
                    $compressed = @file_get_contents($backupFilePath);
                    if ($compressed === false) {
                        patcherly_debug_log("Failed to read compressed backup: {$backupFilePath}");
                        continue;
                    }
                    $content = @gzdecode($compressed);
                    if ($content === false) {
                        patcherly_debug_log("Failed to decompress backup: {$backupFilePath}");
                        continue;
                    }
                } else {
                    $content = @file_get_contents($backupFilePath);
                    if ($content === false) {
                        patcherly_debug_log("Failed to read backup: {$backupFilePath}");
                        continue;
                    }
                }
                
                // Write restored file
                if (!patcherly_write_file_contents($targetPath, $content)) {
                    patcherly_debug_log("Failed to write restored file: {$targetPath}");
                    continue;
                }
                
                // Verify restored file checksum
                $restoredChecksum = hash('sha256', $content);
                $expectedChecksum = $fileInfo['checksum'];
                
                if ($restoredChecksum !== $expectedChecksum) {
                    patcherly_debug_log(
                        "Restored file checksum mismatch for {$originalPath}: " .
                        "expected " . substr($expectedChecksum, 0, 16) . "..., " .
                        "got " . substr($restoredChecksum, 0, 16) . "..."
                    );
                    return new WP_Error('checksum_mismatch', "Checksum mismatch for {$originalPath}");
                }
                
                patcherly_debug_log("Restored {$originalPath} -> {$targetPath}");
            }
            
            patcherly_debug_log('Backup restore completed successfully');
            return true;
            
        } catch (Exception $e) {
            return new WP_Error('restore_failed', 'Backup restore failed: ' . $e->getMessage());
        }
    }
    
    /** List available backups, optionally filtered by error_id. */
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
                            patcherly_debug_log("Failed to read manifest from {$manifestPath}: " . $e->getMessage());
                        }
                    }
                }
            }
        }
        
        return $backups;
    }
    
    // No cleanup helper here: connector pre-apply backups are intentionally customer-managed with
    // indefinite retention. Patcherly's own DB backups are a separate, server-side workflow.

    // camelCase aliases for cross-connector API parity.
    public function createBackup($errorId, $files, $compress = true, $verify = true) {
        return $this->create_backup($errorId, $files, $compress, $verify);
    }

    public function restoreBackup($backupDir, $targetFiles = null) {
        return $this->restore_backup($backupDir, $targetFiles);
    }

    public function listBackups($errorId = null) {
        return $this->list_backups($errorId);
    }
}

