/**
 * Agent-Side Backup Manager (Node.js)
 * Manages versioned backups with checksums, compression, and integrity verification.
 */

const fs = require('fs').promises;
const fsSync = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const { promisify } = require('util');

const gzip = promisify(zlib.gzip);
const gunzip = promisify(zlib.gunzip);

class AgentBackupManager {
    /**
     * Initialize backup manager.
     * 
     * @param {string|null} backupRoot - Root directory for backups. If null, uses:
     *   - PATCHERLY_BACKUP_ROOT or APR_BACKUP_ROOT environment variable
     *   - ../backups/ (outside webroot, default)
     */
    constructor(backupRoot = null) {
        if (backupRoot === null) {
            backupRoot = process.env.PATCHERLY_BACKUP_ROOT || process.env.APR_BACKUP_ROOT || '../backups';
        }
        this.backupRoot = path.resolve(backupRoot);
        this._ensureDir(this.backupRoot);
        this._ensureBackupProtection();
    }

    /**
     * Ensure directory exists (synchronous for constructor)
     */
    _ensureDir(dirPath) {
        try {
            if (!fsSync.existsSync(dirPath)) {
                fsSync.mkdirSync(dirPath, { recursive: true, mode: 0o700 });  // Restrictive permissions
            }
        } catch (err) {
            console.error(`Failed to create backup directory ${dirPath}:`, err);
        }
    }

    /**
     * Ensure backup directory is protected from direct web access.
     */
    _ensureBackupProtection() {
        const htaccessFile = path.join(this.backupRoot, '.htaccess');
        
        // Create .htaccess if it doesn't exist
        if (!fsSync.existsSync(htaccessFile)) {
            try {
                const htaccessContent = 
                    "# Deny all direct access to backup files\n" +
                    "Order Deny,Allow\n" +
                    "Deny from all\n" +
                    "\n# Prevent directory listing\n" +
                    "Options -Indexes\n";
                fsSync.writeFileSync(htaccessFile, htaccessContent, 'utf8');
            } catch (err) {
                // May not have write permissions or not Apache
                console.warn(`Failed to create .htaccess file: ${err.message}`);
            }
        }
        
        // Create .nginx for Nginx (if using Nginx)
        const nginxFile = path.join(this.backupRoot, '.nginx');
        if (!fsSync.existsSync(nginxFile)) {
            try {
                const nginxContent = 
                    "# Nginx configuration snippet\n" +
                    "# Add to your Nginx server block:\n" +
                    "# location ~ ^/(.+\\.patcherly_backups|.+\\.apr_backups)/ {\n" +
                    "#     deny all;\n" +
                    "#     return 403;\n" +
                    "# }\n";
                fsSync.writeFileSync(nginxFile, nginxContent, 'utf8');
            } catch (err) {
                console.warn(`Failed to create .nginx file: ${err.message}`);
            }
        }
        
        // Also create index.html to prevent directory listing
        const indexFile = path.join(this.backupRoot, 'index.html');
        if (!fsSync.existsSync(indexFile)) {
            try {
                fsSync.writeFileSync(indexFile, "<!-- Silence is golden. -->\n", 'utf8');
            } catch (err) {
                console.warn(`Failed to create index.html file: ${err.message}`);
            }
        }
    }

    /**
     * Create a versioned backup with checksums.
     * 
     * @param {string} errorId - Unique error identifier
     * @param {string[]} files - List of file paths to backup
     * @param {boolean} compress - Whether to compress backup files
     * @param {boolean} verify - Whether to verify backup integrity after creation
     * @returns {Promise<Object>} BackupMetadata object
     */
    async createBackup(errorId, files, compress = true, verify = true) {
        const timestamp = new Date().toISOString().replace(/:/g, '-');
        const backupDir = path.join(this.backupRoot, errorId, timestamp);
        
        await fs.mkdir(backupDir, { recursive: true, mode: 0o700 });
        
        console.log(`Creating backup in ${backupDir} for ${files.length} file(s)`);
        
        const backupManifest = {};
        
        for (const filePath of files) {
            try {
                // Check if file exists
                try {
                    await fs.access(filePath);
                } catch {
                    console.warn(`File not found, skipping: ${filePath}`);
                    continue;
                }
                
                // Read file content
                const content = await fs.readFile(filePath);
                
                // Calculate checksum
                const checksum = crypto.createHash('sha256').update(content).digest('hex');
                const fileSize = content.length;
                
                // Determine backup filename
                const backupFileName = path.basename(filePath);
                const backupFile = path.join(backupDir, backupFileName);
                
                // Write backup file
                await fs.writeFile(backupFile, content);
                
                let finalBackupFile = backupFile;
                let finalSize = fileSize;
                let wasCompressed = false;
                
                // Compress if requested
                if (compress && fileSize > 0) {
                    const compressedFile = backupFile + '.gz';
                    const compressed = await gzip(content);
                    await fs.writeFile(compressedFile, compressed);
                    // Remove uncompressed file
                    await fs.unlink(backupFile);
                    finalBackupFile = compressedFile;
                    finalSize = compressed.length;
                    wasCompressed = true;
                }
                
                backupManifest[filePath] = {
                    checksum: checksum,
                    size: finalSize,
                    backup_path: finalBackupFile,
                    original_size: fileSize,
                    compressed: wasCompressed
                };
                
                console.debug(`Backed up ${filePath} -> ${finalBackupFile} (checksum: ${checksum.substring(0, 16)}...)`);
                
            } catch (err) {
                console.error(`Failed to backup file ${filePath}:`, err);
                // Continue with other files
                continue;
            }
        }
        
        if (Object.keys(backupManifest).length === 0) {
            throw new Error('No files were successfully backed up');
        }
        
        // Write manifest
        const manifestPath = path.join(backupDir, 'manifest.json');
        const manifestData = {
            error_id: errorId,
            created_at: timestamp,
            files: backupManifest,
            backup_version: 1
        };
        await fs.writeFile(manifestPath, JSON.stringify(manifestData, null, 2), 'utf8');
        
        // Verify backup integrity if requested
        let verified = true;
        if (verify) {
            verified = await this._verifyBackupIntegrity(backupDir, backupManifest);
        }
        
        const metadata = {
            error_id: errorId,
            backup_dir: backupDir,
            files: Object.keys(backupManifest),
            manifest: backupManifest,
            created_at: timestamp,
            verified: verified,
            to_dict: function() {
                return {
                    error_id: this.error_id,
                    backup_dir: this.backup_dir,
                    files: this.files,
                    manifest: this.manifest,
                    created_at: this.created_at,
                    verified: this.verified
                };
            }
        };
        
        console.log(`Backup created successfully: ${backupDir} (verified: ${verified})`);
        return metadata;
    }

    /**
     * Verify backup integrity by checking checksums.
     * 
     * @param {string} backupDir - Path to backup directory
     * @param {Object} manifest - Backup manifest
     * @returns {Promise<boolean>} True if all checksums match
     */
    async _verifyBackupIntegrity(backupDir, manifest) {
        console.debug(`Verifying backup integrity in ${backupDir}`);
        
        try {
            for (const [filePath, fileInfo] of Object.entries(manifest)) {
                const backupFilePath = fileInfo.backup_path;
                const expectedChecksum = fileInfo.checksum;
                
                try {
                    await fs.access(backupFilePath);
                } catch {
                    console.error(`Backup file not found: ${backupFilePath}`);
                    return false;
                }
                
                // Read and decompress if needed
                let content;
                if (fileInfo.compressed) {
                    const compressed = await fs.readFile(backupFilePath);
                    content = await gunzip(compressed);
                } else {
                    content = await fs.readFile(backupFilePath);
                }
                
                // Verify checksum
                const actualChecksum = crypto.createHash('sha256').update(content).digest('hex');
                
                if (actualChecksum !== expectedChecksum) {
                    console.error(
                        `Checksum mismatch for ${filePath}: ` +
                        `expected ${expectedChecksum.substring(0, 16)}..., got ${actualChecksum.substring(0, 16)}...`
                    );
                    return false;
                }
                
                console.debug(`Verified ${filePath} (checksum: ${expectedChecksum.substring(0, 16)}...)`);
            }
            
            console.log('Backup integrity verification passed');
            return true;
            
        } catch (err) {
            console.error('Backup integrity verification failed:', err);
            return false;
        }
    }

    /**
     * Restore files from a backup.
     * 
     * @param {string} backupDir - Path to backup directory
     * @param {Object} targetFiles - Optional mapping of backup file paths to restore targets
     * @returns {Promise<boolean>} True if restore was successful
     */
    async restoreBackup(backupDir, targetFiles = null) {
        try {
            await fs.access(backupDir);
        } catch {
            console.error(`Backup directory not found: ${backupDir}`);
            return false;
        }
        
        const manifestPath = path.join(backupDir, 'manifest.json');
        try {
            await fs.access(manifestPath);
        } catch {
            console.error(`Manifest not found in backup: ${manifestPath}`);
            return false;
        }
        
        try {
            // Load manifest
            const manifestContent = await fs.readFile(manifestPath, 'utf8');
            const manifestData = JSON.parse(manifestContent);
            const files = manifestData.files || {};
            
            console.log(`Restoring backup from ${backupDir}`);
            
            // Restore each file
            for (const [originalPath, fileInfo] of Object.entries(files)) {
                const backupFilePath = fileInfo.backup_path;
                
                // Determine target file path
                let targetPath;
                if (targetFiles && targetFiles[originalPath]) {
                    targetPath = targetFiles[originalPath];
                } else {
                    targetPath = originalPath;
                }
                
                // Ensure target directory exists
                const targetDir = path.dirname(targetPath);
                await fs.mkdir(targetDir, { recursive: true });
                
                // Read and decompress if needed
                let content;
                if (fileInfo.compressed) {
                    const compressed = await fs.readFile(backupFilePath);
                    content = await gunzip(compressed);
                } else {
                    content = await fs.readFile(backupFilePath);
                }
                
                // Write restored file
                await fs.writeFile(targetPath, content);
                
                // Verify restored file checksum
                const restoredChecksum = crypto.createHash('sha256').update(content).digest('hex');
                const expectedChecksum = fileInfo.checksum;
                
                if (restoredChecksum !== expectedChecksum) {
                    console.error(
                        `Restored file checksum mismatch for ${originalPath}: ` +
                        `expected ${expectedChecksum.substring(0, 16)}..., got ${restoredChecksum.substring(0, 16)}...`
                    );
                    return false;
                }
                
                console.debug(`Restored ${originalPath} -> ${targetPath}`);
            }
            
            console.log('Backup restore completed successfully');
            return true;
            
        } catch (err) {
            console.error('Backup restore failed:', err);
            return false;
        }
    }

    /**
     * List available backups.
     * 
     * @param {string|null} errorId - Optional filter by error_id
     * @returns {Promise<Array>} List of backup metadata dictionaries
     */
    async listBackups(errorId = null) {
        const backups = [];
        
        let errorDirs = [];
        if (errorId) {
            const errorDir = path.join(this.backupRoot, errorId);
            try {
                await fs.access(errorDir);
                errorDirs = [errorDir];
            } catch {
                return [];
            }
        } else {
            const entries = await fs.readdir(this.backupRoot);
            for (const entry of entries) {
                const entryPath = path.join(this.backupRoot, entry);
                const stat = await fs.stat(entryPath);
                if (stat.isDirectory()) {
                    errorDirs.push(entryPath);
                }
            }
        }
        
        for (const errorDir of errorDirs) {
            const entries = await fs.readdir(errorDir);
            for (const entry of entries) {
                const backupDir = path.join(errorDir, entry);
                const stat = await fs.stat(backupDir);
                if (stat.isDirectory()) {
                    const manifestPath = path.join(backupDir, 'manifest.json');
                    try {
                        await fs.access(manifestPath);
                        const manifestContent = await fs.readFile(manifestPath, 'utf8');
                        const manifestData = JSON.parse(manifestContent);
                        backups.push({
                            error_id: manifestData.error_id,
                            backup_dir: backupDir,
                            created_at: manifestData.created_at,
                            files_count: Object.keys(manifestData.files || {}).length
                        });
                    } catch (err) {
                        console.warn(`Failed to read manifest from ${manifestPath}:`, err);
                    }
                }
            }
        }
        
        return backups;
    }

    /**
     * Clean up old backups based on retention policy.
     * 
     * @param {number} maxAgeDays - Delete backups older than this many days
     * @param {number} keepLatestPerError - Always keep this many latest backups per error
     * @returns {Promise<number>} Number of backups deleted
     */
    async cleanupOldBackups(maxAgeDays = 30, keepLatestPerError = 5) {
        let deletedCount = 0;
        const cutoffTime = Date.now() - (maxAgeDays * 24 * 60 * 60 * 1000);
        
        const entries = await fs.readdir(this.backupRoot);
        for (const entry of entries) {
            const errorDir = path.join(this.backupRoot, entry);
            const stat = await fs.stat(errorDir);
            if (!stat.isDirectory()) continue;
            
            // Get all backups for this error
            const backupDirs = [];
            const backupEntries = await fs.readdir(errorDir);
            for (const backupEntry of backupEntries) {
                const backupDir = path.join(errorDir, backupEntry);
                const backupStat = await fs.stat(backupDir);
                if (backupStat.isDirectory()) {
                    const manifestPath = path.join(backupDir, 'manifest.json');
                    try {
                        await fs.access(manifestPath);
                        const manifestContent = await fs.readFile(manifestPath, 'utf8');
                        const manifestData = JSON.parse(manifestContent);
                        const createdAtStr = manifestData.created_at || '';
                        try {
                            const createdAt = new Date(createdAtStr.replace(/-/g, ':').replace(/-/g, ':'));
                            backupDirs.push({ path: backupDir, created_at: createdAt });
                        } catch {
                            // Fallback: use directory modification time
                            const mtime = backupStat.mtime;
                            backupDirs.push({ path: backupDir, created_at: mtime });
                        }
                    } catch {
                        // Use directory modification time as fallback
                        const mtime = backupStat.mtime;
                        backupDirs.push({ path: backupDir, created_at: mtime });
                    }
                }
            }
            
            // Sort by creation time (newest first)
            backupDirs.sort((a, b) => b.created_at - a.created_at);
            
            // Delete old backups
            for (let i = 0; i < backupDirs.length; i++) {
                const { path: backupDir, created_at } = backupDirs[i];
                let shouldDelete = false;
                
                // Delete if older than maxAgeDays
                if (created_at.getTime() < cutoffTime) {
                    shouldDelete = true;
                }
                
                // Delete if beyond keepLatestPerError limit
                if (i >= keepLatestPerError) {
                    shouldDelete = true;
                }
                
                if (shouldDelete) {
                    try {
                        await fs.rm(backupDir, { recursive: true, force: true });
                        deletedCount++;
                        console.debug(`Deleted old backup: ${backupDir}`);
                    } catch (err) {
                        console.warn(`Failed to delete backup ${backupDir}:`, err);
                    }
                }
            }
        }
        
        if (deletedCount > 0) {
            console.log(`Cleaned up ${deletedCount} old backup(s)`);
        }
        
        return deletedCount;
    }
}

module.exports = { AgentBackupManager };

