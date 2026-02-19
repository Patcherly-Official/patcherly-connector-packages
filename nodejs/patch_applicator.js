/**
 * Patch Applicator for Node.js Agent
 * Handles parsing and applying unified diff patches to files.
 */

const fs = require('fs').promises;
const path = require('path');
const { execSync } = require('child_process');

class PatchParseError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PatchParseError';
    }
}

class PatchApplyError extends Error {
    constructor(message) {
        super(message);
        this.name = 'PatchApplyError';
    }
}

class FileLock {
    /**
     * File locking mechanism using lock files.
     */
    constructor(filePath) {
        this.filePath = filePath;
        this.lockFile = `${filePath}.lock`;
        this.lockFd = null;
    }

    async acquire() {
        try {
            // Try to create lock file exclusively
            this.lockFd = await fs.open(this.lockFile, 'wx');
            await this.lockFd.writeFile(`${process.pid}\n`);
            return this;
        } catch (error) {
            if (error.code === 'EEXIST') {
                throw new PatchApplyError(`File is locked: ${this.filePath}`);
            }
            throw error;
        }
    }

    async release() {
        if (this.lockFd) {
            await this.lockFd.close();
            this.lockFd = null;
        }
        try {
            await fs.unlink(this.lockFile);
        } catch (error) {
            // Ignore if lock file doesn't exist
        }
    }
}

class Hunk {
    /**
     * Represents a hunk (block of changes) in a patch.
     */
    constructor(origStart, origLen, newStart, newLen, context, removed, added) {
        this.origStart = origStart;
        this.origLen = origLen;
        this.newStart = newStart;
        this.newLen = newLen;
        this.context = context;
        this.removed = removed;
        this.added = added;
    }

    canApplyTo(fileLines) {
        /**
         * Check if this hunk can be applied to the file.
         * Returns: { canApply: boolean, error: string | null }
         */
        // Check bounds
        if (this.origStart < 1) {
            return { canApply: false, error: 'Invalid start line (must be >= 1)' };
        }

        // Check if we have enough lines in file
        if (this.origStart - 1 + this.context.length > fileLines.length) {
            return {
                canApply: false,
                error: `Hunk starts at line ${this.origStart} but file has only ${fileLines.length} lines`
            };
        }

        // Check context matches
        const startIdx = this.origStart - 1;
        for (let i = 0; i < this.context.length; i++) {
            if (startIdx + i >= fileLines.length) {
                return { canApply: false, error: 'Context mismatch: file too short' };
            }
            const expected = this.context[i].replace(/\r?\n$/, '');
            const actual = fileLines[startIdx + i].replace(/\r?\n$/, '');
            if (actual !== expected) {
                return {
                    canApply: false,
                    error: `Context mismatch at line ${this.origStart + i}`
                };
            }
        }

        return { canApply: true, error: null };
    }
}

class FilePatch {
    /**
     * Represents a patch for a single file.
     */
    constructor(filePath) {
        this.filePath = filePath;
        this.hunks = [];
    }

    addHunk(hunk) {
        this.hunks.push(hunk);
    }

    async canApplyTo(filePath) {
        /**
         * Check if this patch can be applied to the file.
         * Returns: { canApply: boolean, error: string | null }
         */
        let fileExists = false;
        try {
            await fs.access(filePath);
            fileExists = true;
        } catch (error) {
            // File doesn't exist - check if all hunks are additions
            for (const hunk of this.hunks) {
                if (hunk.origLen > 0) {
                    return { canApply: false, error: 'File does not exist and patch contains deletions' };
                }
            }
            return { canApply: true, error: null };
        }

        // Read file
        let fileLines;
        try {
            const content = await fs.readFile(filePath, 'utf-8');
            fileLines = content.split(/\r?\n/).map(line => line + '\n');
        } catch (error) {
            return { canApply: false, error: `Cannot read file: ${error.message}` };
        }

        // Check each hunk
        for (let i = 0; i < this.hunks.length; i++) {
            const hunk = this.hunks[i];
            const result = hunk.canApplyTo(fileLines);
            if (!result.canApply) {
                return { canApply: false, error: `Hunk ${i + 1}: ${result.error}` };
            }
        }

        return { canApply: true, error: null };
    }
}

class PatchApplicator {
    /**
     * Parses and applies unified diff patches.
     */
    constructor() {
        console.log('Initialized PatchApplicator');
    }

    parsePatch(patchText) {
        /**
         * Parse unified diff format into FilePatch objects.
         * Throws PatchParseError if patch cannot be parsed.
         */
        const filePatches = [];
        const lines = patchText.split('\n');

        let i = 0;
        while (i < lines.length) {
            // Look for file header: --- a/path
            if (lines[i].startsWith('---')) {
                const match = lines[i].match(/^---\s+a\/(.+)$/) || lines[i].match(/^---\s+(.+)$/);
                if (!match) {
                    i++;
                    continue;
                }

                const filePath = match[1].trim();

                // Skip to +++ line
                i++;
                if (i >= lines.length || !lines[i].startsWith('+++')) {
                    throw new PatchParseError(`Missing +++ line after --- for ${filePath}`);
                }

                // Create FilePatch
                const filePatch = new FilePatch(filePath);

                // Parse hunks
                i++;
                while (i < lines.length) {
                    const line = lines[i];

                    // Empty line between hunks
                    if (!line.trim()) {
                        i++;
                        continue;
                    }

                    // New file header - done with this file
                    if (line.startsWith('---')) {
                        break;
                    }

                    // Hunk header: @@ -orig_start,orig_len +new_start,new_len @@
                    if (line.startsWith('@@')) {
                        const hunk = this.parseHunk(lines, i);
                        filePatch.addHunk(hunk);
                        // Skip past hunk
                        while (i < lines.length && !lines[i].startsWith('@@')) {
                            i++;
                        }
                        if (i < lines.length && lines[i].startsWith('@@')) {
                            continue; // Next hunk
                        }
                        break;
                    }

                    i++;
                }

                filePatches.push(filePatch);
            } else {
                i++;
            }
        }

        if (filePatches.length === 0) {
            throw new PatchParseError('No file patches found in patch text');
        }

        return filePatches;
    }

    parseHunk(lines, startIdx) {
        /**
         * Parse a hunk from patch lines.
         */
        const hunkHeader = lines[startIdx];

        // Parse hunk header: @@ -orig_start,orig_len +new_start,new_len @@
        const match = hunkHeader.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@$/);
        if (!match) {
            throw new PatchParseError(`Invalid hunk header: ${hunkHeader}`);
        }

        const origStart = parseInt(match[1], 10);
        const origLen = parseInt(match[2] || '1', 10);
        const newStart = parseInt(match[3], 10);
        const newLen = parseInt(match[4] || '1', 10);

        const context = [];
        const removed = [];
        const added = [];

        // Parse hunk content
        let i = startIdx + 1;
        while (i < lines.length) {
            const line = lines[i];

            // End of hunk
            if (line.startsWith('@@') || line.startsWith('---')) {
                break;
            }

            if (line.startsWith(' ')) {
                // Context line (unchanged)
                context.push(line.substring(1));
            } else if (line.startsWith('-')) {
                // Removed line
                removed.push(line.substring(1));
            } else if (line.startsWith('+')) {
                // Added line
                added.push(line.substring(1));
            } else if (line.trim() === '') {
                // Empty line in context
                context.push('');
            }

            i++;
        }

        return new Hunk(origStart, origLen, newStart, newLen, context, removed, added);
    }

    async applyPatch(filePatch, filePath, dryRun = false, verifySyntax = true) {
        /**
         * Apply a patch to a file.
         * Returns: { success: boolean, message: string, syntaxErrors: string[] | null }
         */
        // Check if patch can be applied
        const canApply = await filePatch.canApplyTo(filePath);
        if (!canApply.canApply) {
            return {
                success: false,
                message: `Cannot apply patch: ${canApply.error}`,
                syntaxErrors: null
            };
        }

        if (dryRun) {
            return {
                success: true,
                message: `Dry-run: Patch would be applied successfully to ${filePath}`,
                syntaxErrors: null
            };
        }

        // Acquire file lock
        const lock = new FileLock(filePath);
        try {
            await lock.acquire();

            // Read original file
            let originalLines = [];
            try {
                const content = await fs.readFile(filePath, 'utf-8');
                originalLines = content.split(/\r?\n/).map((line, idx, arr) => {
                    // Add newline to all lines except last (or if file ends with newline)
                    if (idx < arr.length - 1 || content.endsWith('\n')) {
                        return line + '\n';
                    }
                    return line;
                });
            } catch (error) {
                if (error.code !== 'ENOENT') {
                    throw error;
                }
                // File doesn't exist - will be created
            }

            // Apply hunks (in reverse order to maintain line numbers)
            let modifiedLines = [...originalLines];

            // Sort hunks by start line in reverse order
            const sortedHunks = [...filePatch.hunks].sort((a, b) => b.origStart - a.origStart);

            for (const hunk of sortedHunks) {
                modifiedLines = this.applyHunk(hunk, modifiedLines);
            }

            // Write modified file
            const content = modifiedLines.join('');
            await fs.writeFile(filePath, content, 'utf-8');

            // Verify syntax if requested
            let syntaxErrors = null;
            if (verifySyntax) {
                const syntaxOk = await this.verifySyntax(filePath);
                if (!syntaxOk.valid) {
                    // Restore original file
                    await fs.writeFile(filePath, originalLines.join(''), 'utf-8');
                    return {
                        success: false,
                        message: 'Syntax validation failed',
                        syntaxErrors: syntaxOk.errors
                    };
                }
                syntaxErrors = syntaxOk.errors || [];
            }

            await lock.release();

            return {
                success: true,
                message: `Patch applied successfully to ${filePath}`,
                syntaxErrors
            };
        } catch (error) {
            await lock.release();
            if (error instanceof PatchApplyError) {
                return {
                    success: false,
                    message: error.message,
                    syntaxErrors: null
                };
            }
            console.error('Error applying patch:', error);
            return {
                success: false,
                message: `Error applying patch: ${error.message}`,
                syntaxErrors: null
            };
        }
    }

    applyHunk(hunk, fileLines) {
        /**
         * Apply a single hunk to file lines.
         */
        const startIdx = hunk.origStart - 1;

        // Remove old lines
        const linesToRemove = hunk.context.length + hunk.removed.length;
        const result = fileLines.slice(0, startIdx);

        // Add context + new lines
        for (const line of hunk.context) {
            result.push(line.endsWith('\n') ? line : line + '\n');
        }

        for (const line of hunk.added) {
            result.push(line.endsWith('\n') ? line : line + '\n');
        }

        // Add remaining lines
        const remainingStart = startIdx + linesToRemove;
        if (remainingStart < fileLines.length) {
            result.push(...fileLines.slice(remainingStart));
        }

        return result;
    }

    async verifySyntax(filePath) {
        /**
         * Verify syntax of a JavaScript/Node.js file.
         * Returns: { valid: boolean, errors: string[] }
         */
        const ext = path.extname(filePath).toLowerCase();
        
        if (!['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) {
            // For non-JavaScript files, assume valid
            return { valid: true, errors: [] };
        }

        try {
            // Try to parse with Node.js syntax checker
            // Use node --check for basic syntax validation
            execSync(`node --check "${filePath}"`, { 
                encoding: 'utf-8',
                stdio: ['pipe', 'pipe', 'pipe'],
                timeout: 5000
            });
            return { valid: true, errors: [] };
        } catch (error) {
            // Extract error message from stderr
            const errorMsg = error.stderr?.toString() || error.message || 'Unknown syntax error';
            return {
                valid: false,
                errors: [errorMsg]
            };
        }
    }
}

module.exports = {
    PatchApplicator,
    PatchParseError,
    PatchApplyError
};

