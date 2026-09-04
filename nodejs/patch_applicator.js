/**
 * Patch Applicator for Node.js Agent
 * Handles parsing and applying unified diff patches to files.
 */

const fs = require('fs').promises;
const fssync = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

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
    constructor(origStart, origLen, newStart, newLen, context, removed, added, segments = []) {
        this.origStart = origStart;
        this.origLen = origLen;
        this.newStart = newStart;
        this.newLen = newLen;
        this.context = context;
        this.removed = removed;
        this.added = added;
        this.segments = segments;
    }

    lastChangeSegmentIndex() {
        let last = -1;
        for (let i = 0; i < this.segments.length; i++) {
            const t = this.segments[i].type;
            if (t === 'added' || t === 'removed') {
                last = i;
            }
        }
        return last;
    }

    origFileSegments() {
        // Trailing context after the last change is decorative; mid-hunk context
        // between multiple change sites must still be matched.
        if (!this.segments.length) {
            return [];
        }
        const lastChange = this.lastChangeSegmentIndex();
        const result = [];
        for (let i = 0; i < this.segments.length; i++) {
            const seg = this.segments[i];
            if (seg.type === 'added') {
                continue;
            }
            if (seg.type === 'context' && i > lastChange) {
                continue;
            }
            result.push(seg);
        }
        return result;
    }

    origLinesInHunk() {
        if (this.segments.length) {
            return this.origFileSegments().length;
        }
        return this.context.length + this.removed.length;
    }

    canApplyTo(fileLines) {
        if (this.origStart < 1) {
            return { canApply: false, error: 'Invalid start line (must be >= 1)' };
        }

        const origLines = this.origLinesInHunk();
        if (this.origStart - 1 + origLines > fileLines.length) {
            return {
                canApply: false,
                error: `Hunk starts at line ${this.origStart} but file has only ${fileLines.length} lines`,
            };
        }

        if (this.segments.length) {
            let idx = this.origStart - 1;
            for (const seg of this.origFileSegments()) {
                if (idx >= fileLines.length) {
                    return { canApply: false, error: 'Context mismatch: file too short' };
                }
                const expected = (seg.text ?? '').replace(/\r?\n$/, '');
                const actual = fileLines[idx].replace(/\r?\n$/, '');
                if (actual !== expected) {
                    return { canApply: false, error: `Context mismatch at line ${idx + 1}` };
                }
                idx++;
            }
            return { canApply: true, error: null };
        }

        const startIdx = this.origStart - 1;
        for (let i = 0; i < this.context.length; i++) {
            if (startIdx + i >= fileLines.length) {
                return { canApply: false, error: 'Context mismatch: file too short' };
            }
            const expected = this.context[i].replace(/\r?\n$/, '');
            const actual = fileLines[startIdx + i].replace(/\r?\n$/, '');
            if (actual !== expected) {
                return { canApply: false, error: `Context mismatch at line ${this.origStart + i}` };
            }
        }

        return { canApply: true, error: null };
    }

    matchesPostImage(fileLines) {
        if (this.newStart < 1) {
            return { matches: false, error: 'Invalid new start line (must be >= 1)' };
        }

        let idx = this.newStart - 1;
        if (this.segments.length) {
            for (const seg of this.segments) {
                if (seg.type === 'removed') {
                    continue;
                }
                if (idx >= fileLines.length) {
                    return { matches: false, error: 'Post-image mismatch: file too short' };
                }
                const expected = (seg.text ?? '').replace(/\r?\n$/, '');
                const actual = fileLines[idx].replace(/\r?\n$/, '');
                if (actual !== expected) {
                    return { matches: false, error: `Post-image mismatch at line ${idx + 1}` };
                }
                idx++;
            }
            return { matches: true, error: null };
        }

        for (const line of this.context) {
            if (idx >= fileLines.length) {
                return { matches: false, error: 'Post-image mismatch: file too short' };
            }
            const expected = line.replace(/\r?\n$/, '');
            const actual = fileLines[idx].replace(/\r?\n$/, '');
            if (actual !== expected) {
                return { matches: false, error: `Post-image mismatch at line ${idx + 1}` };
            }
            idx++;
        }
        for (const line of this.added) {
            if (idx >= fileLines.length) {
                return { matches: false, error: 'Post-image mismatch: file too short' };
            }
            const expected = line.replace(/\r?\n$/, '');
            const actual = fileLines[idx].replace(/\r?\n$/, '');
            if (actual !== expected) {
                return { matches: false, error: `Post-image mismatch at line ${idx + 1}` };
            }
            idx++;
        }

        return { matches: true, error: null };
    }

    static lineCore(line) {
        return String(line ?? '').replace(/\r?\n$/, '');
    }

    static leadingWs(line) {
        const core = Hunk.lineCore(line);
        const m = core.match(/^([ \t]*)/);
        return m ? m[1] : '';
    }

    /** Allow leading indent drift; blank/whitespace-only lines stay exact. */
    static linesMatchFlexible(a, b) {
        a = Hunk.lineCore(a);
        b = Hunk.lineCore(b);
        if (a === b) {
            return true;
        }
        const ka = a.replace(/^[ \t]+/, '');
        const kb = b.replace(/^[ \t]+/, '');
        if (ka === '' || kb === '') {
            return false;
        }
        return ka === kb;
    }

    reanchorWithIndentRewrite(fileLines, ctxStart) {
        if (ctxStart < 0 || !this.segments.length) {
            return false;
        }

        const headerDelta = this.newStart - this.origStart;
        const lastChange = this.lastChangeSegmentIndex();
        const saved = {
            origStart: this.origStart,
            newStart: this.newStart,
            segments: this.segments,
            context: this.context,
            removed: this.removed,
            added: this.added,
        };

        let idx = ctxStart;
        let patchRemovedIndent = null;
        let fileRemovedIndent = null;
        const newSegments = [];
        const newContext = [];
        const newRemoved = [];
        const newAdded = [];

        const restore = () => {
            this.origStart = saved.origStart;
            this.newStart = saved.newStart;
            this.segments = saved.segments;
            this.context = saved.context;
            this.removed = saved.removed;
            this.added = saved.added;
        };

        for (let i = 0; i < this.segments.length; i++) {
            const seg = this.segments[i];
            const type = seg.type ?? '';
            const text = String(seg.text ?? '');

            if (type === 'context' && i > lastChange) {
                newSegments.push(seg);
                continue;
            }
            if (type === 'added') {
                newSegments.push({ type: 'added', text });
                continue;
            }
            if (idx >= fileLines.length) {
                restore();
                return false;
            }

            const fileText = Hunk.lineCore(fileLines[idx]);
            const patchText = Hunk.lineCore(text);
            if (!Hunk.linesMatchFlexible(fileText, patchText)) {
                restore();
                return false;
            }
            if (type === 'removed' && patchRemovedIndent === null) {
                patchRemovedIndent = Hunk.leadingWs(patchText);
                fileRemovedIndent = Hunk.leadingWs(fileText);
            }
            newSegments.push({ type, text: fileText });
            if (type === 'context') {
                newContext.push(fileText);
            } else {
                newRemoved.push(fileText);
            }
            idx++;
        }

        for (let si = 0; si < newSegments.length; si++) {
            if ((newSegments[si].type ?? '') !== 'added') {
                continue;
            }
            let t = Hunk.lineCore(newSegments[si].text ?? '');
            if (patchRemovedIndent !== null && fileRemovedIndent !== null && patchRemovedIndent !== fileRemovedIndent) {
                if (patchRemovedIndent !== '' && t.startsWith(patchRemovedIndent)) {
                    t = fileRemovedIndent + t.slice(patchRemovedIndent.length);
                } else {
                    t = fileRemovedIndent + t.replace(/^[ \t]+/, '');
                }
            }
            newSegments[si] = { type: 'added', text: t };
            newAdded.push(t);
        }

        this.segments = newSegments;
        this.context = newContext;
        this.removed = newRemoved;
        this.added = newAdded;
        this.origStart = ctxStart + 1;
        this.newStart = this.origStart + headerDelta;

        if (this.canApplyTo(fileLines).canApply) {
            return true;
        }
        restore();
        return false;
    }

    tryRelocateInFile(fileLines) {
        if (this.canApplyTo(fileLines).canApply) {
            return true;
        }
        if (!this.segments.length || !this.removed.length) {
            return false;
        }

        const leadingContext = [];
        for (const seg of this.segments) {
            if (seg.type === 'removed') {
                break;
            }
            if (seg.type === 'context') {
                leadingContext.push(Hunk.lineCore(seg.text ?? ''));
            }
        }

        const removedNeedle = Hunk.lineCore(this.removed[0] ?? '');
        if (!removedNeedle || removedNeedle.replace(/^[ \t]+/, '') === '') {
            return false;
        }

        const ctxCount = leadingContext.length;
        const headerDelta = this.newStart - this.origStart;

        for (let i = 0; i < fileLines.length; i++) {
            if (!Hunk.linesMatchFlexible(fileLines[i], removedNeedle)) {
                continue;
            }
            const ctxStart = i - ctxCount;
            if (ctxStart < 0) {
                continue;
            }
            let matched = true;
            for (let j = 0; j < ctxCount; j++) {
                if (!Hunk.linesMatchFlexible(fileLines[ctxStart + j], leadingContext[j])) {
                    matched = false;
                    break;
                }
            }
            if (!matched) {
                continue;
            }
            const savedOrig = this.origStart;
            const savedNew = this.newStart;
            this.origStart = ctxStart + 1;
            this.newStart = this.origStart + headerDelta;
            if (this.canApplyTo(fileLines).canApply) {
                return true;
            }
            this.origStart = savedOrig;
            this.newStart = savedNew;

            if (this.reanchorWithIndentRewrite(fileLines, ctxStart)) {
                return true;
            }
        }

        return false;
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

    async readFileLines(filePath) {
        const content = await fs.readFile(filePath, 'utf-8');
        return content.split(/\r?\n/).map((line, idx, arr) => {
            if (idx < arr.length - 1 || content.endsWith('\n')) {
                return line + '\n';
            }
            return line;
        });
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
            fileLines = await this.readFileLines(filePath);
        } catch (error) {
            return { canApply: false, error: `Cannot read file: ${error.message}` };
        }

        for (let i = 0; i < this.hunks.length; i++) {
            const hunk = this.hunks[i];
            if (!hunk.canApplyTo(fileLines).canApply) {
                hunk.tryRelocateInFile(fileLines);
            }
            const result = hunk.canApplyTo(fileLines);
            if (!result.canApply) {
                return { canApply: false, error: `Hunk ${i + 1}: ${result.error}` };
            }
        }

        return { canApply: true, error: null };
    }

    async matchesPostImage(filePath) {
        if (!fssync.existsSync(filePath)) {
            return { matches: false, error: 'File does not exist' };
        }

        let fileLines;
        try {
            fileLines = await this.readFileLines(filePath);
        } catch (error) {
            return { matches: false, error: `Cannot read file: ${error.message}` };
        }

        for (let i = 0; i < this.hunks.length; i++) {
            const result = this.hunks[i].matchesPostImage(fileLines);
            if (!result.matches) {
                return { matches: false, error: `Hunk ${i + 1}: ${result.error}` };
            }
        }

        return { matches: true, error: null };
    }
}

class PatchApplicator {
    /**
     * Parses and applies unified diff patches.
     */
    constructor() {
        console.log('Initialized PatchApplicator');
        const configuredRoots = process.env.PATCHERLY_TARGET_ROOTS || '';
        const envRoots = configuredRoots
            .split(path.delimiter)
            .map((p) => p && p.trim())
            .filter(Boolean)
            .map((p) => path.resolve(p));
        this.allowedTargetRoots = Array.from(new Set([path.resolve(process.cwd()), ...envRoots]));
    }

    isPathWithinAllowedRoots(candidatePath) {
        try {
            const resolved = path.resolve(candidatePath);
            /** Follow symlinks so a path inside the jail cannot escape via link targets. */
            let checkPath = resolved;
            if (fssync.existsSync(resolved)) {
                try {
                    checkPath = fssync.realpathSync.native(resolved);
                } catch {
                    return false;
                }
            }
            return this.allowedTargetRoots.some((root) => {
                let rootReal = path.resolve(root);
                if (fssync.existsSync(rootReal)) {
                    try {
                        rootReal = fssync.realpathSync.native(rootReal);
                    } catch {
                        /* keep resolved root */
                    }
                }
                if (checkPath === rootReal) return true;
                return checkPath.startsWith(rootReal + path.sep);
            });
        } catch {
            return false;
        }
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
                        const { hunk, nextIndex } = this.parseHunk(lines, i);
                        filePatch.addHunk(hunk);
                        i = nextIndex;
                        continue;
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
         * @returns {{ hunk: Hunk, nextIndex: number }} Index of the next line after this hunk (next @@/--- or EOF).
         */
        const hunkHeader = lines[startIdx].replace(/\r$/, '');

        // Parse hunk header: @@ -orig_start,orig_len +new_start,new_len @@ [optional section]
        // Optional trailing text after the second @@ is valid unified-diff (git style).
        const match = hunkHeader.match(/^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@/);
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
        const segments = [];

        // Parse hunk content
        let i = startIdx + 1;
        while (i < lines.length) {
            const line = lines[i];

            // End of hunk
            if (line.startsWith('@@') || line.startsWith('---')) {
                break;
            }

            if (line.startsWith(' ')) {
                const text = line.substring(1);
                context.push(text);
                segments.push({ type: 'context', text });
            } else if (line.startsWith('-')) {
                const text = line.substring(1);
                removed.push(text);
                segments.push({ type: 'removed', text });
            } else if (line.startsWith('+')) {
                const text = line.substring(1);
                added.push(text);
                segments.push({ type: 'added', text });
            } else if (line.trim() === '') {
                context.push('');
                segments.push({ type: 'context', text: '' });
            }

            i++;
        }

        return {
            hunk: new Hunk(origStart, origLen, newStart, newLen, context, removed, added, segments),
            nextIndex: i,
        };
    }

    async applyPatch(filePatch, filePath, dryRun = false, verifySyntax = true) {
        /**
         * Apply a patch to a file.
         * Returns: { success: boolean, message: string, syntaxErrors: string[] | null }
         */
        if (!this.isPathWithinAllowedRoots(filePath)) {
            return {
                success: false,
                message: `File path is outside allowed target roots: ${filePath}`,
                syntaxErrors: null
            };
        }
        // Check if patch can be applied
        const canApply = await filePatch.canApplyTo(filePath);
        if (!canApply.canApply) {
            const already = await filePatch.matchesPostImage(filePath);
            if (already.matches) {
                return {
                    success: true,
                    message: `Patch already applied to ${filePath}`,
                    syntaxErrors: null,
                };
            }
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
        const startIdx = hunk.origStart - 1;

        if (hunk.segments.length) {
            const result = fileLines.slice(0, startIdx);
            let origConsumed = 0;
            const trailingDecorative = [];
            let lastChange = -1;
            for (let i = 0; i < hunk.segments.length; i++) {
                const t = hunk.segments[i].type;
                if (t === 'added' || t === 'removed') {
                    lastChange = i;
                }
            }
            for (let i = 0; i < hunk.segments.length; i++) {
                const seg = hunk.segments[i];
                const text = String(seg.text ?? '');
                if (seg.type === 'context') {
                    if (i > lastChange) {
                        trailingDecorative.push(text);
                        continue;
                    }
                    result.push(text.endsWith('\n') ? text : text + '\n');
                    origConsumed++;
                } else if (seg.type === 'removed') {
                    origConsumed++;
                } else if (seg.type === 'added') {
                    result.push(text.endsWith('\n') ? text : text + '\n');
                }
            }
            const remainingStart = startIdx + origConsumed;
            if (remainingStart < fileLines.length) {
                result.push(...fileLines.slice(remainingStart));
            } else if (trailingDecorative.length) {
                for (const text of trailingDecorative) {
                    result.push(text.endsWith('\n') ? text : text + '\n');
                }
            }
            return result;
        }

        const linesToRemove = hunk.context.length + hunk.removed.length;
        const result = fileLines.slice(0, startIdx);

        for (const line of hunk.context) {
            result.push(line.endsWith('\n') ? line : line + '\n');
        }

        for (const line of hunk.added) {
            result.push(line.endsWith('\n') ? line : line + '\n');
        }

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
            execFileSync('node', ['--check', filePath], {
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

