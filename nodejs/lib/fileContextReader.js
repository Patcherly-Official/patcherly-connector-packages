/**
 * Read bounded sanitized file excerpts at ingest time (library-only, no HTTP).
 */

const fs = require('fs');
const path = require('path');
const { sanitizeSensitiveData } = require('../sanitizer.js');

const DEFAULT_CONTEXT_LINES = 50;
const MAX_CONTEXT_LINES = 500;

const LINE_PATTERNS = [
    /on line\s+(\d+)/i,
    /:(\d+)(?::\d+)?\s/,
    /\((\d+)\)\s*$/,
    /, line (\d+)/i,
];

function allowedRoots() {
    const roots = [path.resolve(process.cwd())];
    const configured = process.env.PATCHERLY_TARGET_ROOTS || '';
    if (configured) {
        for (const part of configured.split(path.delimiter)) {
            const trimmed = part && part.trim();
            if (trimmed) roots.push(path.resolve(trimmed));
        }
    }
    return Array.from(new Set(roots));
}

function isPathWithinAllowedRoots(candidatePath) {
    try {
        const resolved = path.resolve(candidatePath);
        let checkPath = resolved;
        if (fs.existsSync(resolved)) {
            try {
                checkPath = fs.realpathSync.native(resolved);
            } catch {
                return false;
            }
        }
        return allowedRoots().some((root) => {
            let rootReal = path.resolve(root);
            if (fs.existsSync(rootReal)) {
                try {
                    rootReal = fs.realpathSync.native(rootReal);
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

function extractLineNumber(errorContext) {
    if (!errorContext) return null;
    for (const pattern of LINE_PATTERNS) {
        const match = String(errorContext).match(pattern);
        if (match) {
            const n = parseInt(match[1], 10);
            if (!Number.isNaN(n)) return n;
        }
    }
    return null;
}

function readFileContextExcerpt(filePath, lineNumber = null, contextLines = DEFAULT_CONTEXT_LINES) {
    const trimmed = String(filePath || '').trim();
    if (!trimmed) return null;
    const window = Math.max(1, Math.min(MAX_CONTEXT_LINES, Number(contextLines) || DEFAULT_CONTEXT_LINES));
    const candidate = path.resolve(trimmed);
    if (!fs.existsSync(candidate) || !fs.statSync(candidate).isFile()) return null;
    let canon;
    try {
        canon = fs.realpathSync.native(candidate);
    } catch {
        return null;
    }
    if (!isPathWithinAllowedRoots(canon)) return null;
    let content;
    try {
        content = fs.readFileSync(canon, 'utf8');
    } catch {
        return null;
    }
    const lines = content.split('\n');
    const totalLines = lines.length;
    let startLine = 1;
    let endLine = totalLines;
    if (lineNumber !== null && lineNumber > 0) {
        startLine = Math.max(1, lineNumber - window);
        endLine = Math.min(totalLines, lineNumber + window);
    }
    const extractedContent = lines.slice(startLine - 1, endLine).join('\n');
    const result = sanitizeSensitiveData(extractedContent);
    return {
        content: result.sanitized_content,
        redacted_ranges: result.redacted_lines,
        start_line: startLine,
        end_line: endLine,
        total_lines: totalLines,
        file_path: trimmed,
        line_number: lineNumber,
    };
}

function buildIngestFileContext(
    logLine,
    captureSource = 'log_monitor',
    filePath = null,
    lineNumber = null,
    contextLines = DEFAULT_CONTEXT_LINES,
) {
  // eslint-disable-next-line global-require
    const { extractFilePath } = require('../node_agent.js');
    const resolvedPath = filePath || extractFilePath(logLine);
    if (!resolvedPath) return null;
    const resolvedLine = lineNumber == null ? extractLineNumber(logLine) : lineNumber;
    const excerpt = readFileContextExcerpt(resolvedPath, resolvedLine, contextLines);
    if (!excerpt) return null;
    excerpt.capture_source = captureSource;
    return excerpt;
}

function enrichIngestPayloadWithFileContext(
    payload,
    logLine,
    captureSource = 'log_monitor',
    filePath = null,
    lineNumber = null,
) {
    const ctx = buildIngestFileContext(logLine, captureSource, filePath, lineNumber);
    if (ctx) payload.ingest_file_context = ctx;
    return payload;
}

module.exports = {
    DEFAULT_CONTEXT_LINES,
    allowedRoots,
    extractLineNumber,
    readFileContextExcerpt,
    buildIngestFileContext,
    enrichIngestPayloadWithFileContext,
};
