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

function extractSourceLocation(errorContext) {
    // Deepest useful (path, line). Prefer last Python File/line; first Node at;
    // PHP #0 (innermost). Mirrors server extract_source_location().
    if (!errorContext) return { path: null, line: null };
    const text = String(errorContext);

    const pyRe = /File\s+["']([^"']+)["']\s*,\s*line\s+(\d+)/gi;
    let pyLast = null;
    let m;
    while ((m = pyRe.exec(text)) !== null) pyLast = m;
    if (pyLast) return { path: pyLast[1], line: parseInt(pyLast[2], 10) };

    // PHP fatals put the throw site in "in /path:line" before #0..#N callers.
    const phpInRe = /\bin\s+((?:\/|[A-Za-z]:[\\/])[^\s:]+?\.\w+)(?::(\d+)|\s+on line\s+(\d+))/gi;
    let phpInFirst = null;
    while ((m = phpInRe.exec(text)) !== null) {
        if (!phpInFirst) phpInFirst = m;
    }
    if (phpInFirst) {
        const line = phpInFirst[2] || phpInFirst[3];
        return { path: phpInFirst[1], line: line ? parseInt(line, 10) : null };
    }

    const phpStackRe = /#(\d+)\s+((?:\/|[A-Za-z]:[\\/])[^\s(]+?\.\w+)\((\d+)\)/g;
    let bestPhp = null;
    while ((m = phpStackRe.exec(text)) !== null) {
        const idx = parseInt(m[1], 10);
        if (!bestPhp || idx < bestPhp.idx) bestPhp = { idx, path: m[2], line: parseInt(m[3], 10) };
    }
    if (bestPhp) return { path: bestPhp.path, line: bestPhp.line };

    const nodeParen = /\((?:file:\/\/)?((?:\/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?\)/;
    m = text.match(nodeParen);
    if (m) return { path: m[1], line: parseInt(m[2], 10) };
    const nodeBare = /\bat\s+(?:file:\/\/)?((?:\/|[A-Za-z]:[\\/])[^\s()]+?\.\w+):(\d+)(?::\d+)?/;
    m = text.match(nodeBare);
    if (m) return { path: m[1], line: parseInt(m[2], 10) };

    const ff = /@((?:\/|[A-Za-z]:[\\/])[^\s:@]+?\.\w+):(\d+)(?::\d+)?/;
    m = text.match(ff);
    if (m) return { path: m[1], line: parseInt(m[2], 10) };

    const fileOnlyRe = /File\s+["']([^"']+)["']/g;
    let fileLast = null;
    while ((m = fileOnlyRe.exec(text)) !== null) fileLast = m;
    if (fileLast) return { path: fileLast[1], line: null };

    return { path: null, line: null };
}

function extractLineNumber(errorContext) {
    if (!errorContext) return null;
    const loc = extractSourceLocation(errorContext);
    if (loc.line != null && !Number.isNaN(loc.line)) return loc.line;
    let last = null;
    for (const pattern of LINE_PATTERNS) {
        const flags = pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`;
        const re = new RegExp(pattern.source, flags);
        let match;
        while ((match = re.exec(String(errorContext))) !== null) {
            const n = parseInt(match[1], 10);
            if (!Number.isNaN(n)) last = n;
        }
        if (last != null) return last;
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
    const resolvedPath = filePath || extractSourceLocation(logLine).path;
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
    extractSourceLocation,
    extractLineNumber,
    readFileContextExcerpt,
    buildIngestFileContext,
    enrichIngestPayloadWithFileContext,
};
