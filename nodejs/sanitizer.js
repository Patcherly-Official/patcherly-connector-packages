/**
 * Sanitizer module for JavaScript/Node.js code.
 *
 * This module provides functions to:
 * 1. Sanitize sensitive data (API keys, passwords, tokens) from JavaScript source code
 * 2. Check if patches are safe to apply (don't overwrite redacted sensitive data)
 *
 * Used by the file content endpoint and AI service to protect sensitive information.
 */

// Patterns that span multiple lines and must run on the whole content BEFORE
// the per-line loop. Same fix as connectors/python/sanitizer.py (1.46.0):
// pasted PEM blocks were never redacted before because the loop only saw one
// line at a time. Line count is preserved by padding the replacement with the
// same number of newlines as the original match.
//
// 1.47.0 (V3): added the canonical OpenSSH "ssh-rsa AAAA…" blob shape so that
// `~/.ssh/id_rsa.pub` dumps printed into a log/error trace get redacted in
// one whole-content sweep.
const MULTILINE_SENSITIVE_PATTERNS = [
    // `[A-Z ]*` (not `+`) so PKCS#8 unencrypted keys (`-----BEGIN PRIVATE KEY-----`
    // with no algorithm prefix — the format `openssl pkcs8` exports for modern
    // Ed25519/RSA/EC keys) get redacted alongside OPENSSH / RSA / DSA / EC /
    // ENCRYPTED PRIVATE KEY blocks.
    { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replacement: 'PRIVATE_KEY_REDACTED' },
    { pattern: /(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\s+AAAA[A-Za-z0-9+/=\s]{40,}(?:\s+[^\s\n]+)?/g, replacement: 'SSH_PUBLIC_KEY_REDACTED' },
];

// Common patterns for sensitive data in JavaScript.
//
// Notes for 1.47.0 (V3, "high-signal vendor tokens"):
//   * The vendor-token regexes below are anchored on canonical vendor
//     PREFIXES (AKIA / ASIA / ghp_ / ghs_ / xoxb- / sk_live_ / whsec_ / …)
//     so they fire on log/trace text, not just on `name = "value"` source.
//   * Each replacement is a fixed placeholder, NEVER a back-reference into
//     the matched value, so the operator's secret cannot leak through the
//     placeholder.
const SENSITIVE_PATTERNS = [
    // API keys and tokens
    { pattern: /['"]([A-Za-z0-9_-]{32,})['"]/, replacement: 'CREDENTIAL_REDACTED' },
    { pattern: /api[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'CREDENTIAL_REDACTED' },
    { pattern: /secret[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'SECRET_KEY_REDACTED' },
    { pattern: /access[_-]?token\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'ACCESS_TOKEN_REDACTED' },
    { pattern: /auth[_-]?token\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AUTH_TOKEN_REDACTED' },
    { pattern: /bearer\s+([A-Za-z0-9._-]{20,})/i, replacement: 'BEARER_TOKEN_REDACTED' },

    // HMAC / JWT / signing secrets (parity with the WordPress + Python connectors)
    { pattern: /(hmac[_-]?secret|signing[_-]?key|encryption[_-]?key)\s*[=:]\s*['"]([^'"]{8,})['"]/i, replacement: 'HMAC_SECRET_REDACTED' },
    { pattern: /(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)\s*[=:]\s*['"]([^'"]{8,})['"]/i, replacement: 'JWT_SECRET_REDACTED' },

    // AWS credentials
    { pattern: /aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AWS_ACCESS_KEY_REDACTED' },
    { pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AWS_SECRET_KEY_REDACTED' },
    // 1.47.0 (V3): canonical AKIA*/ASIA* bare-value match so bare AWS access
    // keys in stack traces / shell history dumps get redacted even when they
    // are not wrapped in an `aws_access_key_id="..."` assignment.
    { pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, replacement: 'AWS_ACCESS_KEY_ID_REDACTED' },

    // 1.47.0 (V3): GitHub tokens (PAT / OAuth / user-to-server /
    // server-to-server / refresh). Spec: 36-255 base62 chars after the prefix.
    { pattern: /\bgh[pousr]_[A-Za-z0-9]{36,255}\b/g, replacement: 'GITHUB_TOKEN_REDACTED' },

    // 1.47.0 (V3): Slack legacy and rotated tokens (bot / user / app / signing).
    { pattern: /\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b/g, replacement: 'SLACK_TOKEN_REDACTED' },
    { pattern: /\bxapp-[0-9]+-[A-Z0-9]+-[A-Za-z0-9]+\b/g, replacement: 'SLACK_APP_TOKEN_REDACTED' },

    // 1.47.0 (V3): Stripe API keys (secret / restricted / publishable / webhook).
    { pattern: /\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,200}\b/g, replacement: 'STRIPE_SECRET_KEY_REDACTED' },
    { pattern: /\bpk_(?:live|test)_[A-Za-z0-9]{20,200}\b/g, replacement: 'STRIPE_PUBLISHABLE_KEY_REDACTED' },
    { pattern: /\bwhsec_[A-Za-z0-9]{20,200}\b/g, replacement: 'STRIPE_WEBHOOK_SECRET_REDACTED' },

    // Database credentials
    { pattern: /password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'PASSWORD_REDACTED' },
    { pattern: /db[_-]?password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'DB_PASSWORD_REDACTED' },
    { pattern: /mongo[_-]?password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'MONGO_PASSWORD_REDACTED' },

    // SMTP / mail credentials (parity with the WordPress + Python connectors)
    { pattern: /(smtp[_-]?password|mail[_-]?password|email[_-]?password)\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'SMTP_PASSWORD_REDACTED' },

    // Connection strings with credentials. 1.47.0 (V3): added `amqp(s)`,
    // `clickhouse(s)`, `mssql`, `oracle`, `jdbc:*://` shapes.
    { pattern: /(postgresql|postgres|mysql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|clickhouse|clickhouses|mssql|oracle):\/\/([^:\s]+):([^@\s]+)@/, replacement: '$1://USERNAME_REDACTED:PASSWORD_REDACTED@' },
    { pattern: /jdbc:([a-z0-9]+):\/\/([^:\s]+):([^@\s]+)@/, replacement: 'jdbc:$1://USERNAME_REDACTED:PASSWORD_REDACTED@' },

    // Environment variable assignments with sensitive names
    { pattern: /process\.env\.(SECRET_KEY|PASSWORD|TOKEN|CREDENTIAL)\s*=\s*['"]([^'"]+)['"]/, replacement: 'SENSITIVE_ENV_REDACTED' },
];

function applyMultilineSensitivePatterns(fileContent) {
    for (const { pattern, replacement } of MULTILINE_SENSITIVE_PATTERNS) {
        fileContent = fileContent.replace(pattern, (match) => {
            const newlines = (match.match(/\n/g) || []).length;
            return replacement + '\n'.repeat(newlines);
        });
    }
    return fileContent;
}

/**
 * Sanitize sensitive data from JavaScript source code.
 *
 * @param {string} fileContent - The raw file content
 * @returns {Object} Object with:
 *   - sanitized_content: The content with sensitive data replaced
 *   - redacted_lines: Array of line numbers that were redacted
 *   - metadata: Object with redaction statistics and warnings
 */
function sanitizeSensitiveData(fileContent) {
    // Pre-pass: redact multi-line PEM blocks at the whole-content level so the
    // per-line loop below can keep operating one line at a time without missing
    // cross-line secrets.
    fileContent = applyMultilineSensitivePatterns(fileContent);

    const lines = fileContent.split('\n');
    const redactedLines = new Set();
    let redactionCount = 0;
    const redactionTypes = {};

    // Lines that the multi-line pre-pass just touched (look for the literal
    // replacement markers — extended in 1.47.0 V3 to also cover SSH public-key
    // blobs).
    const MULTILINE_MARKERS = ['PRIVATE_KEY_REDACTED', 'SSH_PUBLIC_KEY_REDACTED'];
    for (let i = 0; i < lines.length; i++) {
        for (const marker of MULTILINE_MARKERS) {
            if (lines[i].indexOf(marker) !== -1) {
                redactedLines.add(i + 1);
                redactionCount++;
                redactionTypes[marker] = (redactionTypes[marker] || 0) + 1;
                break;
            }
        }
    }

    // Apply all sensitive patterns
    for (const { pattern, replacement } of SENSITIVE_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Skip comments (basic check)
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
                continue;
            }
            
            // Reset lastIndex first: several of the 1.47.0 V3 vendor-token
            // patterns are flagged `/g` so `String.replace` redacts EVERY
            // occurrence on a line. But `RegExp.prototype.test()` advances
            // lastIndex on /g regexes, so without this reset the next line's
            // test would start mid-string and miss matches.
            if (pattern.global) {
                pattern.lastIndex = 0;
            }
            // Check if line matches pattern
            if (pattern.test(line)) {
                // Apply redaction
                const originalLine = line;
                lines[i] = line.replace(pattern, replacement);
                
                if (originalLine !== lines[i]) {
                    redactedLines.add(i + 1); // 1-indexed
                    redactionCount++;
                    
                    // Track redaction type
                    const redactionType = replacement;
                    redactionTypes[redactionType] = (redactionTypes[redactionType] || 0) + 1;
                }
            }
        }
    }
    
    const sanitizedContent = lines.join('\n');
    const redactedLinesArray = Array.from(redactedLines).sort((a, b) => a - b);
    
    const metadata = {
        redaction_count: redactionCount,
        redaction_types: redactionTypes,
        has_redactions: redactionCount > 0,
        redacted_lines_count: redactedLinesArray.length,
        warning: redactionCount > 0 ? 'This file contains sensitive data that has been redacted' : null
    };
    
    return {
        sanitized_content: sanitizedContent,
        redacted_lines: redactedLinesArray,
        metadata: metadata
    };
}

/**
 * Check if a patch is safe to apply (doesn't modify redacted lines).
 *
 * @param {string} patchContent - The unified diff patch content
 * @param {Array<number>} redactedLines - Array of line numbers that were redacted
 * @param {string} filePath - Path to the file being patched
 * @returns {Object} Object with:
 *   - is_safe: Boolean indicating if patch is safe
 *   - reason: If not safe, explanation of why (null if safe)
 */
function isPatchSafeToApply(patchContent, redactedLines, filePath) {
    if (!redactedLines || redactedLines.length === 0) {
        return { is_safe: true, reason: null };
    }
    
    // Parse unified diff format to extract modified lines
    const modifiedLines = new Set();
    let currentLine = null;
    
    const lines = patchContent.split('\n');
    for (const line of lines) {
        // Parse hunk header
        const hunkMatch = line.match(/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/);
        if (hunkMatch) {
            currentLine = parseInt(hunkMatch[3], 10); // Starting line in new file
        } else if (currentLine !== null) {
            if (line.startsWith('+')) {
                modifiedLines.add(currentLine);
                currentLine++;
            } else if (line.startsWith('-')) {
                // Deleted line doesn't increment current_line
            } else if (line.startsWith(' ')) {
                // Context line
                currentLine++;
            }
        }
    }
    
    // Check if any modified lines overlap with redacted lines
    const overlappingLines = Array.from(modifiedLines).filter(line => redactedLines.includes(line));
    
    if (overlappingLines.length > 0) {
        return {
            is_safe: false,
            reason: `Patch attempts to modify redacted sensitive data on lines: ${overlappingLines.sort((a, b) => a - b).join(', ')}`
        };
    }
    
    return { is_safe: true, reason: null };
}

/**
 * Generate a human-readable summary of redactions.
 *
 * @param {Object} metadata - Metadata from sanitizeSensitiveData()
 * @returns {string} Human-readable summary string
 */
function getRedactionSummary(metadata) {
    if (!metadata.has_redactions) {
        return "No sensitive data detected in this file.";
    }
    
    const count = metadata.redaction_count;
    const linesCount = metadata.redacted_lines_count;
    const types = metadata.redaction_types;
    
    const summaryParts = [
        `Redacted ${count} sensitive value(s) across ${linesCount} line(s):`
    ];
    
    for (const [redactionType, typeCount] of Object.entries(types)) {
        summaryParts.push(`  - ${redactionType}: ${typeCount} occurrence(s)`);
    }
    
    return summaryParts.join('\n');
}

/**
 * Mask a sensitive value, revealing only the last N characters.
 *
 * @param {string} value - The sensitive value to mask
 * @param {number} revealChars - Number of characters to reveal at the end
 * @returns {string} Masked value (e.g., "****abcd")
 */
function maskSensitiveValue(value, revealChars = 4) {
    if (value.length <= revealChars) {
        return '*'.repeat(value.length);
    }
    
    return '*'.repeat(value.length - revealChars) + value.slice(-revealChars);
}

/**
 * Best-effort redaction on log/trace text before ingest (same patterns as file sanitization).
 * @param {string} text
 * @returns {string}
 */
function sanitizeLogLineForIngest(text) {
    if (text == null || typeof text !== 'string') {
        return '';
    }
    return sanitizeSensitiveData(text).sanitized_content;
}

module.exports = {
    sanitizeSensitiveData,
    isPatchSafeToApply,
    getRedactionSummary,
    maskSensitiveValue,
    sanitizeLogLineForIngest
};

