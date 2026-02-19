/**
 * Sanitizer module for JavaScript/Node.js code.
 *
 * This module provides functions to:
 * 1. Sanitize sensitive data (API keys, passwords, tokens) from JavaScript source code
 * 2. Check if patches are safe to apply (don't overwrite redacted sensitive data)
 *
 * Used by the file content endpoint and AI service to protect sensitive information.
 */

// Common patterns for sensitive data in JavaScript
const SENSITIVE_PATTERNS = [
    // API keys and tokens
    { pattern: /['"]([A-Za-z0-9_-]{32,})['"]/, replacement: 'API_KEY_REDACTED' },
    { pattern: /api[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'API_KEY_REDACTED' },
    { pattern: /secret[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'SECRET_KEY_REDACTED' },
    { pattern: /access[_-]?token\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'ACCESS_TOKEN_REDACTED' },
    { pattern: /auth[_-]?token\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AUTH_TOKEN_REDACTED' },
    { pattern: /bearer\s+([A-Za-z0-9._-]{20,})/i, replacement: 'BEARER_TOKEN_REDACTED' },
    
    // AWS credentials
    { pattern: /aws[_-]?access[_-]?key[_-]?id\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AWS_ACCESS_KEY_REDACTED' },
    { pattern: /aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'AWS_SECRET_KEY_REDACTED' },
    
    // Database credentials
    { pattern: /password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'PASSWORD_REDACTED' },
    { pattern: /db[_-]?password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'DB_PASSWORD_REDACTED' },
    { pattern: /mongo[_-]?password\s*[=:]\s*['"]([^'"]+)['"]/i, replacement: 'MONGO_PASSWORD_REDACTED' },
    
    // Connection strings with credentials
    { pattern: /(mongodb|mysql|postgresql):\/\/([^:]+):([^@]+)@/, replacement: '$1://USERNAME_REDACTED:PASSWORD_REDACTED@' },
    
    // Environment variable assignments with sensitive names
    { pattern: /process\.env\.(API_KEY|SECRET_KEY|PASSWORD|TOKEN)\s*=\s*['"]([^'"]+)['"]/, replacement: 'SENSITIVE_ENV_REDACTED' },
];

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
    const lines = fileContent.split('\n');
    const redactedLines = new Set();
    let redactionCount = 0;
    const redactionTypes = {};
    
    // Apply all sensitive patterns
    for (const { pattern, replacement } of SENSITIVE_PATTERNS) {
        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            
            // Skip comments (basic check)
            const trimmed = line.trim();
            if (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*')) {
                continue;
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

module.exports = {
    sanitizeSensitiveData,
    isPatchSafeToApply,
    getRedactionSummary,
    maskSensitiveValue
};

