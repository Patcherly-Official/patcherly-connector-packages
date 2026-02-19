<?php
/**
 * Sanitizer module for PHP code.
 *
 * This module provides functions to:
 * 1. Sanitize sensitive data (API keys, passwords, tokens) from PHP source code
 * 2. Check if patches are safe to apply (don't overwrite redacted sensitive data)
 *
 * Used by the file content endpoint and AI service to protect sensitive information.
 */

namespace Patcherly\Connector;

class Sanitizer
{
    /**
     * Common patterns for sensitive data in PHP
     */
    private const SENSITIVE_PATTERNS = [
        // API keys and tokens
        '/["\']([A-Za-z0-9_-]{32,})["\']/' => 'API_KEY_REDACTED',
        '/\$api[_-]?key\s*=\s*["\']([^"\']+)["\']/' => 'API_KEY_REDACTED',
        '/\$secret[_-]?key\s*=\s*["\']([^"\']+)["\']/' => 'SECRET_KEY_REDACTED',
        '/\$access[_-]?token\s*=\s*["\']([^"\']+)["\']/' => 'ACCESS_TOKEN_REDACTED',
        '/\$auth[_-]?token\s*=\s*["\']([^"\']+)["\']/' => 'AUTH_TOKEN_REDACTED',
        
        // Database credentials
        '/\$password\s*=\s*["\']([^"\']+)["\']/' => 'PASSWORD_REDACTED',
        '/\$db[_-]?password\s*=\s*["\']([^"\']+)["\']/' => 'DB_PASSWORD_REDACTED',
        '/\$mysql[_-]?password\s*=\s*["\']([^"\']+)["\']/' => 'MYSQL_PASSWORD_REDACTED',
        
        // define() constants with sensitive names
        '/define\s*\(\s*["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\s*,\s*["\']([^"\']+)["\']\s*\)/' => 'SENSITIVE_DEFINE_REDACTED',
        
        // Connection strings with credentials
        '/(mysql|pgsql|mongodb):\/\/([^:]+):([^@]+)@/' => '\1://USERNAME_REDACTED:PASSWORD_REDACTED@',
        
        // $_ENV and getenv() with sensitive names
        '/\$_ENV\[["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\]/' => 'SENSITIVE_ENV_REDACTED',
        '/getenv\(["\']?(API_KEY|SECRET_KEY|PASSWORD|TOKEN)["\']?\)/' => 'SENSITIVE_ENV_REDACTED',
    ];

    /**
     * Sanitize sensitive data from PHP source code.
     *
     * @param string $fileContent The raw file content
     * @return array Associative array with:
     *   - sanitized_content: The content with sensitive data replaced
     *   - redacted_lines: Array of line numbers that were redacted
     *   - metadata: Array with redaction statistics and warnings
     */
    public static function sanitizeSensitiveData(string $fileContent): array
    {
        $lines = explode("\n", $fileContent);
        $redactedLines = [];
        $redactionCount = 0;
        $redactionTypes = [];
        
        foreach (self::SENSITIVE_PATTERNS as $pattern => $replacement) {
            foreach ($lines as $i => $line) {
                // Skip comments (basic check)
                if (preg_match('/^\s*\/\//', $line) || preg_match('/^\s*#/', $line) || preg_match('/^\s*\/\*/', $line)) {
                    continue;
                }
                
                // Check if line matches pattern
                if (preg_match($pattern, $line)) {
                    // Apply redaction
                    $originalLine = $line;
                    $line = preg_replace($pattern, $replacement, $line);
                    
                    if ($originalLine !== $line) {
                        $lines[$i] = $line;
                        $redactedLines[] = $i + 1; // 1-indexed
                        $redactionCount++;
                        
                        // Track redaction type
                        $redactionType = is_string($replacement) ? $replacement : 'PATTERN_REDACTED';
                        if (!isset($redactionTypes[$redactionType])) {
                            $redactionTypes[$redactionType] = 0;
                        }
                        $redactionTypes[$redactionType]++;
                    }
                }
            }
        }
        
        $sanitizedContent = implode("\n", $lines);
        $redactedLines = array_unique($redactedLines);
        sort($redactedLines);
        
        $metadata = [
            'redaction_count' => $redactionCount,
            'redaction_types' => $redactionTypes,
            'has_redactions' => $redactionCount > 0,
            'redacted_lines_count' => count($redactedLines),
            'warning' => $redactionCount > 0 ? 'This file contains sensitive data that has been redacted' : null
        ];
        
        return [
            'sanitized_content' => $sanitizedContent,
            'redacted_lines' => $redactedLines,
            'metadata' => $metadata
        ];
    }

    /**
     * Check if a patch is safe to apply (doesn't modify redacted lines).
     *
     * @param string $patchContent The unified diff patch content
     * @param array $redactedLines Array of line numbers that were redacted
     * @param string $filePath Path to the file being patched
     * @return array Associative array with:
     *   - is_safe: Boolean indicating if patch is safe
     *   - reason: If not safe, explanation of why (null if safe)
     */
    public static function isPatchSafeToApply(string $patchContent, array $redactedLines, string $filePath): array
    {
        if (empty($redactedLines)) {
            return ['is_safe' => true, 'reason' => null];
        }
        
        // Parse unified diff format to extract modified lines
        $modifiedLines = [];
        $currentLine = null;
        
        foreach (explode("\n", $patchContent) as $line) {
            // Parse hunk header
            if (preg_match('/@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/', $line, $matches)) {
                $currentLine = (int)$matches[3]; // Starting line in new file
            } elseif ($currentLine !== null) {
                if (strpos($line, '+') === 0) {
                    $modifiedLines[] = $currentLine;
                    $currentLine++;
                } elseif (strpos($line, '-') === 0) {
                    // Deleted line doesn't increment current_line
                } elseif (strpos($line, ' ') === 0) {
                    // Context line
                    $currentLine++;
                }
            }
        }
        
        // Check if any modified lines overlap with redacted lines
        $overlappingLines = array_intersect($modifiedLines, $redactedLines);
        
        if (!empty($overlappingLines)) {
            sort($overlappingLines);
            return [
                'is_safe' => false,
                'reason' => 'Patch attempts to modify redacted sensitive data on lines: ' . implode(', ', $overlappingLines)
            ];
        }
        
        return ['is_safe' => true, 'reason' => null];
    }

    /**
     * Generate a human-readable summary of redactions.
     *
     * @param array $metadata Metadata from sanitizeSensitiveData()
     * @return string Human-readable summary string
     */
    public static function getRedactionSummary(array $metadata): string
    {
        if (!$metadata['has_redactions']) {
            return "No sensitive data detected in this file.";
        }
        
        $count = $metadata['redaction_count'];
        $linesCount = $metadata['redacted_lines_count'];
        $types = $metadata['redaction_types'];
        
        $summaryParts = [
            "Redacted {$count} sensitive value(s) across {$linesCount} line(s):"
        ];
        
        foreach ($types as $redactionType => $typeCount) {
            $summaryParts[] = "  - {$redactionType}: {$typeCount} occurrence(s)";
        }
        
        return implode("\n", $summaryParts);
    }

    /**
     * Mask a sensitive value, revealing only the last N characters.
     *
     * @param string $value The sensitive value to mask
     * @param int $revealChars Number of characters to reveal at the end
     * @return string Masked value (e.g., "****abcd")
     */
    public static function maskSensitiveValue(string $value, int $revealChars = 4): string
    {
        $length = strlen($value);
        
        if ($length <= $revealChars) {
            return str_repeat('*', $length);
        }
        
        return str_repeat('*', $length - $revealChars) . substr($value, -$revealChars);
    }
}

