<?php
/**
 * Sanitizer for WordPress Patcherly Plugin
 * Removes sensitive data (API keys, passwords, credentials) from code before sending to AI
 */

if (!defined('ABSPATH')) { exit; }

/**
 * Sanitize sensitive data from code content
 * 
 * @param string $content The code content to sanitize
 * @return array Array with 'content' (sanitized) and 'redacted_ranges' (line ranges)
 */
function patcherly_sanitize_sensitive_data($content) {
    // Pre-pass: redact multi-line PEM blocks at the whole-content level. The
    // line-by-line loop below can't see across lines, so without this the
    // pasted private key block would silently leak (parity with the Python /
    // Node / PHP-standalone connector sanitizers, 1.46.0 follow-up). Line
    // count is preserved by padding the replacement with the same number of
    // newlines as the original match.
    $multiline_patterns = [
        '/-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]*?-----END [A-Z ]+PRIVATE KEY-----/' => 'PRIVATE_KEY_REDACTED',
    ];
    foreach ($multiline_patterns as $multi_pattern => $multi_replacement) {
        $content = preg_replace_callback(
            $multi_pattern,
            function ($match) use ($multi_replacement) {
                return $multi_replacement . str_repeat("\n", substr_count($match[0], "\n"));
            },
            $content
        );
    }

    // Pre-pass: patterns that DON'T fit the 5-group `$1$2$3[REDACTED]$5`
    // template used by the per-line loop below (connection strings have 3
    // groups, bearer tokens have 2). Before 1.46.0 these were squeezed into
    // the per-line loop with the wrong replacement template, which produced a
    // partial-redaction bug: `postgresql://app:hunter2@db.internal/...` came
    // out as `postgresql://apphunter2[REDACTED]db.internal/...` -- the
    // password was joined onto the username and remained in the output.
    $content = preg_replace(
        '/(mysql|pgsql|postgresql|mongodb|redis):\/\/([^:]+):([^@]+)@/i',
        '$1://USERNAME_REDACTED:PASSWORD_REDACTED@',
        $content
    );
    $content = preg_replace(
        '/(bearer\s+)([A-Za-z0-9._-]{20,})/i',
        '$1[REDACTED]',
        $content
    );

    $lines = explode("\n", $content);
    $redactedRanges = [];
    $sanitizedLines = [];

    // Patterns for sensitive data detection
    $patterns = [
        // API Keys, Tokens, Secrets
        '/(["\']?)(api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer[_-]?token)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{20,})(["\']?)/i',
        
        // Passwords
        '/(["\']?)(password|passwd|pwd|pass)(["\']?\s*[:=]\s*["\']?)([^"\'\s]{6,})(["\']?)/i',
        
        // Database credentials
        '/(["\']?)(db[_-]?password|db[_-]?pass|database[_-]?password|mysql[_-]?password)(["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)/i',
        
        // WordPress constants
        '/(define\s*\(\s*["\'])(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)(["\'],\s*["\'])([^"\']+)(["\'])/i',
        
        // HMAC secrets
        '/(["\']?)(hmac[_-]?secret|signing[_-]?key|encryption[_-]?key)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i',
        
        // JWT secrets
        '/(["\']?)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i',
        
        // AWS credentials
        '/(["\']?)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)(["\']?\s*[:=]\s*["\']?)([A-Z0-9]{16,})(["\']?)/i',

        // (Connection strings are handled by the content-level pre-pass above
        // because their 3-group regex doesn't fit this loop's
        // `$1$2$3[REDACTED]$5` template and used to leave the password joined
        // to the username in the output -- see the comment near the pre-pass.)

        // Email credentials in SMTP
        '/(["\']?)(smtp[_-]?password|mail[_-]?password|email[_-]?password)(["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)/i',
        
        // Generic secrets
        '/(["\']?)(secret|private[_-]?key|client[_-]?secret)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i'
    ];
    
    foreach ($lines as $lineNum => $line) {
        $originalLine = $line;
        $wasRedacted = false;

        // Lines touched by the multi-line PEM pre-pass already contain the
        // replacement marker.
        if (strpos($line, 'PRIVATE_KEY_REDACTED') !== false) {
            $wasRedacted = true;
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                // Replace sensitive value with [REDACTED]
                $line = preg_replace($pattern, '$1$2$3[REDACTED]$5', $line);
                $wasRedacted = true;
            }
        }

        // Track redacted line ranges
        if ($wasRedacted) {
            $redactedRanges[] = [$lineNum + 1, $lineNum + 1];
        }

        $sanitizedLines[] = $line;
    }
    
    // Merge consecutive redacted ranges
    $mergedRanges = [];
    foreach ($redactedRanges as $range) {
        if (empty($mergedRanges)) {
            $mergedRanges[] = $range;
        } else {
            $lastRange = &$mergedRanges[count($mergedRanges) - 1];
            if ($range[0] <= $lastRange[1] + 1) {
                // Merge consecutive ranges
                $lastRange[1] = max($lastRange[1], $range[1]);
            } else {
                $mergedRanges[] = $range;
            }
        }
    }
    
    return [
        'content' => implode("\n", $sanitizedLines),
        'redacted_ranges' => $mergedRanges
    ];
}

/**
 * Check if a patch is safe to apply (doesn't modify redacted lines)
 * 
 * @param string $patch The unified diff patch
 * @param array $redactedRanges Array of [start_line, end_line] ranges
 * @return array Array with 'is_safe' (bool) and 'conflicts' (array of conflicting line numbers)
 */
function patcherly_is_patch_safe_to_apply($patch, $redactedRanges) {
    if (empty($redactedRanges)) {
        return ['is_safe' => true, 'conflicts' => []];
    }
    
    $conflicts = [];
    $lines = explode("\n", $patch);
    $currentLine = 0;
    
    foreach ($lines as $line) {
        // Parse unified diff format to track line numbers
        if (preg_match('/^@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@/', $line, $matches)) {
            // New hunk starting at line $matches[3]
            $currentLine = intval($matches[3]);
            continue;
        }
        
        // Check if this line modifies content
        if (preg_match('/^[\+\-]/', $line) && !preg_match('/^[\+\-]{3}/', $line)) {
            // This is a modification line
            foreach ($redactedRanges as $range) {
                if ($currentLine >= $range[0] && $currentLine <= $range[1]) {
                    $conflicts[] = $currentLine;
                    break;
                }
            }
            
            // Only increment line number for context and additions (not deletions)
            if (substr($line, 0, 1) !== '-') {
                $currentLine++;
            }
        } elseif (substr($line, 0, 1) === ' ') {
            // Context line
            $currentLine++;
        }
    }
    
    return [
        'is_safe' => empty($conflicts),
        'conflicts' => array_unique($conflicts)
    ];
}

/**
 * Wrapper function for use in file content retrieval
 * 
 * @param string $content The code content to sanitize
 * @return array Array with 'content' (sanitized) and 'redacted_ranges' (line ranges)
 */
function patcherly_sanitize_php_code($content) {
    return patcherly_sanitize_sensitive_data($content);
}

/**
 * Best-effort secret redaction on log/trace text before ingest (same patterns as file content).
 *
 * @param string $log_line Raw log line or multi-line error text.
 * @return string Sanitized text for API payload.
 */
function patcherly_sanitize_log_line_for_ingest($log_line) {
    if (!is_string($log_line) || $log_line === '') {
        return is_string($log_line) ? $log_line : '';
    }
    $out = patcherly_sanitize_sensitive_data($log_line);

    return $out['content'];
}

