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
    //
    // 1.47.0 (V3): also redacts the canonical OpenSSH "ssh-rsa AAAA…" public
    // key blob shape so `~/.ssh/id_rsa.pub` dumps printed into a log/error
    // trace get redacted in one whole-content sweep.
    $multiline_patterns = [
        // `[A-Z ]*` (not `+`) so PKCS#8 unencrypted keys
        // (`-----BEGIN PRIVATE KEY-----` with no algorithm prefix — the
        // format `openssl pkcs8` exports for modern Ed25519/RSA/EC keys)
        // get redacted alongside OPENSSH / RSA / DSA / EC / ENCRYPTED
        // PRIVATE KEY blocks.
        '/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/' => 'PRIVATE_KEY_REDACTED',
        '/(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp(?:256|384|521))\s+AAAA[A-Za-z0-9+\/=\s]{40,}(?:\s+[^\s\n]+)?/' => 'SSH_PUBLIC_KEY_REDACTED',
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
    //
    // 1.47.0 (V3): connection-string scheme list extended (amqp, clickhouse,
    // mssql, oracle, jdbc:*) so RabbitMQ / ClickHouse / SQL Server / Oracle
    // URIs in error traces get redacted alongside the original SQL/NoSQL ones.
    $content = preg_replace(
        '/(postgres|postgresql|mysql|pgsql|mongodb|mongodb\+srv|redis|rediss|amqp|amqps|clickhouse|clickhouses|mssql|oracle):\/\/([^:\s]+):([^@\s]+)@/i',
        '$1://USERNAME_REDACTED:PASSWORD_REDACTED@',
        $content
    );
    $content = preg_replace(
        '/jdbc:([a-z0-9]+):\/\/([^:\s]+):([^@\s]+)@/i',
        'jdbc:$1://USERNAME_REDACTED:PASSWORD_REDACTED@',
        $content
    );
    $content = preg_replace(
        '/(bearer\s+)([A-Za-z0-9._-]{20,})/i',
        '$1[REDACTED]',
        $content
    );

    // 1.47.0 (V3): high-signal vendor token bare-value patterns. Each
    // replacement is a fixed placeholder string (NEVER a back-reference into
    // the matched value) so the operator's secret cannot leak through the
    // placeholder. These run at the whole-content level so they fire on log /
    // trace text not wrapped in a `key = "value"` assignment.
    $vendor_value_patterns = [
        '/\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/' => 'AWS_ACCESS_KEY_ID_REDACTED',
        '/\bgh[pousr]_[A-Za-z0-9]{36,255}\b/' => 'GITHUB_TOKEN_REDACTED',
        '/\bxox[abeoprs]-[A-Za-z0-9-]{10,}\b/' => 'SLACK_TOKEN_REDACTED',
        '/\bxapp-[0-9]+-[A-Z0-9]+-[A-Za-z0-9]+\b/' => 'SLACK_APP_TOKEN_REDACTED',
        '/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_SECRET_KEY_REDACTED',
        '/\bpk_(?:live|test)_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_PUBLISHABLE_KEY_REDACTED',
        '/\bwhsec_[A-Za-z0-9]{20,200}\b/' => 'STRIPE_WEBHOOK_SECRET_REDACTED',
    ];
    foreach ($vendor_value_patterns as $vendor_pattern => $vendor_marker) {
        $content = preg_replace($vendor_pattern, $vendor_marker, $content);
    }

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
    
    // Pre-pass markers — any of these on a line means it was already redacted
    // by one of the whole-content sweeps above (multi-line PEM/SSH blobs,
    // connection strings, bearer tokens, or 1.47.0 V3 vendor tokens).
    $prepass_markers = [
        'PRIVATE_KEY_REDACTED',
        'SSH_PUBLIC_KEY_REDACTED',
        'AWS_ACCESS_KEY_ID_REDACTED',
        'GITHUB_TOKEN_REDACTED',
        'SLACK_TOKEN_REDACTED',
        'SLACK_APP_TOKEN_REDACTED',
        'STRIPE_SECRET_KEY_REDACTED',
        'STRIPE_PUBLISHABLE_KEY_REDACTED',
        'STRIPE_WEBHOOK_SECRET_REDACTED',
        'USERNAME_REDACTED:PASSWORD_REDACTED',
    ];

    foreach ($lines as $lineNum => $line) {
        $originalLine = $line;
        $wasRedacted = false;

        // Lines touched by any whole-content pre-pass already contain a
        // replacement marker.
        foreach ($prepass_markers as $prepass_marker) {
            if (strpos($line, $prepass_marker) !== false) {
                $wasRedacted = true;
                break;
            }
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

