<?php
/**
 * Sanitizer: strip credentials, private keys, and tokens from code before sending it to the AI.
 */

if (!defined('ABSPATH')) { exit; }

/**
 * @param string $content
 * @return array{content:string, redacted_ranges:array} Sanitized content + line ranges that were redacted.
 */
function patcherly_sanitize_sensitive_data($content) {
    // Whole-content sweep for multi-line secrets (PEM private keys, OpenSSH public-key blobs).
    // The per-line loop below can't see across lines; line count is preserved by padding with newlines.
    $multiline_patterns = [
        // `[A-Z ]*` (not `+`) so PKCS#8 unencrypted PRIVATE KEY blocks match alongside OPENSSH/RSA/DSA/EC/ENCRYPTED.
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

    // Whole-content sweep for connection-string URIs (3 groups — doesn't fit the 5-group per-line template).
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

    // High-signal vendor token bare-value patterns. Replacements MUST be fixed strings, never a
    // back-reference into the match, so the secret can't leak through the placeholder.
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

    // Per-line `key = "value"` patterns. Connection strings stay in the whole-content pre-pass
    // because their 3-group regex doesn't fit the `$1$2$3[REDACTED]$5` template used here.
    $patterns = [
        '/(["\']?)(api[_-]?key|apikey|api[_-]?secret|access[_-]?key|secret[_-]?key|auth[_-]?token|bearer[_-]?token)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-]{20,})(["\']?)/i',
        '/(["\']?)(password|passwd|pwd|pass)(["\']?\s*[:=]\s*["\']?)([^"\'\s]{6,})(["\']?)/i',
        '/(["\']?)(db[_-]?password|db[_-]?pass|database[_-]?password|mysql[_-]?password)(["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)/i',
        '/(define\s*\(\s*["\'])(DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)(["\'],\s*["\'])([^"\']+)(["\'])/i',
        '/(["\']?)(hmac[_-]?secret|signing[_-]?key|encryption[_-]?key)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i',
        '/(["\']?)(jwt[_-]?secret|jwt[_-]?key|token[_-]?secret)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i',
        '/(["\']?)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)(["\']?\s*[:=]\s*["\']?)([A-Z0-9]{16,})(["\']?)/i',
        '/(["\']?)(smtp[_-]?password|mail[_-]?password|email[_-]?password)(["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)/i',
        '/(["\']?)(secret|private[_-]?key|client[_-]?secret)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i'
    ];

    // Lines containing any of these markers were already redacted by the whole-content sweeps.
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

        foreach ($prepass_markers as $prepass_marker) {
            if (strpos($line, $prepass_marker) !== false) {
                $wasRedacted = true;
                break;
            }
        }

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $line)) {
                $line = preg_replace($pattern, '$1$2$3[REDACTED]$5', $line);
                $wasRedacted = true;
            }
        }

        if ($wasRedacted) {
            $redactedRanges[] = [$lineNum + 1, $lineNum + 1];
        }

        $sanitizedLines[] = $line;
    }

    $mergedRanges = [];
    foreach ($redactedRanges as $range) {
        if (empty($mergedRanges)) {
            $mergedRanges[] = $range;
        } else {
            $lastRange = &$mergedRanges[count($mergedRanges) - 1];
            if ($range[0] <= $lastRange[1] + 1) {
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
 * True iff the patch does not modify any line covered by $redactedRanges.
 *
 * @param array $redactedRanges Array of [start_line, end_line] ranges (1-indexed, inclusive).
 * @return array{is_safe:bool, conflicts:array<int>}
 */
function patcherly_is_patch_safe_to_apply($patch, $redactedRanges) {
    if (empty($redactedRanges)) {
        return ['is_safe' => true, 'conflicts' => []];
    }

    $conflicts = [];
    $lines = explode("\n", $patch);
    $currentLine = 0;

    foreach ($lines as $line) {
        if (preg_match('/^@@ -(\d+),?(\d+)? \+(\d+),?(\d+)? @@/', $line, $matches)) {
            $currentLine = intval($matches[3]);
            continue;
        }

        if (preg_match('/^[\+\-]/', $line) && !preg_match('/^[\+\-]{3}/', $line)) {
            foreach ($redactedRanges as $range) {
                if ($currentLine >= $range[0] && $currentLine <= $range[1]) {
                    $conflicts[] = $currentLine;
                    break;
                }
            }

            // Deletions don't advance the line cursor (the line is removed).
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

/** Alias preserved for callers in the file-content path. */
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

