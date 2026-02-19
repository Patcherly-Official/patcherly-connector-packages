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
        
        // Connection strings (partial redaction)
        '/(mysql:\/\/|postgresql:\/\/|mongodb:\/\/|redis:\/\/)([^:]+):([^@]+)@/i',
        
        // Email credentials in SMTP
        '/(["\']?)(smtp[_-]?password|mail[_-]?password|email[_-]?password)(["\']?\s*[:=]\s*["\']?)([^"\'\s]+)(["\']?)/i',
        
        // Generic secrets
        '/(["\']?)(secret|private[_-]?key|client[_-]?secret)(["\']?\s*[:=]\s*["\']?)([a-zA-Z0-9_\-+\/=]{16,})(["\']?)/i'
    ];
    
    foreach ($lines as $lineNum => $line) {
        $originalLine = $line;
        $wasRedacted = false;
        
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

