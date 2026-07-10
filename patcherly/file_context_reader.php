<?php
/**
 * Standalone file-context excerpt reader for ingest and inbound file-content callbacks.
 *
 * Library-only — must NOT register wp_ajax actions. Loaded by the main plugin and Rescue MU-plugin.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_path_is_within')) {
    /**
     * Defence-in-depth path containment: candidate must equal $root or be a real descendant.
     *
     * @param string $candidate realpath()-canonical file path
     * @param string $root      realpath()-canonical root directory
     */
    function patcherly_path_is_within($candidate, $root): bool {
        if (!is_string($candidate) || $candidate === '' || !is_string($root) || $root === '') {
            return false;
        }
        $root_real = realpath($root);
        if ($root_real === false) {
            return false;
        }
        $root_with_sep = rtrim($root_real, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        return $candidate === $root_real || strpos($candidate, $root_with_sep) === 0;
    }
}

if (!function_exists('patcherly_ingest_file_context_default_lines')) {
    /** Default excerpt window at ingest (matches basic fix tier). */
    function patcherly_ingest_file_context_default_lines(): int {
        return 50;
    }
}

if (!function_exists('patcherly_file_context_allowed_roots')) {
    /**
     * @return list<string> Canonical allowed roots for WordPress file reads.
     */
    function patcherly_file_context_allowed_roots(): array {
        $roots = [];
        if (defined('ABSPATH') && is_string(ABSPATH) && ABSPATH !== '') {
            $roots[] = ABSPATH;
        }
        if (function_exists('wp_upload_dir')) {
            $uploads = wp_upload_dir();
            if (is_array($uploads) && !empty($uploads['basedir']) && is_string($uploads['basedir'])) {
                $roots[] = $uploads['basedir'];
            }
        }
        return $roots;
    }
}

if (!function_exists('patcherly_file_context_path_allowed')) {
    function patcherly_file_context_path_allowed(string $real_path): bool {
        foreach (patcherly_file_context_allowed_roots() as $root) {
            if (patcherly_path_is_within($real_path, $root)) {
                return true;
            }
        }
        return false;
    }
}

if (!function_exists('patcherly_ensure_file_context_helpers')) {
    function patcherly_ensure_file_context_helpers(): void {
        if (!function_exists('patcherly_extract_file_path')) {
            $path_extract = __DIR__ . '/path_extract.php';
            if (is_readable($path_extract)) {
                require_once $path_extract;
            }
        }
        if (!function_exists('patcherly_sanitize_sensitive_data')) {
            $sanitizer = __DIR__ . '/sanitizer.php';
            if (is_readable($sanitizer)) {
                require_once $sanitizer;
            }
        }
    }
}

if (!function_exists('patcherly_read_file_context_excerpt')) {
    /**
     * Read a bounded sanitized excerpt from disk (same shape as ajax file-content success).
     *
     * @return array<string,mixed>|null
     */
    function patcherly_read_file_context_excerpt(
        string $file_path,
        ?int $line_number = null,
        int $context_lines = 50
    ): ?array {
        patcherly_ensure_file_context_helpers();
        $file_path = trim($file_path);
        if ($file_path === '') {
            return null;
        }
        $context_lines = max(1, min(500, $context_lines));
        $real_path = realpath($file_path);
        if ($real_path === false || !is_file($real_path)) {
            return null;
        }
        if (!patcherly_file_context_path_allowed($real_path)) {
            return null;
        }
        $file_contents = @file_get_contents($real_path);
        if ($file_contents === false) {
            return null;
        }
        $lines = explode("\n", $file_contents);
        $total_lines = count($lines);
        $start_line = 1;
        $end_line = $total_lines;
        if ($line_number !== null && $line_number > 0) {
            $start_line = max(1, $line_number - $context_lines);
            $end_line = min($total_lines, $line_number + $context_lines);
        }
        $extracted_lines = array_slice($lines, $start_line - 1, $end_line - $start_line + 1);
        $content = implode("\n", $extracted_lines);
        if (!function_exists('patcherly_sanitize_sensitive_data')) {
            return null;
        }
        $result = patcherly_sanitize_sensitive_data($content);
        return [
            'content' => $result['content'],
            'redacted_ranges' => $result['redacted_ranges'],
            'start_line' => $start_line,
            'end_line' => $end_line,
            'total_lines' => $total_lines,
            'file_path' => $file_path,
            'line_number' => $line_number,
        ];
    }
}

if (!function_exists('patcherly_build_ingest_file_context')) {
    /**
     * Build ingest_file_context object for a log line or explicit path/line.
     *
     * @return array<string,mixed>|null
     */
    function patcherly_build_ingest_file_context(
        string $log_line,
        string $capture_source = 'log_monitor',
        ?string $file_path = null,
        ?int $line_number = null,
        int $context_lines = 50
    ): ?array {
        patcherly_ensure_file_context_helpers();
        if ($file_path === null || $file_path === '') {
            $file_path = function_exists('patcherly_extract_file_path')
                ? patcherly_extract_file_path($log_line)
                : null;
        }
        if (!$file_path) {
            return null;
        }
        if ($line_number === null && function_exists('patcherly_extract_line_number')) {
            $line_number = patcherly_extract_line_number($log_line);
        }
        $excerpt = patcherly_read_file_context_excerpt($file_path, $line_number, $context_lines);
        if ($excerpt === null) {
            return null;
        }
        $excerpt['capture_source'] = $capture_source;
        return $excerpt;
    }
}

if (!function_exists('patcherly_enrich_ingest_payload_with_file_context')) {
    /**
     * Attach ingest_file_context to a connector ingest payload when readable.
     *
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    function patcherly_enrich_ingest_payload_with_file_context(
        array $payload,
        string $log_line,
        string $capture_source = 'log_monitor',
        ?string $file_path = null,
        ?int $line_number = null
    ): array {
        $ctx = patcherly_build_ingest_file_context(
            $log_line,
            $capture_source,
            $file_path,
            $line_number,
            patcherly_ingest_file_context_default_lines()
        );
        if ($ctx !== null) {
            $payload['ingest_file_context'] = $ctx;
        }
        return $payload;
    }
}
