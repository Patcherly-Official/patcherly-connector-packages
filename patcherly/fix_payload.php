<?php
/**
 * Shared helpers for GET /fix AnalysisResult payloads (main + rescue apply paths).
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_unwrap_patch_text')) {
    /**
     * Unwrap a fix string that may be JSON with nested fix/patch keys.
     */
    function patcherly_unwrap_patch_text(string $fix): string {
        $decoded = json_decode($fix, true);
        if (!is_array($decoded)) {
            return $fix;
        }
        $top = $decoded['fix'] ?? null;
        if (is_string($top) && trim($top) !== '') {
            return $top;
        }
        $nested = $decoded['patch'] ?? null;
        if (is_string($nested) && trim($nested) !== '') {
            return $nested;
        }
        return $fix;
    }
}

if (!function_exists('patcherly_coalesce_patch_text_from_analysis_response')) {
    /**
     * Pick executable unified-diff text from a signed GET /fix JSON body.
     */
    function patcherly_coalesce_patch_text_from_analysis_response(array $data): string {
        $fix_raw = isset($data['fix']) ? trim((string) $data['fix']) : '';
        if ($fix_raw !== '') {
            $unwrapped = patcherly_unwrap_patch_text($fix_raw);
            if (trim($unwrapped) !== '') {
                return $unwrapped;
            }
        }
        if (isset($data['patch']) && is_array($data['patch'])) {
            $nested = $data['patch']['patch'] ?? null;
            if (is_string($nested) && trim($nested) !== '') {
                return trim($nested);
            }
        }
        return $fix_raw;
    }
}

if (!function_exists('patcherly_extract_files_from_patch_text')) {
    /**
     * @return list<string>
     */
    function patcherly_extract_files_from_patch_text(string $fix): array {
        $files = [];
        $fix = patcherly_unwrap_patch_text($fix);
        foreach (explode("\n", $fix) as $line) {
            if (strpos($line, '+++ ') === 0 || strpos($line, '--- ') === 0) {
                $file_path = trim(substr($line, 4));
                if (strpos($file_path, 'a/') === 0 || strpos($file_path, 'b/') === 0) {
                    $file_path = substr($file_path, 2);
                }
                if ($file_path !== '' && $file_path !== '/dev/null' && !in_array($file_path, $files, true)) {
                    $files[] = $file_path;
                }
            }
        }
        return $files;
    }
}

if (!function_exists('patcherly_extract_files_from_analysis_response')) {
    /**
     * @return list<string>
     */
    function patcherly_extract_files_from_analysis_response(array $data): array {
        $patch_text = patcherly_coalesce_patch_text_from_analysis_response($data);
        $files = $patch_text !== '' ? patcherly_extract_files_from_patch_text($patch_text) : [];
        foreach (['files_affected'] as $key) {
            if (!empty($data[$key]) && is_array($data[$key])) {
                $files = array_merge($files, $data[$key]);
            }
            if (isset($data['patch']) && is_array($data['patch']) && !empty($data['patch'][$key]) && is_array($data['patch'][$key])) {
                $files = array_merge($files, $data['patch'][$key]);
            }
        }
        $out = [];
        foreach ($files as $file) {
            if (!is_string($file)) {
                continue;
            }
            $file = trim($file);
            if ($file !== '' && !in_array($file, $out, true)) {
                $out[] = $file;
            }
        }
        return $out;
    }
}

if (!function_exists('patcherly_resolve_backup_file_paths')) {
    /**
     * Resolve relative patch paths to existing absolute paths for pre-apply backup.
     *
     * @param list<string> $paths
     * @return list<string>
     */
    function patcherly_resolve_backup_file_paths(array $paths): array {
        if (!function_exists('patcherly_resolve_patch_target')) {
            require_once __DIR__ . '/path_resolve.php';
        }
        $resolved = [];
        foreach ($paths as $path) {
            if (!is_string($path) || $path === '') {
                continue;
            }
            $target = patcherly_resolve_patch_target($path);
            if ($target === '' || !file_exists($target)) {
                continue;
            }
            $real = realpath($target);
            $resolved[] = $real !== false ? $real : $target;
        }
        return array_values(array_unique($resolved));
    }
}

if (!function_exists('patcherly_analysis_response_has_apply_payload')) {
    function patcherly_analysis_response_has_apply_payload(array $data): bool {
        return patcherly_coalesce_patch_text_from_analysis_response($data) !== '';
    }
}
