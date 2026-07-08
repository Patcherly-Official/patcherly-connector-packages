<?php
/**
 * Split bundled log fragments into individual timestamp-prefixed occurrences.
 *
 * PHP debug.log tail reads and rescue/main ingest paths can deliver multiple
 * repeats of the same error in one physical line (no newline between brackets).
 * Server dedup keys off the first canonical occurrence — connectors should
 * enqueue each occurrence separately when possible.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_split_log_occurrences')) {
    /**
     * @return string[]
     */
    function patcherly_split_log_occurrences(string $text): array {
        $text = trim($text);
        if ($text === '') {
            return [];
        }
        $parts = preg_split(
            '/(?=\[\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}|\[\d{1,2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2})/',
            $text
        );
        if (!is_array($parts)) {
            return [$text];
        }
        $out = [];
        foreach ($parts as $part) {
            $part = trim((string) $part);
            if ($part !== '') {
                $out[] = $part;
            }
        }
        return $out !== [] ? $out : [$text];
    }
}
