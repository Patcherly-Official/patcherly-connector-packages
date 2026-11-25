<?php
/**
 * Monotonic unix-second timestamps for outbound WordPress connector HMAC signatures.
 *
 * Replay protection keys on token_id + signature. Same wall-clock second →
 * same signature → HTTP 409 replay_detected. Advance into the near future
 * when needed so every sign (and retry) is unique within the API ±300s skew.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_next_hmac_timestamp')) {
    /** @var int */
    $GLOBALS['patcherly_last_hmac_timestamp'] = 0;

    function patcherly_next_hmac_timestamp(): string
    {
        $now = time();
        $last = (int) ($GLOBALS['patcherly_last_hmac_timestamp'] ?? 0);
        $candidate = $now > $last ? $now : $last + 1;
        if ($candidate - $now > 240) {
            $waitUntil = $candidate - 240;
            while (time() < $waitUntil) {
                usleep(50000);
            }
            $now = time();
            $last = (int) ($GLOBALS['patcherly_last_hmac_timestamp'] ?? 0);
            $candidate = $now > $last ? $now : $last + 1;
        }
        $GLOBALS['patcherly_last_hmac_timestamp'] = $candidate;
        return (string) $candidate;
    }
}
