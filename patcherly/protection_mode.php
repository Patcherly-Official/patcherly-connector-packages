<?php
/**
 * Connector-side protection mode standby (Layer 10).
 *
 * When the API returns HTTP 423 with code target_protection_mode_active, the
 * connector pauses ingest and fix polling until protection_mode_until expires
 * or is cleared manually on the server.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_PROTECTION_MODE_OPTION')) {
    define('PATCHERLY_PROTECTION_MODE_OPTION', 'patcherly_protection_mode_until');
}

if (!function_exists('patcherly_protection_mode_clear_expired')) {
    function patcherly_protection_mode_clear_expired(): void {
        $raw = get_option(PATCHERLY_PROTECTION_MODE_OPTION, '');
        if (!is_string($raw) || $raw === '' || strcasecmp($raw, 'indefinite') === 0) {
            return;
        }
        try {
            $expiry = new DateTimeImmutable($raw);
            if ($expiry <= new DateTimeImmutable('now', new DateTimeZone('UTC'))) {
                delete_option(PATCHERLY_PROTECTION_MODE_OPTION);
            }
        } catch (Throwable $e) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('Patcherly: failed to evaluate protection mode option: ' . $e->getMessage());
            }
        }
    }
}

if (!function_exists('patcherly_protection_mode_is_standby')) {
    function patcherly_protection_mode_is_standby(): bool {
        patcherly_protection_mode_clear_expired();
        $raw = get_option(PATCHERLY_PROTECTION_MODE_OPTION, '');
        if (!is_string($raw) || $raw === '') {
            return false;
        }
        if (strcasecmp($raw, 'indefinite') === 0) {
            return true;
        }
        try {
            $expiry = new DateTimeImmutable($raw);
            return $expiry > new DateTimeImmutable('now', new DateTimeZone('UTC'));
        } catch (Throwable $e) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('Patcherly: invalid protection mode until option: ' . $e->getMessage());
            }
            return true;
        }
    }
}

if (!function_exists('patcherly_protection_mode_enter')) {
    /**
     * @param string|null $until ISO-8601 expiry from the API, or null for indefinite.
     */
    function patcherly_protection_mode_enter(?string $until): void {
        $value = ($until === null || trim($until) === '') ? 'indefinite' : trim($until);
        update_option(PATCHERLY_PROTECTION_MODE_OPTION, $value, false);
    }
}

if (!function_exists('patcherly_protection_mode_handle_http')) {
    function patcherly_protection_mode_handle_http(int $status_code, string $body_text): bool {
        if ($status_code !== 423) {
            return false;
        }
        $matched = false;
        $until = null;
        try {
            $data = json_decode($body_text, true);
            $detail = is_array($data) ? ($data['detail'] ?? null) : null;
            if (is_array($detail) && ($detail['code'] ?? '') === 'target_protection_mode_active') {
                $until = isset($detail['until']) ? (string) $detail['until'] : null;
                $matched = true;
            }
        } catch (Throwable $e) {
            if (function_exists('patcherly_debug_log')) {
                patcherly_debug_log('Patcherly: failed to parse protection-mode 423 body: ' . $e->getMessage());
            }
            return false;
        }
        if (!$matched) {
            return false;
        }
        patcherly_protection_mode_enter($until);
        if (function_exists('patcherly_debug_log')) {
            patcherly_debug_log(
                'Patcherly: site entered protection mode standby until ' .
                ($until ?: 'manual release') . '; pausing ingest and fix polling.'
            );
        }
        return true;
    }
}

if (!defined('PATCHERLY_SUSPICIOUS_REFUSAL_MSG')) {
    define(
        'PATCHERLY_SUSPICIOUS_REFUSAL_MSG',
        'Connector refused to apply: server marked this patch as suspicious'
    );
}
