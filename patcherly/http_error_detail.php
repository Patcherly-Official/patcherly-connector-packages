<?php
/**
 * Unwrap FastAPI/HTTP error bodies for WordPress connector soft-stops.
 * Prefer nested detail.code; fall back to top-level code.
 */

if (!defined('ABSPATH') && !defined('PATCHERLY_HTTP_ERROR_DETAIL_LOADED')) {
    // Allow standalone test includes without WordPress bootstrap.
    define('PATCHERLY_HTTP_ERROR_DETAIL_LOADED', true);
}

if (!defined('PATCHERLY_FIX_APPROVE_STATUSES')) {
    define('PATCHERLY_FIX_APPROVE_STATUSES', 'awaiting_approval,manual_review_required');
}

if (!function_exists('patcherly_http_error_detail')) {
    /**
     * @param mixed $payload
     * @return array<string, mixed>
     */
    function patcherly_http_error_detail($payload): array {
        if (!is_array($payload)) {
            return [];
        }
        $detail = $payload['detail'] ?? null;
        if (is_array($detail)) {
            return $detail;
        }
        return $payload;
    }
}

if (!function_exists('patcherly_http_error_code')) {
    /**
     * @param mixed $payload
     */
    function patcherly_http_error_code($payload): ?string {
        $detail = patcherly_http_error_detail($payload);
        $code = $detail['code'] ?? null;
        if ($code === null || $code === '') {
            return null;
        }
        return (string) $code;
    }
}

if (!function_exists('patcherly_is_fix_approve_status')) {
    function patcherly_is_fix_approve_status(?string $status): bool {
        if ($status === null || $status === '') {
            return false;
        }
        $allowed = array_filter(array_map('trim', explode(',', (string) PATCHERLY_FIX_APPROVE_STATUSES)));
        return in_array($status, $allowed, true);
    }
}

if (!function_exists('patcherly_is_approve_409_soft_stop')) {
    function patcherly_is_approve_409_soft_stop(?string $code): bool {
        static $codes = [
            'empty_fix',
            'error_path_blocked',
            'low_confidence_confirmation_required',
            'auto_apply_not_enabled',
            'approve_requires_post_analysis',
        ];
        return $code !== null && in_array($code, $codes, true);
    }
}
