<?php
/**
 * Paired site host helpers for clone / URL-change detection.
 *
 * Stores the normalized hostname from home_url() at successful OAuth poll only.
 * Compared on admin_menu (priority 8) before the settings menu is registered.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!defined('PATCHERLY_OPTION_PAIRED_SITE_HOST')) {
    define('PATCHERLY_OPTION_PAIRED_SITE_HOST', 'patcherly_paired_site_host');
}

if (!defined('PATCHERLY_OPTION_HOST_MISMATCH_NOTICE')) {
    define('PATCHERLY_OPTION_HOST_MISMATCH_NOTICE', 'patcherly_host_mismatch_notice');
}

if (!defined('PATCHERLY_OPTION_HOST_MISMATCH_ACKED')) {
    define('PATCHERLY_OPTION_HOST_MISMATCH_ACKED', 'patcherly_host_mismatch_acked');
}

if (!function_exists('patcherly_normalize_site_host')) {
    /**
     * Normalize a URL or host for hostname-only comparison.
     *
     * Lowercase, strip scheme/path/port, strip leading www.
     */
    function patcherly_normalize_site_host($url_or_host): string
    {
        $raw = trim((string) $url_or_host);
        if ($raw === '') {
            return '';
        }

        $host = '';
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $raw)) {
            $parsed = parse_url($raw);
            $host = is_array($parsed) && isset($parsed['host']) ? (string) $parsed['host'] : '';
        } elseif (strpos($raw, '/') !== false) {
            $parsed = parse_url('https://' . ltrim($raw, '/'));
            $host = is_array($parsed) && isset($parsed['host']) ? (string) $parsed['host'] : '';
        } else {
            // Bare host or host:port
            $host = $raw;
        }

        $host = strtolower(trim($host));
        if ($host === '') {
            return '';
        }

        // Strip port (IPv6 in brackets is uncommon for WP home_url; keep simple).
        if (strpos($host, '[') !== 0 && strpos($host, ':') !== false) {
            $host = explode(':', $host, 2)[0];
        }

        if (strncmp($host, 'www.', 4) === 0) {
            $host = substr($host, 4);
        }

        return $host;
    }
}

if (!function_exists('patcherly_get_paired_site_host')) {
    function patcherly_get_paired_site_host(): string
    {
        return trim((string) get_option(PATCHERLY_OPTION_PAIRED_SITE_HOST, ''));
    }
}

if (!function_exists('patcherly_set_paired_site_host')) {
    /**
     * Persist a normalized host (from URL or bare host). Empty clears.
     */
    function patcherly_set_paired_site_host($url_or_host): void
    {
        $host = patcherly_normalize_site_host($url_or_host);
        if ($host === '') {
            delete_option(PATCHERLY_OPTION_PAIRED_SITE_HOST);
            return;
        }
        update_option(PATCHERLY_OPTION_PAIRED_SITE_HOST, $host, false);
    }
}

if (!function_exists('patcherly_clear_paired_site_host')) {
    function patcherly_clear_paired_site_host(): void
    {
        delete_option(PATCHERLY_OPTION_PAIRED_SITE_HOST);
    }
}

if (!function_exists('patcherly_get_host_mismatch_notice')) {
    /**
     * @return array{fingerprint?:string,old_url?:string,new_url?:string}|null
     */
    function patcherly_get_host_mismatch_notice(): ?array
    {
        $raw = get_option(PATCHERLY_OPTION_HOST_MISMATCH_NOTICE, null);
        if (!is_array($raw) || empty($raw['fingerprint'])) {
            return null;
        }
        return [
            'fingerprint' => (string) $raw['fingerprint'],
            'old_url'     => isset($raw['old_url']) ? (string) $raw['old_url'] : '',
            'new_url'     => isset($raw['new_url']) ? (string) $raw['new_url'] : '',
        ];
    }
}

if (!function_exists('patcherly_set_host_mismatch_notice')) {
    /**
     * Store a one-shot site-host mismatch notice (Site Kit-style).
     */
    function patcherly_set_host_mismatch_notice(string $old_url, string $new_url): void
    {
        $old_url = trim($old_url);
        $new_url = trim($new_url);
        $fingerprint = hash('sha256', $old_url . "\0" . $new_url);
        update_option(
            PATCHERLY_OPTION_HOST_MISMATCH_NOTICE,
            [
                'fingerprint' => $fingerprint,
                'old_url'     => $old_url,
                'new_url'     => $new_url,
            ],
            false
        );
    }
}

if (!function_exists('patcherly_clear_host_mismatch_notice')) {
    function patcherly_clear_host_mismatch_notice(): void
    {
        delete_option(PATCHERLY_OPTION_HOST_MISMATCH_NOTICE);
    }
}

if (!function_exists('patcherly_get_host_mismatch_acked')) {
    /**
     * @return string[]
     */
    function patcherly_get_host_mismatch_acked(): array
    {
        $raw = get_option(PATCHERLY_OPTION_HOST_MISMATCH_ACKED, []);
        if (!is_array($raw)) {
            return [];
        }
        $out = [];
        foreach ($raw as $fp) {
            if (is_string($fp) && $fp !== '') {
                $out[] = $fp;
            }
        }
        return array_values(array_unique($out));
    }
}

if (!function_exists('patcherly_ack_host_mismatch_fingerprint')) {
    function patcherly_ack_host_mismatch_fingerprint(string $fingerprint): void
    {
        $fingerprint = trim($fingerprint);
        if ($fingerprint === '') {
            return;
        }
        $acked = patcherly_get_host_mismatch_acked();
        if (!in_array($fingerprint, $acked, true)) {
            $acked[] = $fingerprint;
            // Cap growth (keep newest fingerprints).
            if (count($acked) > 20) {
                $acked = array_slice($acked, -20);
            }
            update_option(PATCHERLY_OPTION_HOST_MISMATCH_ACKED, $acked, false);
        }
    }
}

if (!function_exists('patcherly_is_host_mismatch_acked')) {
    function patcherly_is_host_mismatch_acked(string $fingerprint): bool
    {
        $fingerprint = trim($fingerprint);
        if ($fingerprint === '') {
            return false;
        }
        return in_array($fingerprint, patcherly_get_host_mismatch_acked(), true);
    }
}

if (!function_exists('patcherly_host_mismatch_alert_pending')) {
    /**
     * True when an undismissed host-mismatch notice should show red dots.
     */
    function patcherly_host_mismatch_alert_pending(): bool
    {
        $notice = patcherly_get_host_mismatch_notice();
        if ($notice === null) {
            return false;
        }
        return !patcherly_is_host_mismatch_acked($notice['fingerprint']);
    }
}

if (!function_exists('patcherly_host_display_url')) {
    /**
     * Turn a normalized host or URL into a short display string for notices.
     */
    function patcherly_host_display_url(string $host_or_url): string
    {
        $raw = trim($host_or_url);
        if ($raw === '') {
            return '';
        }
        if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $raw)) {
            return $raw;
        }
        return 'https://' . ltrim($raw, '/');
    }
}
