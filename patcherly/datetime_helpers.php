<?php
/**
 * WordPress site date/time formatting helpers for connector admin UI.
 */
if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_site_datetime_js_config')) {
    /**
     * @return array{timezone:string,locale:string,hour12:bool,date_format:string,time_format:string}
     */
    function patcherly_site_datetime_js_config(): array {
        $timezone = function_exists('wp_timezone_string') ? (string) wp_timezone_string() : '';
        if ($timezone === '') {
            $offset  = (float) get_option('gmt_offset', 0);
            $hours   = (int) $offset;
            $minutes = (int) round(abs($offset - $hours) * 60);
            $sign    = $offset >= 0 ? '+' : '-';
            $timezone = sprintf('%s%02d:%02d', $sign, abs($hours), $minutes);
        }
        $time_format = (string) get_option('time_format', 'g:i a');
        return [
            'timezone'    => $timezone,
            'locale'      => function_exists('determine_locale') ? determine_locale() : 'en_US',
            'hour12'      => (bool) preg_match('/[aA]/', $time_format),
            'date_format' => (string) get_option('date_format', 'F j, Y'),
            'time_format' => $time_format,
        ];
    }
}

if (!function_exists('patcherly_normalize_api_datetime_string')) {
    function patcherly_normalize_api_datetime_string(string $raw): string {
        $s = trim($raw);
        if ($s === '') {
            return '';
        }
        if (preg_match('/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(\d+)(.*)$/', $s, $m)) {
            $frac = substr($m[2], 0, 3);
            $s = $m[1] . '.' . str_pad($frac, 3, '0', STR_PAD_RIGHT) . $m[3];
        }
        if (preg_match('/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?$/', $s)) {
            $s .= 'Z';
        }
        return $s;
    }
}

if (!function_exists('patcherly_format_api_datetime_for_display')) {
    function patcherly_format_api_datetime_for_display($raw): string {
        if ($raw === null || $raw === '' || $raw === '—') {
            return '—';
        }
        $s = (string) $raw;
        try {
            $dt = new DateTimeImmutable(patcherly_normalize_api_datetime_string($s));
        } catch (\Throwable $e) {
            return $s;
        }
        $date_format = (string) get_option('date_format', 'F j, Y');
        $time_format = (string) get_option('time_format', 'g:i a');
        $format = $date_format . ' ' . $time_format;
        if (function_exists('wp_date')) {
            return wp_date($format, $dt->getTimestamp());
        }
        return $dt->format($format);
    }
}
