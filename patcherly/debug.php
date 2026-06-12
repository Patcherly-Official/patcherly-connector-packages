<?php
/**
 * Patcherly — Debug Mode page (opt-in, local diagnostics only).
 *
 * Pure display surface: never makes wp_remote_* / fetch / XHR calls and never writes to the DB.
 * Captured entries come from Patcherly_Connector_Plugin::debug_record(); deletion goes through
 * the admin-post patcherly_debug_clear_log handler in patcherly.php.
 *
 * Defence-in-depth: this file re-runs a redaction pass on every entry before render.
 * Contract locked by tests/test-debug-mode-sanitization.php.
 */

if (!defined('ABSPATH')) { exit; }

if (!function_exists('patcherly_debug_sanitize_url')) {
    /** Defence-in-depth wrapper around Patcherly_Connector_Plugin::debug_sanitize_url(). */
    function patcherly_debug_sanitize_url(string $url): string {
        if (class_exists('Patcherly_Connector_Plugin')) {
            return Patcherly_Connector_Plugin::debug_sanitize_url($url);
        }
        return substr(sanitize_text_field($url), 0, 200);
    }
}

if (!function_exists('patcherly_debug_redaction_blocklist')) {
    /**
     * Strings that MUST NOT appear in rendered entries. Pinned by test-debug-mode-sanitization.php.
     *
     * @return string[]
     */
    function patcherly_debug_redaction_blocklist(): array {
        return [
            'Authorization',
            'Bearer',
            'X-Patcherly-Signature',
            'X-Patcherly-Hmac-Kid',
            'access_token',
            'refresh_token',
            'device_code',
        ];
    }
}

if (!function_exists('patcherly_debug_redact')) {
    /**
     * Replace any rendered field that contains a blocklisted keyword (or
     * a long hex run that smells like a token / signature) with
     * "[redacted]". This is a paranoid post-process — the capture side
     * already filters bodies and headers — but it makes test-driven
     * regression-proofing trivial.
     */
    function patcherly_debug_redact($value): string {
        if (!is_scalar($value)) {
            return '[redacted]';
        }
        $s = (string) $value;
        $blocklist = patcherly_debug_redaction_blocklist();
        foreach ($blocklist as $needle) {
            if (stripos($s, $needle) !== false) {
                return '[redacted]';
            }
        }
        // Hex runs of >= 40 chars are almost certainly secrets (sha1, hmac,
        // bearer tokens, etc.). Redact the whole value.
        if (preg_match('/[a-f0-9]{40,}/i', $s)) {
            return '[redacted]';
        }
        return $s;
    }
}

if (!function_exists('patcherly_debug_render')) {
    /**
     * Render the Debug page.
     *
     * @param mixed $plugin_instance Reserved for future use; currently unused.
     */
    function patcherly_debug_render($plugin_instance): void {
        unset($plugin_instance);
        if (!current_user_can('manage_options')) { return; }

        $entries = get_option('patcherly_debug_log_entries', []);
        if (!is_array($entries)) { $entries = []; }
        // Newest first — easier to scan during a live reproduction.
        $entries = array_reverse($entries);

        $cleared_flag = false;
        // phpcs:ignore WordPress.Security.NonceVerification.Recommended -- post-redirect display flag only; the destructive action ran via patcherly_debug_clear_log nonce.
        if (isset($_GET['cleared']) && (string) $_GET['cleared'] === '1') {
            $cleared_flag = true;
        }
        ?>
        <div class="wrap patcherly-wrap patcherly-debug-wrap">
            <h1><?php esc_html_e('Debug', 'patcherly'); ?></h1>

            <?php if ($cleared_flag) : ?>
                <div class="notice notice-success is-dismissible"><p><?php esc_html_e('Captured debug entries have been cleared.', 'patcherly'); ?></p></div>
            <?php endif; ?>

            <div class="notice notice-warning">
                <p>
                    <strong><?php esc_html_e('Debug Mode is ON.', 'patcherly'); ?></strong>
                    <?php esc_html_e('The table below lists sanitized metadata for every request this connector has sent to the Patcherly API since you enabled Debug Mode. Tokens, signatures, and request/response bodies are not captured. Disabling Debug Mode in Settings → Advanced settings will immediately delete every captured entry from your database. Nothing is ever transmitted off your site.', 'patcherly'); ?>
                </p>
            </div>

            <div class="patcherly-debug-toolbar" style="display:flex;gap:8px;align-items:center;margin:12px 0;">
                <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>" onsubmit="return confirm('<?php echo esc_js(__('Clear all captured debug entries? This cannot be undone.', 'patcherly')); ?>');">
                    <input type="hidden" name="action" value="patcherly_debug_clear_log" />
                    <?php wp_nonce_field('patcherly_debug_clear_log'); ?>
                    <button type="submit" class="button button-secondary"><?php esc_html_e('Clear log', 'patcherly'); ?></button>
                </form>
                <button type="button" class="button" id="patcherly-debug-copy-json"><?php esc_html_e('Copy as JSON', 'patcherly'); ?></button>
                <a class="button" href="<?php echo esc_url(admin_url('admin.php?page=patcherly')); ?>"><?php esc_html_e('Back to Settings', 'patcherly'); ?></a>
                <span id="patcherly-debug-copy-result" class="patcherly-muted"></span>
            </div>

            <p class="description">
                <?php
                printf(
                    /* translators: 1: number of entries, 2: max entries */
                    esc_html__('Showing %1$d of up to %2$d most-recent entries (ring buffer).', 'patcherly'),
                    (int) count($entries),
                    (int) Patcherly_Connector_Plugin::DEBUG_LOG_MAX_ENTRIES
                );
                ?>
            </p>

            <table class="widefat striped patcherly-debug-table">
                <thead>
                    <tr>
                        <th style="width:160px"><?php esc_html_e('When', 'patcherly'); ?></th>
                        <th style="width:160px"><?php esc_html_e('Purpose', 'patcherly'); ?></th>
                        <th style="width:70px"><?php esc_html_e('Method', 'patcherly'); ?></th>
                        <th><?php esc_html_e('URL', 'patcherly'); ?></th>
                        <th style="width:70px"><?php esc_html_e('HTTP', 'patcherly'); ?></th>
                        <th style="width:80px"><?php esc_html_e('Duration', 'patcherly'); ?></th>
                        <th><?php esc_html_e('Error', 'patcherly'); ?></th>
                    </tr>
                </thead>
                <tbody>
                <?php if (empty($entries)) : ?>
                    <tr><td colspan="7" style="text-align:center;color:#666;padding:18px;"><?php esc_html_e('No requests captured yet. Trigger an action (e.g. open the Errors page) to populate the log.', 'patcherly'); ?></td></tr>
                <?php else : ?>
                    <?php foreach ($entries as $e) :
                        if (!is_array($e)) { continue; }
                        $ts      = isset($e['t']) ? (int) $e['t'] : 0;
                        $purpose = isset($e['purpose']) ? patcherly_debug_redact($e['purpose']) : '';
                        $method  = isset($e['method'])  ? patcherly_debug_redact($e['method'])  : '';
                        $url     = isset($e['url'])     ? patcherly_debug_redact($e['url'])     : '';
                        $code    = isset($e['code'])    ? (int) $e['code']                       : 0;
                        $ms      = isset($e['ms'])      ? (int) $e['ms']                         : 0;
                        $error   = isset($e['error'])   ? patcherly_debug_redact($e['error'])   : '';
                        $code_class = 'patcherly-badge';
                        if ($code === 0 && $error !== '') { $code_class .= ' danger'; }
                        elseif ($code >= 200 && $code < 300) { $code_class .= ' success'; }
                        elseif ($code >= 300 && $code < 400) { $code_class .= ''; }
                        elseif ($code >= 400 && $code < 500) { $code_class .= ' warn'; }
                        elseif ($code >= 500)                { $code_class .= ' danger'; }
                    ?>
                    <tr>
                        <td><?php echo esc_html($ts ? gmdate('Y-m-d H:i:s', $ts) . ' UTC' : '—'); ?></td>
                        <td><?php echo esc_html($purpose !== '' ? $purpose : 'other'); ?></td>
                        <td><code><?php echo esc_html($method !== '' ? $method : '-'); ?></code></td>
                        <td style="word-break:break-all;font-family:Menlo,Consolas,monospace;font-size:12px;"><?php echo esc_html($url); ?></td>
                        <td><span class="<?php echo esc_attr($code_class); ?>"><?php echo esc_html($code > 0 ? (string) $code : '—'); ?></span></td>
                        <td><?php echo esc_html($ms > 0 ? ($ms . ' ms') : '—'); ?></td>
                        <td style="word-break:break-word;color:#9a1c1a;font-size:12px;"><?php echo esc_html($error); ?></td>
                    </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
                </tbody>
            </table>

            <!-- Copy-as-JSON payload (server-rendered into a hidden script tag
                 so the small inline handler below doesn't have to re-encode
                 entries on the client). -->
            <script type="application/json" id="patcherly-debug-payload"><?php
                // wp_json_encode produces correctly-escaped JSON; we still
                // run each value through the redaction helper before encoding
                // so the JSON payload mirrors the rendered table exactly.
                $payload = [];
                foreach ($entries as $e) {
                    if (!is_array($e)) { continue; }
                    $payload[] = [
                        't'       => isset($e['t']) ? (int) $e['t'] : 0,
                        'purpose' => isset($e['purpose']) ? patcherly_debug_redact($e['purpose']) : '',
                        'method'  => isset($e['method'])  ? patcherly_debug_redact($e['method'])  : '',
                        'url'     => isset($e['url'])     ? patcherly_debug_redact($e['url'])     : '',
                        'code'    => isset($e['code'])    ? (int) $e['code']                       : 0,
                        'ms'      => isset($e['ms'])      ? (int) $e['ms']                         : 0,
                        'error'   => isset($e['error'])   ? patcherly_debug_redact($e['error'])   : '',
                    ];
                }
                echo wp_json_encode($payload, JSON_PRETTY_PRINT);
            ?></script>

            <script>
            (function () {
                var btn = document.getElementById('patcherly-debug-copy-json');
                var out = document.getElementById('patcherly-debug-copy-result');
                var node = document.getElementById('patcherly-debug-payload');
                if (!btn || !node) { return; }
                btn.addEventListener('click', function () {
                    var txt = node.textContent || '';
                    var done = function () { if (out) out.textContent = 'Copied.'; setTimeout(function () { if (out) out.textContent = ''; }, 1500); };
                    if (navigator.clipboard && navigator.clipboard.writeText) {
                        navigator.clipboard.writeText(txt).then(done, function () {
                            if (out) out.textContent = 'Copy failed — select the JSON below manually.';
                        });
                    } else {
                        var ta = document.createElement('textarea');
                        ta.value = txt; document.body.appendChild(ta); ta.select();
                        try { document.execCommand('copy'); done(); }
                        catch (_) { if (out) out.textContent = 'Copy failed.'; }
                        document.body.removeChild(ta);
                    }
                });
            })();
            </script>
        </div>
        <?php
    }
}
