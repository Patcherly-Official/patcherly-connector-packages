<?php
/**
 * Patcherly Demo Mode loader (v1.49.x — fully self-contained).
 *
 * Mounts a mocked Errors page under the "Demo (explore)" submenu so a
 * brand-new operator can see what Patcherly looks like without first
 * pairing the site. The demo:
 *   - reads its dataset from `demo/demo_data.json` (bundled),
 *   - mutates state ONLY in `sessionStorage` (per-tab),
 *   - performs ZERO real `wp_remote_*` / admin-ajax / database calls,
 *   - is registered through `patcherly.php` via two lines (a submenu
 *     callback + an asset-enqueue branch), so deleting the demo/ folder
 *     + dropping those two lines fully uninstalls the feature.
 *
 * The contract above is locked by `tests/test-demo-self-contained.php`.
 */

if (!defined('ABSPATH')) { exit; }

if (!function_exists('patcherly_demo_render')) {
    function patcherly_demo_render(): void {
        if (!current_user_can('manage_options')) { return; }
        // __FILE__ is already inside the demo/ folder, so the URL resolves
        // to .../patcherly/demo/demo_data.json (sibling). Previously we
        // passed `dirname(__FILE__) . '/patcherly.php'` as the second arg,
        // which made WP's plugin_basename() treat `patcherly/demo` as the
        // plugin folder and prepend `demo/` to the first arg, producing
        // .../patcherly/demo/demo/demo_data.json (double "demo/") → 404.
        $data_url = plugins_url('demo_data.json', __FILE__);
        ?>
        <div class="wrap patcherly-wrap patcherly-demo-wrap" data-patcherly-demo data-demo-data-url="<?php echo esc_url($data_url); ?>">
            <h1><?php esc_html_e('Demo (explore)', 'patcherly'); ?></h1>

            <div class="notice notice-info patcherly-demo-banner">
                <p>
                    <strong><?php esc_html_e('Demo mode', 'patcherly'); ?>:</strong>
                    <?php esc_html_e('everything on this page is mocked locally on your server. No data is sent to the Patcherly API, no AI calls are made, and nothing is written to your WordPress database. Use the actions below to explore how Patcherly handles WordPress errors before you connect your site for real.', 'patcherly'); ?>
                </p>
            </div>

            <div class="patcherly-demo-toolbar">
                <button type="button" class="button" id="patcherly-demo-tour"><?php esc_html_e('Restart guided tour', 'patcherly'); ?></button>
                <button type="button" class="button" id="patcherly-demo-reset"><?php esc_html_e('Reset demo state', 'patcherly'); ?></button>
                <span id="patcherly-demo-msg" class="patcherly-muted"></span>
            </div>

            <h2><?php esc_html_e('Filters', 'patcherly'); ?></h2>
            <div class="patcherly-demo-filters" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:8px 0 12px 0;">
                <label data-tour="filter-status"><?php esc_html_e('Status', 'patcherly'); ?>
                    <select id="patcherly-demo-flt-status">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <option value="pending">pending</option>
                        <option value="analyzed">analyzed</option>
                        <option value="awaiting_approval">awaiting_approval</option>
                        <option value="fixed">fixed</option>
                        <option value="restored">restored</option>
                        <option value="dismissed">dismissed</option>
                    </select>
                </label>
                <label data-tour="filter-severity"><?php esc_html_e('Severity', 'patcherly'); ?>
                    <select id="patcherly-demo-flt-sev">
                        <option value=""><?php esc_html_e('Any', 'patcherly'); ?></option>
                        <option value="critical">critical</option>
                        <option value="error">error</option>
                        <option value="warning">warning</option>
                        <option value="info">info</option>
                    </select>
                </label>
                <label><?php esc_html_e('Language', 'patcherly'); ?>
                    <input id="patcherly-demo-flt-lang" type="text" placeholder="e.g. php" style="width:120px;" />
                </label>
            </div>

            <div data-tour="bulk" style="display:flex;align-items:center;gap:8px;margin:8px 0 12px 0;">
                <label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="patcherly-demo-cb-all" /> <?php esc_html_e('Select all', 'patcherly'); ?></label>
                <button id="patcherly-demo-del-selected" class="button button-secondary"><?php esc_html_e('Delete selected', 'patcherly'); ?></button>
            </div>

            <div class="patcherly-demo-list" style="max-width:1080px;background:#fff;border:1px solid #ccd0d4;border-radius:6px;overflow:hidden">
                <table class="widefat fixed" style="margin:0">
                    <thead>
                        <tr>
                            <th style="width:28px"></th>
                            <th style="width:150px"><?php esc_html_e('Created', 'patcherly'); ?></th>
                            <th style="width:90px" data-tour="severity"><?php esc_html_e('Severity', 'patcherly'); ?></th>
                            <th style="width:130px" data-tour="status"><?php esc_html_e('Status', 'patcherly'); ?></th>
                            <th style="width:100px"><?php esc_html_e('Language', 'patcherly'); ?></th>
                            <th><?php esc_html_e('Message', 'patcherly'); ?></th>
                            <th style="width:220px" data-tour="actions"><?php esc_html_e('Actions', 'patcherly'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-demo-tbody">
                        <tr><td colspan="7" style="text-align:center;color:#666"><?php esc_html_e('Loading mocked errors…', 'patcherly'); ?></td></tr>
                    </tbody>
                </table>
            </div>

            <div id="patcherly-demo-toast" class="patcherly-demo-toast" role="status" aria-live="polite" hidden></div>

            <div id="patcherly-demo-tour-overlay" class="patcherly-demo-tour" hidden>
                <div class="patcherly-demo-tour__backdrop"></div>
                <div class="patcherly-demo-tour__bubble" role="dialog" aria-modal="true" aria-labelledby="patcherly-demo-tour-title">
                    <h3 id="patcherly-demo-tour-title" class="patcherly-demo-tour__title"></h3>
                    <p class="patcherly-demo-tour__body"></p>
                    <div class="patcherly-demo-tour__nav">
                        <button type="button" class="button" data-tour-act="skip"><?php esc_html_e('Skip tour', 'patcherly'); ?></button>
                        <button type="button" class="button patcherly-demo-tour__back" data-tour-act="back"><?php esc_html_e('Back', 'patcherly'); ?></button>
                        <button type="button" class="button button-primary" data-tour-act="next"><?php esc_html_e('Next', 'patcherly'); ?></button>
                    </div>
                </div>
            </div>
        </div>
        <?php
    }
}

if (!function_exists('patcherly_demo_enqueue_assets')) {
    /**
     * Enqueue demo-only CSS + JS. Called from `enqueue_assets()` in
     * `patcherly.php` when the active screen is `?page=patcherly-demo`.
     * Asset URLs are computed off the plugin file so they survive
     * symlinks (per WP.org reviewer directive).
     *
     * @param string $base    Base plugin URL (= plugin_dir_url(__FILE__) in patcherly.php).
     * @param string $version Plugin version string for cache-busting.
     */
    function patcherly_demo_enqueue_assets(string $base, string $version): void {
        wp_enqueue_style(
            'patcherly-demo',
            $base . 'demo/assets/css/patcherly-demo.css',
            ['patcherly'],
            $version
        );
        wp_enqueue_script(
            'patcherly-demo',
            $base . 'demo/assets/js/patcherly-demo.js',
            [],
            $version,
            true
        );
        wp_localize_script('patcherly-demo', 'PATCHERLY_DEMO_I18N', [
            'noResults'         => __('No errors match these filters.', 'patcherly'),
            'reset'             => __('Demo state reset.', 'patcherly'),
            'tour_done'         => __('Tour finished — explore as you like.', 'patcherly'),
            // Action button labels — used by patcherly-demo.js rowActions().
            // Only Approve + Dismiss appear on `awaiting_approval` rows (the
            // single human-decision step in the real Patcherly lifecycle —
            // mirrors patcherly-errors.js line 85). Rollback appears on
            // `fixed` rows. Delete appears on every row.
            'btn_approve'       => __('Approve & apply fix', 'patcherly'),
            'btn_dismiss'       => __('Dismiss', 'patcherly'),
            'btn_rollback'      => __('Rollback', 'patcherly'),
            'btn_delete'        => __('Delete', 'patcherly'),
            // Toast messages used by patcherly-demo.js performAction().
            'toast_fix_applied' => __('AI-drafted fix applied (mock).', 'patcherly'),
            'toast_dismissed'   => __('Error dismissed (mock).', 'patcherly'),
            'toast_rolled_back' => __('Restored from backup (mock).', 'patcherly'),
            'toast_deleted'     => __('Deleted (mock).', 'patcherly'),
            'severity_critical' => __('Critical severity', 'patcherly'),
            'severity_error'    => __('Error severity', 'patcherly'),
            'severity_warning'  => __('Warning severity', 'patcherly'),
            'severity_info'     => __('Info severity', 'patcherly'),
        ]);
    }
}
