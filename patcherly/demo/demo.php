<?php
/**
 * Patcherly Demo Mode loader (v1.49.x — fully self-contained).
 *
 * Mounts a mocked Errors page under the "Demo (explore)" submenu so a
 * brand-new operator can see what Patcherly looks like without first
 * pairing the site. The demo:
 *   - reads its dataset from `demo/demo_data.json` (bundled),
 *   - mutates state ONLY in `sessionStorage` (per-tab),
 *   - performs ZERO real `wp_remote_*` / admin-ajax / database calls.
 *
 * Off-switch hierarchy:
 *   1. Default (recommended for most operators) — leave demo/ on disk
 *      and untick "Show the Demo submenu" in Patcherly → Advanced
 *      settings. The `OPTION_DEMO_ENABLED` toggle (default `'1'`) gates
 *      both the `add_submenu_page()` registration in
 *      `register_settings_page()` AND the defensive re-check inside
 *      `render_demo_page_entry()`, so the submenu disappears AND any
 *      stale `?page=patcherly-demo` bookmark lands on a friendly hint.
 *      This is the only off-switch that survives plugin auto-updates.
 *      Contract test: `tests/test-demo-submenu-gate.php`.
 *   2. Removal at distribution time — strip the demo before publishing
 *      by deleting the demo/ folder AND the three Demo-aware blocks in
 *      patcherly.php: the `OPTION_DEMO_ENABLED`-gated `add_submenu_page()`
 *      call, the `elseif ($page === 'patcherly-demo')` branch in
 *      `enqueue_assets()`, and the `render_demo_page_entry()` method.
 *      The Advanced-settings toggle (`field_demo_enabled` + its
 *      `register_setting`) can stay or go — with the demo files gone
 *      it's a harmless no-op, but pruning it keeps the UI honest.
 *      See `connectors/patcherly/demo/README.md` for the full how-to.
 *
 * The self-contained contract (no I/O, no globals) is locked by
 * `tests/test-demo-self-contained.php`. The off-switch contract at (1)
 * is locked by `tests/test-demo-submenu-gate.php`.
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
                        <?php
                        // Canonical 18-status list — must mirror the real Errors page.
                        $demo_statuses = [
                            'pending'                => __('Pending', 'patcherly'),
                            'pending_analysis'       => __('Analyzing', 'patcherly'),
                            'analysis_failed'        => __('Analysis failed', 'patcherly'),
                            'analyzed'               => __('Analyzed', 'patcherly'),
                            'awaiting_approval'      => __('Awaiting approval', 'patcherly'),
                            'manual_review_required' => __('Manual review', 'patcherly'),
                            'approved'               => __('Approved', 'patcherly'),
                            'applying'               => __('Applying', 'patcherly'),
                            'fixed'                  => __('Fixed', 'patcherly'),
                            'failed'                 => __('Apply failed', 'patcherly'),
                            'restored'               => __('Restored', 'patcherly'),
                            'rolling_back'           => __('Rolling back', 'patcherly'),
                            'rolled_back'            => __('Rolled back', 'patcherly'),
                            'rollback_failed'        => __('Rollback failed', 'patcherly'),
                            'dismissed'              => __('Dismissed', 'patcherly'),
                            'ignored'                => __('Ignored', 'patcherly'),
                            'excluded'               => __('Excluded', 'patcherly'),
                            'manual'                 => __('Manual', 'patcherly'),
                        ];
                        foreach ($demo_statuses as $value => $label) {
                            echo '<option value="' . esc_attr($value) . '">' . esc_html($label) . '</option>';
                        }
                        ?>
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
                <span style="flex:1 1 auto"></span>
                <?php /* Column manager — sessionStorage-backed; Language hidden by default. */ ?>
                <div class="patcherly-columns-wrap" id="patcherly-demo-columns-wrap">
                    <button type="button" class="button patcherly-columns-toggle" id="patcherly-demo-columns-toggle" aria-haspopup="menu" aria-expanded="false">
                        <span class="dashicons dashicons-admin-generic" aria-hidden="true"></span>
                        <?php esc_html_e('Columns', 'patcherly'); ?>
                    </button>
                    <div class="patcherly-columns-menu" id="patcherly-demo-columns-menu" role="menu" hidden></div>
                </div>
            </div>

            <div class="patcherly-demo-list" style="max-width:1080px;background:#fff;border:1px solid #ccd0d4;border-radius:6px;overflow:hidden">
                <table class="widefat fixed" style="margin:0">
                    <thead>
                        <tr>
                            <th style="width:28px"></th>
                            <th data-col="created"  style="width:150px"><?php esc_html_e('Detected', 'patcherly'); ?></th>
                            <th data-col="severity" style="width:90px"  data-tour="severity"><?php esc_html_e('Severity', 'patcherly'); ?></th>
                            <th data-col="status"   style="width:130px" data-tour="status"><?php esc_html_e('Status', 'patcherly'); ?></th>
                            <th data-col="language" style="width:100px"><?php esc_html_e('Language', 'patcherly'); ?></th>
                            <th data-col="message"><?php esc_html_e('Message', 'patcherly'); ?></th>
                            <th data-col="actions"  style="width:200px;text-align:right" data-tour="actions"><?php esc_html_e('Actions', 'patcherly'); ?></th>
                        </tr>
                    </thead>
                    <tbody id="patcherly-demo-tbody">
                        <tr><td colspan="99" style="text-align:center;color:#666"><?php esc_html_e('Loading mocked errors…', 'patcherly'); ?></td></tr>
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
     * Enqueue demo-only CSS + JS for ?page=patcherly-demo. Asset URLs computed off the
     * plugin file so they survive symlinks.
     *
     * @param string $base    Base plugin URL.
     * @param string $version Plugin version string for cache-busting.
     */
    function patcherly_demo_enqueue_assets(string $base, string $version): void {
        // Per-file mtime → bumps the asset URL on in-place edits; falls back to plugin version.
        $ver = function (string $rel) use ($version): string {
            if (class_exists('Patcherly_Connector_Plugin') && method_exists('Patcherly_Connector_Plugin', 'asset_version')) {
                return Patcherly_Connector_Plugin::asset_version($rel);
            }
            return $version;
        };
        wp_enqueue_style(
            'patcherly-demo',
            $base . 'demo/assets/css/patcherly-demo.css',
            ['patcherly'],
            $ver('demo/assets/css/patcherly-demo.css')
        );
        // Shared PatcherlyFormat helper — same status labels/badges as the real Errors page.
        wp_enqueue_script(
            'patcherly-format',
            $base . 'assets/js/patcherly-format.js',
            [],
            $ver('assets/js/patcherly-format.js'),
            true
        );
        wp_enqueue_script(
            'patcherly-demo',
            $base . 'demo/assets/js/patcherly-demo.js',
            ['patcherly-format'],
            $ver('demo/assets/js/patcherly-demo.js'),
            true
        );
        wp_localize_script('patcherly-demo', 'PATCHERLY_DEMO_I18N', [
            'noResults'         => __('No errors match these filters.', 'patcherly'),
            'reset'             => __('Demo state reset.', 'patcherly'),
            'tour_done'         => __('Tour finished — explore as you like.', 'patcherly'),
            // Action labels — must mirror the real Errors page.
            'btn_analyze'        => __('Analyze', 'patcherly'),
            'btn_preview'        => __('Preview', 'patcherly'),
            'btn_accept'         => __('Accept fix', 'patcherly'),
            'btn_approve'        => __('Approve fix', 'patcherly'),
            'btn_apply'          => __('Apply fix', 'patcherly'),
            'btn_dismiss'        => __('Dismiss', 'patcherly'),
            'btn_rollback'       => __('Rollback', 'patcherly'),
            'btn_restore'        => __('Restore', 'patcherly'),
            'btn_delete'         => __('Delete', 'patcherly'),
            // Toast messages used by patcherly-demo.js performAction().
            'toast_analyzing'    => __('AI analysis started (mock).', 'patcherly'),
            'toast_accepted'     => __('Fix accepted — awaiting approval (mock).', 'patcherly'),
            'toast_applying'     => __('Applying the AI-drafted fix (mock).', 'patcherly'),
            'toast_fix_applied'  => __('AI-drafted fix applied (mock).', 'patcherly'),
            'toast_dismissed'    => __('Error dismissed (mock).', 'patcherly'),
            'toast_rolled_back'  => __('Restored from backup (mock).', 'patcherly'),
            'toast_restored'     => __('Restored to active queue (mock).', 'patcherly'),
            'toast_deleted'      => __('Deleted (mock).', 'patcherly'),
            'severity_critical'  => __('Critical severity', 'patcherly'),
            'severity_error'     => __('Error severity', 'patcherly'),
            'severity_warning'   => __('Warning severity', 'patcherly'),
            'severity_info'      => __('Info severity', 'patcherly'),
        ]);
    }
}
