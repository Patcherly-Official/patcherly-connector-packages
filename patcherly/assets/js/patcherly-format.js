/*!
 * Shared formatters for the WP plugin admin UI.
 *
 * Loaded by the Errors page (patcherly-errors.js) and the Demo page
 * (patcherly-demo.js) so the human-readable status labels, status
 * tooltips, row-action icons, and icon-button markup stay identical
 * across both — the demo page is sold as a faithful preview of the real
 * Errors page, and drift between the two has bitten reviewers in the past.
 *
 * `formatStatusLabel` / `statusBadgeHtml` mirror the dashboard's
 * lifecycle vocabulary (server/app/core/state.py :: _PREFERRED_STATUS_ORDER).
 * `iconHtml` / `iconButtonHtml` mirror the lucide-react icons rendered by
 * dashboard-next/.../errors/page.tsx so a paired site shows the same
 * glyphs in WP-admin as it does in app.patcherly.com. Update this file
 * + the dashboard label/icon map together when a new canonical status
 * or row action appears.
 */
(function (global) {
  if (global.PatcherlyFormat) return;

  // Pretty labels for every canonical status the server can emit. Keep the
  // copy short — these render inside table cells alongside the message.
  var STATUS_LABELS = {
    pending:                 'Pending',
    pending_analysis:        'Analyzing…',
    analysis_failed:         'Analysis failed',
    analyzed:                'Analyzed',
    awaiting_approval:       'Awaiting approval',
    manual_review_required:  'Manual review',
    approved:                'Approved',
    applying:                'Applying…',
    fixed:                   'Fixed',
    failed:                  'Apply failed',
    restored:                'Restored',
    rolling_back:            'Rolling back…',
    rolled_back:             'Rolled back',
    rollback_failed:         'Rollback failed',
    dismissed:               'Dismissed',
    ignored:                 'Ignored',
    excluded:                'Excluded',
    manual:                  'Manual'
  };

  // One-sentence tooltip per status — rendered via the badge `title` attribute.
  var STATUS_TOOLTIPS = {
    pending:                 'Detected by Patcherly — waiting to be analysed by the AI.',
    pending_analysis:        "Patcherly's AI is analysing this error right now.",
    analysis_failed:         "The AI couldn't analyse this one — try re-running the analyse action.",
    analyzed:                'A draft fix is ready — preview it before you accept.',
    awaiting_approval:       'A draft fix is ready and waiting for your approval to be applied.',
    manual_review_required:  'Patcherly wants a human eye on this one before applying any fix.',
    approved:                'Approved — Patcherly will apply this fix on the next pass.',
    applying:                'The drafted fix is being written to your code right now.',
    fixed:                   'Fix applied successfully. A pre-apply backup stays on your server for rollback.',
    failed:                  "Applying the fix failed — your code wasn't changed.",
    restored:                'Brought back into the active queue from an ignored or dismissed state.',
    rolling_back:            'Patcherly is restoring the pre-apply backup right now.',
    rolled_back:             'Backup restored — your code is back to its pre-fix state.',
    rollback_failed:         "Rollback didn't complete — your code wasn't reverted.",
    dismissed:               "You marked this as not worth fixing. Won't be re-analysed.",
    ignored:                 'Hidden from the default view. Restore to bring it back.',
    excluded:                'Excluded by a workspace rule — Patcherly skips this one.',
    manual:                  'Tracked by Patcherly without auto-fix — handle it yourself.'
  };

  // Badge kind drives the colour pill in the status column. The 4 buckets
  // map to .patcherly-status-badge--{ok,warn,err,neutral} declared in
  // assets/css/patcherly-connector.css.
  var STATUS_KIND = {
    pending:                 'neutral',
    pending_analysis:        'neutral',
    analysis_failed:         'err',
    analyzed:                'neutral',
    awaiting_approval:       'warn',
    manual_review_required:  'warn',
    approved:                'warn',
    applying:                'warn',
    fixed:                   'ok',
    failed:                  'err',
    restored:                'ok',
    rolling_back:            'warn',
    rolled_back:             'ok',
    rollback_failed:         'err',
    dismissed:               'neutral',
    ignored:                 'neutral',
    excluded:                'neutral',
    manual:                  'neutral'
  };

  function escHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]);
    });
  }
  function formatStatusLabel(status) {
    if (!status) return '—';
    return STATUS_LABELS[status] || String(status).replace(/_/g, ' ');
  }
  function formatStatusTooltip(status) {
    return STATUS_TOOLTIPS[status] || '';
  }
  function statusBadgeHtml(status) {
    var label = formatStatusLabel(status);
    var kind  = STATUS_KIND[status] || 'neutral';
    var tip   = formatStatusTooltip(status);
    // `title` drives the OS-native tooltip on hover; aria-label keeps
    // screen readers in lockstep so the explanation isn't visual-only.
    var attrs = 'class="patcherly-status-badge patcherly-status-badge--' + kind + '"';
    if (tip) {
      attrs += ' title="' + escHtml(tip) + '"';
      attrs += ' aria-label="' + escHtml(label + ' — ' + tip) + '"';
    }
    return '<span ' + attrs + '>' + escHtml(label) + '</span>';
  }

  // ── Row-action icons ─────────────────────────────────────────────────
  // Inline SVG (lucide stroke style) so the plugin never reaches out for
  // a webfont or sprite. Matches the icons rendered in
  // dashboard-next/.../errors/page.tsx for each ActionIcon. Keep the
  // viewBox + stroke attrs identical across icons so they line up
  // visually inside the icon-button square.
  var SVG_OPEN  = '<svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">';
  var SVG_CLOSE = '</svg>';
  var ICON_PATHS = {
    eye:        '<path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/>',
    brain:      '<path d="M9 3a3 3 0 0 0-3 3 3 3 0 0 0-3 3 3 3 0 0 0 1 2.236A3 3 0 0 0 3 13a3 3 0 0 0 3 3 3 3 0 0 0 0 3 3 3 0 0 0 3 3 3 3 0 0 0 3-3V6a3 3 0 0 0-3-3Z"/><path d="M15 3a3 3 0 0 1 3 3 3 3 0 0 1 3 3 3 3 0 0 1-1 2.236A3 3 0 0 1 21 13a3 3 0 0 1-3 3 3 3 0 0 1 0 3 3 3 0 0 1-3 3 3 3 0 0 1-3-3V6a3 3 0 0 1 3-3Z"/>',
    check:      '<path d="M20 6 9 17l-5-5"/>',
    x:          '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    rotateCcw:  '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/>',
    refreshCw:  '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>',
    trash:      '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/>',
    loader:     '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>'
  };

  function iconHtml(name) {
    var path = ICON_PATHS[name];
    if (!path) return '';
    return SVG_OPEN + path + SVG_CLOSE;
  }

  // Render a square icon button matching the dashboard `ActionIcon`
  // colour variants. `opts` = { act, title, icon, variant, busy }.
  //   - act:     value of data-act (drives the click dispatcher)
  //   - title:   accessible name + native tooltip (always required)
  //   - icon:    key from ICON_PATHS
  //   - variant: one of info|accent|success|warning|danger|muted
  //   - busy:    optional truthy → renders spinner state instead
  function iconButtonHtml(opts) {
    var act     = opts.act || '';
    var title   = opts.title || '';
    var icon    = opts.icon || 'check';
    var variant = opts.variant || 'muted';
    if (opts.busy) {
      return '<span class="patcherly-icon-btn patcherly-icon-btn--' + variant + ' is-busy" title="' + escHtml(title) + '" aria-label="' + escHtml(title) + '">' + iconHtml('loader') + '</span>';
    }
    return '<button type="button" '
      + 'class="patcherly-icon-btn patcherly-icon-btn--' + variant + '" '
      + 'data-act="' + escHtml(act) + '" '
      + 'title="' + escHtml(title) + '" '
      + 'aria-label="' + escHtml(title) + '">'
      + iconHtml(icon)
      + '</button>';
  }

  global.PatcherlyFormat = {
    formatStatusLabel: formatStatusLabel,
    formatStatusTooltip: formatStatusTooltip,
    statusBadgeHtml: statusBadgeHtml,
    iconHtml: iconHtml,
    iconButtonHtml: iconButtonHtml,
    STATUS_LABELS: STATUS_LABELS,
    STATUS_TOOLTIPS: STATUS_TOOLTIPS,
    STATUS_KIND: STATUS_KIND
  };
})(window);
