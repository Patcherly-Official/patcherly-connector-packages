/*!
 * Shared formatters for the WP plugin admin UI.
 *
 * Loaded by the Errors page (patcherly-errors.js) and the Demo page
 * (patcherly-demo.js) so the human-readable status labels stay identical
 * across both — the demo page is sold as a faithful preview of the real
 * Errors page, and drift between the two has bitten reviewers in the past.
 *
 * `formatStatusLabel` mirrors the dashboard's lifecycle vocabulary
 * (server/app/core/state.py :: _PREFERRED_STATUS_ORDER). Update this file
 * + the dashboard label map together when a new canonical status appears.
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

  function formatStatusLabel(status) {
    if (!status) return '—';
    return STATUS_LABELS[status] || String(status).replace(/_/g, ' ');
  }
  function statusBadgeHtml(status) {
    var label = formatStatusLabel(status);
    var kind  = STATUS_KIND[status] || 'neutral';
    return '<span class="patcherly-status-badge patcherly-status-badge--' + kind + '">' + label + '</span>';
  }

  global.PatcherlyFormat = {
    formatStatusLabel: formatStatusLabel,
    statusBadgeHtml: statusBadgeHtml,
    STATUS_LABELS: STATUS_LABELS,
    STATUS_KIND: STATUS_KIND
  };
})(window);
