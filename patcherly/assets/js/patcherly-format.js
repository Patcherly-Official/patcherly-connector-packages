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
 * `errorPreviewText` / `errorFullText` mirror dashboard-next/lib/errorDisplay.ts
 * (language-aware headlines when API `message` is absent).
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
    pending_analysis:        'Pending analysis',
    analysis_failed:         'Analysis failed',
    analyzed:                'Analyzed',
    awaiting_approval:       'Ready to Patch',
    manual_review_required:  'Manual review',
    approved:                'Approved',
    applying:                'Applying',
    fixed:                   'Patched',
    failed:                  'Apply failed',
    rolling_back:            'Rolling back',
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
    pending_analysis:        'Queued for AI analysis — Patcherly will analyse this shortly. If analysis is busy, automatic retries run in the background.',
    analysis_failed:         "The AI couldn't analyse this one after automatic retries — click Retry analysis to try again.",
    analyzed:                'Analyzed — no patch proposed (Not patchable). Mark fixed or delete.',
    awaiting_approval:       'A draft patch is ready — review it, then click Approve patch in the row actions to apply.',
    manual_review_required:  'Patcherly wants a human eye on this one before applying any patch.',
    approved:                'Approved — Patcherly will apply this patch on the next pass.',
    applying:                'The drafted patch is being written to your code right now.',
    fixed:                   'Patch applied successfully. A pre-apply backup stays on your server for rollback.',
    failed:                  "Applying the patch failed — your code wasn't changed.",
    rolling_back:            'Patcherly is restoring the pre-apply backup right now.',
    rolled_back:             'Backup restored — your code is back to its pre-patch state.',
    rollback_failed:         "Rollback didn't complete — your code wasn't reverted.",
    dismissed:               'Read-only status — use Hide or Reject patch on new errors.',
    ignored:                 'Hidden from the default view (Hide or reject-not-needed). Unignore to restore to pending.',
    excluded:                'Excluded by a workspace rule — Patcherly skips this one.',
    manual:                  'Read-only status — Mark as manually patched writes Patched.'
  };

  // Badge kind drives the colour pill in the status column. Buckets map to
  // .patcherly-status-badge--{ok,warn,err,neutral,ai,yellow,info} in connector CSS.
  var STATUS_KIND = {
    pending:                 'neutral',
    pending_analysis:        'ai',
    analysis_failed:         'err',
    analyzed:                'ai',
    awaiting_approval:       'ai',
    manual_review_required:  'ai',
    approved:                'ok',
    applying:                'ok',
    fixed:                   'ok',
    failed:                  'err',
    rolling_back:            'warn',
    rolled_back:             'warn',
    rollback_failed:         'err',
    dismissed:               'neutral',
    ignored:                 'neutral',
    excluded:                'neutral',
    manual:                  'info'
  };

  // Approved-row sub-states (mirror dashboard-next/lib/errorStatus.ts).
  var APPROVED_PHASE_LABELS = {
    waiting:         'Waiting for connector',
    dispatch_failed: 'Dispatch failed',
    stalled:         'Apply stalled'
  };
  var APPROVED_PHASE_TOOLTIPS = {
    waiting:         'Patch approved — waiting for the connector to fetch and apply it.',
    dispatch_failed: 'Apply dispatch failed — use Retry Patch to try again.',
    stalled:         'Apply stalled — rescue ping failed or the connector is unreachable. Use Retry Patch.'
  };

  var IN_FLIGHT_ERROR_STATUSES = {
    pending_analysis: true,
    approved:         true,
    applying:         true,
    rolling_back:     true
  };

  var PRE_ANALYSIS_ERROR_STATUSES = {
    pending: true,
    pending_analysis: true,
    excluded: true,
    ignored: true
  };

  var IGNORE_USER_ALLOWED_STATUSES = {
    pending: true,
    pending_analysis: true,
    analysis_failed: true,
    excluded: true,
    failed: true,
    rolled_back: true,
    rollback_failed: true
  };

  function dispatchFieldsFrom(item) {
    if (!item || typeof item !== 'object') return null;
    if (item.apply_dispatch_ok !== undefined || item.apply_dispatch_ok === null
      || item.apply_stalled_at || item.apply_dispatch_error || item.apply_dispatch_channel
      || item.fix_cached_on_connector || item.target_edge_rescue_blocked
      || item.executed_at || item.backup_path) {
      return item;
    }
    return null;
  }

  function resolveApprovedApplyPhase(dispatch) {
    dispatch = dispatch || {};
    if (dispatch.apply_dispatch_ok === false) return 'dispatch_failed';
    if (dispatch.apply_stalled_at) return 'stalled';
    return 'waiting';
  }

  function escHtml(s) {
    if (s == null) return '';
    return String(s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]);
    });
  }
  function isApplyingAwaitingVerification(dispatch) {
    dispatch = dispatch || {};
    return Boolean(dispatch.executed_at) && String(dispatch.backup_path || '').trim() !== '';
  }

  function formatStatusLabel(status, dispatch) {
    if (!status) return '—';
    if (status === 'applying' && isApplyingAwaitingVerification(dispatch)) {
      return 'Verifying patch';
    }
    if (status === 'approved' && dispatch) {
      return APPROVED_PHASE_LABELS[resolveApprovedApplyPhase(dispatch)];
    }
    return STATUS_LABELS[status] || String(status).replace(/_/g, ' ');
  }
  function formatStatusTooltip(status, dispatch) {
    if (status === 'applying' && isApplyingAwaitingVerification(dispatch)) {
      return 'Patch is on your server — Patcherly is waiting for connector smoke-test confirmation.';
    }
    if (status === 'approved' && dispatch) {
      var phase = resolveApprovedApplyPhase(dispatch);
      if (phase === 'dispatch_failed') {
        var err = String(dispatch.apply_dispatch_error || '').trim();
        var cacheHint = localCacheApplyFallbackHint({
          status: 'approved',
          apply_dispatch_ok: false,
          apply_dispatch_error: dispatch.apply_dispatch_error,
          fix_cached_on_connector: dispatch.fix_cached_on_connector,
          target_edge_rescue_blocked: dispatch.target_edge_rescue_blocked
        });
        if (cacheHint) return cacheHint;
        return err || APPROVED_PHASE_TOOLTIPS.dispatch_failed;
      }
      return APPROVED_PHASE_TOOLTIPS[phase];
    }
    return STATUS_TOOLTIPS[status] || '';
  }
  function statusBadgeKind(status, dispatch) {
    if (status === 'approved' && dispatch) {
      var phase = resolveApprovedApplyPhase(dispatch);
      if (phase === 'dispatch_failed' || phase === 'stalled') return 'err';
      if (phase === 'waiting') return 'ok';
    }
    if (status === 'approved') return 'ok';
    if (status === 'applying') return 'ok';
    return STATUS_KIND[status] || 'neutral';
  }
  function statusWaitingMotion(status, dispatch) {
    if (status === 'pending_analysis') return 'pulse';
    if (status === 'applying' || status === 'rolling_back') return 'spin';
    if (status === 'approved' && dispatch && resolveApprovedApplyPhase(dispatch) === 'waiting') return 'pulse';
    return null;
  }
  function statusBadgeHtml(status, itemOrDispatch) {
    var dispatch = typeof itemOrDispatch === 'string' ? null : dispatchFieldsFrom(itemOrDispatch);
    var label = formatStatusLabel(status, dispatch);
    var kind  = statusBadgeKind(status, dispatch);
    var tip   = formatStatusTooltip(status, dispatch);
    var motion = statusWaitingMotion(status, dispatch);
    var cls = 'patcherly-status-badge patcherly-status-badge--' + kind;
    if (motion) cls += ' patcherly-status-badge--waiting patcherly-status-badge--waiting-' + motion;
    // `title` drives the OS-native tooltip on hover; aria-label keeps
    // screen readers in lockstep so the explanation isn't visual-only.
    var attrs = 'class="' + cls + '"';
    if (tip) {
      attrs += ' title="' + escHtml(tip) + '"';
      attrs += ' aria-label="' + escHtml(label + ' — ' + tip) + '"';
    }
    return '<span ' + attrs + '>' + escHtml(label) + '</span>';
  }

  function stripAllTimestampPrefixes(line) {
    var s = String(line || '').trim();
    for (;;) {
      var bracket = s.match(/^\[[^\]]+\]\s*/);
      if (!bracket) break;
      s = s.slice(bracket[0].length).trim();
    }
    return s;
  }

  var RESCUE_FATAL_RE = /^Patcherly Rescue fatal:\s*/i;
  var PHP_ON_LINE_RE = /\s+on line\s+(\d+)/gi;
  var SOURCE_ATTRIBUTION = 'Patcherly Advanced Logger';
  var EMERGENCY_SOURCE_ATTRIBUTION = 'Patcherly Emergency Logger';

  function stripRescueWrapper(line) {
    return String(line || '').replace(RESCUE_FATAL_RE, '').trim();
  }

  function normalizePhpOnLineToColon(text) {
    return String(text || '').replace(PHP_ON_LINE_RE, ':$1');
  }

  function shouldSkipMessageInFullText(item, message, logLine) {
    if (!message || !logLine) return false;
    var mLower = message.toLowerCase();
    var langKey = resolveLanguageKey(item && item.code_language);
    if (langKey === 'default') {
      var inferred = inferLanguageKeyFromBody(stripAllTimestampPrefixes(logLine));
      if (inferred) langKey = inferred;
    }
    if (langKey === 'php') {
      var stripped = normalizePhpOnLineToColon(
        stripRescueWrapper(stripAllTimestampPrefixes(logLine))
      );
      return stripped.toLowerCase().indexOf(mLower) !== -1;
    }
    return stripAllTimestampPrefixes(logLine).toLowerCase().indexOf(mLower) !== -1;
  }

  function isRescueSourced(item, logLine) {
    var ch = String((item && item.ingest_channel) || '').toLowerCase();
    if (ch === 'rescue_shutdown' || ch === 'rescue_poll') return true;
    return RESCUE_FATAL_RE.test(logLine || '');
  }

  function sourceAttributionForError(item, logLine) {
    if (isRescueSourced(item, logLine)) return EMERGENCY_SOURCE_ATTRIBUTION;
    return null;
  }

  function hasSourceAttribution(full) {
    return full.indexOf(SOURCE_ATTRIBUTION) !== -1 || full.indexOf(EMERGENCY_SOURCE_ATTRIBUTION) !== -1;
  }

  function inferLanguageKeyFromBody(body) {
    if (RESCUE_FATAL_RE.test(body) || /^PHP\s+(?:Fatal error|Parse error|Warning|Notice):/im.test(body)) {
      return 'php';
    }
    if (/^Traceback \(most recent call last\):/m.test(body)) return 'python';
    if (/^\s*at\s+\S.+\(.+:\d+:\d+\)\s*$/m.test(body)) return 'javascript';
    return null;
  }

  function resolveLanguageKey(codeLanguage) {
    var key = String(codeLanguage || '').trim().toLowerCase();
    if (key === 'php' || key === 'wordpress') return 'php';
    if (key === 'python') return 'python';
    if (key === 'javascript' || key === 'typescript' || key === 'nodejs' || key === 'node' || key === 'node.js') {
      return 'javascript';
    }
    return 'default';
  }

  function headlinePython(body) {
    var lines = String(body || '').split(/\r?\n/);
    var excRe = /^\s*([A-Z][\w.]*(?:Error|Exception)):\s*(.+)\s*$/;
    var i;
    for (i = lines.length - 1; i >= 0; i--) {
      var m = lines[i].match(excRe);
      if (m) return m[1] + ': ' + m[2].trim();
    }
    for (i = 0; i < lines.length; i++) {
      var stripped = lines[i].trim();
      if (!stripped || /^Traceback \(most recent call last\):$/i.test(stripped)) continue;
      if (stripped.indexOf('File ') === 0) continue;
      if (stripped.indexOf('raise ') === 0) continue;
      return stripped;
    }
    return lines.length ? lines[lines.length - 1].trim() : body;
  }

  function headlineJavascript(body) {
    var lines = String(body || '').split(/\r?\n/);
    var namedRe = /^\s*((?:\w+)?Error|(?:\w+)?Exception):\s+.+$/i;
    var uncaughtRe = /^\s*Uncaught\s+.+$/i;
    var frameRe = /^\s*at\s+.+\(.+:\d+:\d+\)\s*$/;
    var i;
    for (i = 0; i < lines.length; i++) {
      var stripped = lines[i].trim();
      if (!stripped) continue;
      if (namedRe.test(stripped) || uncaughtRe.test(stripped)) return stripped;
    }
    for (i = lines.length - 1; i >= 0; i--) {
      stripped = lines[i].trim();
      if (/^\w+Error:/.test(stripped)) return stripped;
    }
    for (i = 0; i < lines.length; i++) {
      stripped = lines[i].trim();
      if (stripped && !frameRe.test(stripped)) return stripped;
    }
    return lines.length ? lines[0].trim() : body;
  }

  function fallbackPreviewFromLogLine(logLine, codeLanguage) {
    var body = stripAllTimestampPrefixes(logLine);
    if (!body) return String(logLine || '').trim();
    var langKey = resolveLanguageKey(codeLanguage);
    if (langKey === 'default') {
      var inferred = inferLanguageKeyFromBody(body);
      if (inferred) langKey = inferred;
    }
    if (langKey === 'php') {
      body = stripRescueWrapper(body);
      return body.replace(/\s+on line\s+(\d+)/gi, ':$1');
    }
    if (langKey === 'python') return headlinePython(body);
    if (langKey === 'javascript') return headlineJavascript(body);
    var parts = body.split(/\r?\n/);
    for (i = 0; i < parts.length; i++) {
      if (parts[i].trim()) return parts[i].trim();
    }
    return body;
  }

  function errorPreviewText(item) {
    item = item || {};
    var message = String(item.message || '').trim();
    if (message) return message;
    var logLine = String(item.log_line || '').trim();
    if (!logLine) return '';
    return fallbackPreviewFromLogLine(logLine, item.code_language) || logLine;
  }

  function mergeErrorBody(item) {
    item = item || {};
    var logLine = String(item.log_line || '').trim();
    var traceback = String(item.traceback || '').trim();
    if (!logLine && !traceback) return '';
    if (!traceback || logLine.indexOf(traceback) !== -1) return logLine;
    if (!logLine) return traceback;
    return logLine + '\n' + traceback;
  }

  function errorFullText(item) {
    item = item || {};
    var message = String(item.message || '').trim();
    var body = mergeErrorBody(item);
    var blocks = [];
    var skipMessage = shouldSkipMessageInFullText(item, message, body);
    if (message && !skipMessage) blocks.push(message);
    if (body && (!message || body !== message)) blocks.push(body);
    var full = blocks.join('\n\n');
    var attribution = sourceAttributionForError(item, body);
    if (attribution && full && !hasSourceAttribution(full)) {
      full += '\n\n(' + attribution + ')';
    }
    return full;
  }

  function severityBadgeHtml(severity) {
    var label = String(severity || '').trim();
    if (!label) return '—';
    var kind = 'neutral';
    if (label === 'Critical') kind = 'critical';
    else if (label === 'High') kind = 'high';
    else if (label === 'Medium') kind = 'medium';
    else if (label === 'Low') kind = 'low';
    return '<span class="patcherly-severity-badge patcherly-severity-badge--' + kind + '">' + escHtml(label) + '</span>';
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
    circleCheck:'<circle cx="12" cy="12" r="10"/><path d="m9 12 2 2 4-4"/>',
    shield:     '<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/>',
    shieldCheck:'<path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/>',
    x:          '<path d="M18 6 6 18"/><path d="m6 6 12 12"/>',
    rotateCcw:  '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/>',
    refreshCw:  '<path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/>',
    clock:      '<circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>',
    trash:      '<path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M10 11v6"/><path d="M14 11v6"/>',
    loader:     '<path d="M21 12a9 9 0 1 1-6.219-8.56"/>',
    history:    '<path d="M3 12a9 9 0 1 0 9-9 9.75 9.75 0 0 0-6.74 2.74L3 8"/><path d="M3 3v5h5"/><path d="M12 7v5l4 2"/>'
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
  //   - variant: one of info|ai|accent|success|warning|danger|muted|neutral
  //   - busy:    optional truthy → stage-tint spinner (variant picks tint)
  function waitingIconTintClass(variant) {
    if (variant === 'ai') return 'patcherly-icon-btn--waiting-ai';
    if (variant === 'warning') return 'patcherly-icon-btn--waiting-warning';
    return 'patcherly-icon-btn--waiting-success';
  }

  function iconButtonHtml(opts) {
    var act     = opts.act || '';
    var title   = opts.title || '';
    var icon    = opts.icon || 'check';
    var variant = opts.variant || 'muted';
    if (opts.busy) {
      return '<span class="patcherly-icon-btn ' + waitingIconTintClass(variant) + ' is-busy" title="' + escHtml(title) + '" aria-label="' + escHtml(title) + '">' + iconHtml('loader') + '</span>';
    }
    return '<button type="button" '
      + 'class="patcherly-icon-btn patcherly-icon-btn--' + variant + '" '
      + 'data-act="' + escHtml(act) + '" '
      + 'title="' + escHtml(title) + '" '
      + 'aria-label="' + escHtml(title) + '">'
      + iconHtml(icon)
      + '</button>';
  }

  function normalizeIsoForParse(iso) {
    if (iso == null || iso === '') return '';
    var s = String(iso).trim();
    if (s === '' || s === '—') return s;
    // API may emit naive UTC with microsecond precision — trim for Date.parse.
    var m = s.match(/^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})\.(\d+)(.*)$/);
    if (m) {
      s = m[1] + '.' + (m[2].slice(0, 3) + '000').slice(0, 3) + m[3];
    }
    if (/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?$/.test(s)) {
      s += 'Z';
    }
    return s;
  }

  /** WordPress determine_locale() uses en_US; Intl expects BCP 47 (en-US). */
  function normalizeBcp47Locale(locale) {
    if (locale == null || locale === '') return undefined;
    return String(locale).replace(/_/g, '-');
  }

  function pad2(n) {
    return n < 10 ? '0' + n : '' + n;
  }

  var PHP_DATE_TOKEN_ORDER = ['Y', 'y', 'F', 'M', 'l', 'D', 'm', 'n', 'd', 'j', 'H', 'h', 'G', 'g', 'i', 's', 'A', 'a'];

  function applyPhpDateFormat(format, tokens) {
    if (!format) return '';
    var out = '';
    for (var i = 0; i < format.length; i++) {
      if (format.charAt(i) === '\\' && i + 1 < format.length) {
        out += format.charAt(i + 1);
        i++;
        continue;
      }
      var matched = false;
      for (var t = 0; t < PHP_DATE_TOKEN_ORDER.length; t++) {
        var tok = PHP_DATE_TOKEN_ORDER[t];
        if (format.substr(i, tok.length) === tok && tokens[tok] != null) {
          out += tokens[tok];
          i += tok.length - 1;
          matched = true;
          break;
        }
      }
      if (!matched) out += format.charAt(i);
    }
    return out;
  }

  /**
   * Build PHP date()/wp_date() token map for a UTC instant in the site timezone.
   * opts: { timezone, locale, hour12 }
   */
  function getWpDateTimeTokens(d, opts) {
    opts = opts || {};
    var tz = opts.timezone || undefined;
    var loc = normalizeBcp47Locale(opts.locale);
    var hour12 = typeof opts.hour12 === 'boolean' ? opts.hour12 : undefined;
    var parts = {};
    try {
      new Intl.DateTimeFormat(loc, {
        timeZone: tz,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: 'numeric',
        minute: '2-digit',
        second: '2-digit',
        hour12: hour12
      }).formatToParts(d).forEach(function (p) {
        if (p.type !== 'literal') parts[p.type] = p.value;
      });
    } catch (_) {
      return null;
    }
    var monthLong = '';
    var monthShort = '';
    var weekdayLong = '';
    var weekdayShort = '';
    try {
      monthLong = new Intl.DateTimeFormat(loc, { timeZone: tz, month: 'long' }).format(d);
      monthShort = new Intl.DateTimeFormat(loc, { timeZone: tz, month: 'short' }).format(d);
      weekdayLong = new Intl.DateTimeFormat(loc, { timeZone: tz, weekday: 'long' }).format(d);
      weekdayShort = new Intl.DateTimeFormat(loc, { timeZone: tz, weekday: 'short' }).format(d);
    } catch (_) {}
    var y = parseInt(parts.year, 10);
    var m = parseInt(parts.month, 10);
    var day = parseInt(parts.day, 10);
    var minute = parseInt(parts.minute, 10);
    var second = parseInt(parts.second || '0', 10);
    var hourParsed = parseInt(parts.hour, 10);
    var dayPeriod = (parts.dayPeriod || '').toLowerCase();
    var hour24 = hourParsed;
    if (hour12 === true) {
      if (dayPeriod === 'pm' && hourParsed < 12) hour24 = hourParsed + 12;
      else if (dayPeriod === 'am' && hourParsed === 12) hour24 = 0;
    }
    var hour12v = hour24 % 12;
    if (hour12v === 0) hour12v = 12;
    var ampm = dayPeriod || (hour24 < 12 ? 'am' : 'pm');
    return {
      Y: '' + y,
      y: pad2(y % 100),
      F: monthLong,
      M: monthShort,
      l: weekdayLong,
      D: weekdayShort,
      m: pad2(m),
      n: '' + m,
      d: pad2(day),
      j: '' + day,
      g: '' + hour12v,
      h: pad2(hour12v),
      G: '' + hour24,
      H: pad2(hour24),
      i: pad2(minute),
      s: pad2(second),
      a: ampm,
      A: ampm.toUpperCase()
    };
  }

  /**
   * Format a UTC ISO timestamp using the site timezone (Settings → General).
   * opts: { timezone, locale, hour12, date_format, time_format }
   */
  function formatDateTimeIso(iso, opts) {
    opts = opts || {};
    if (iso == null || iso === '') return '—';
    var raw = String(iso);
    // Already formatted by PHP (ajax_errors_list) — no ISO "T" separator.
    if (raw.indexOf('T') === -1 && raw.indexOf('—') === -1) {
      return raw;
    }
    try {
      var d = new Date(normalizeIsoForParse(raw));
      if (isNaN(d.getTime())) return raw;
      var dateFmt = opts.date_format;
      var timeFmt = opts.time_format;
      if (dateFmt && timeFmt) {
        var tokens = getWpDateTimeTokens(d, opts);
        if (tokens) {
          return applyPhpDateFormat(dateFmt, tokens) + ' ' + applyPhpDateFormat(timeFmt, tokens);
        }
      }
      var intlOpts = {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: 'numeric',
        minute: '2-digit'
      };
      if (opts.timezone) intlOpts.timeZone = opts.timezone;
      if (typeof opts.hour12 === 'boolean') intlOpts.hour12 = opts.hour12;
      return new Intl.DateTimeFormat(normalizeBcp47Locale(opts.locale), intlOpts).format(d);
    } catch (_) {
      return raw;
    }
  }

  // Row-action legend — shared by the Errors page and Demo page footers.
  // Keep short blurbs in sync with dashboard ErrorsActionLegend.tsx.
  var ACTION_LEGEND = [
    {
      key: 'analyze', icon: 'brain', variant: 'ai', label: 'Analyze with AI',
      description: 'Start or retry AI analysis.'
    },
    {
      key: 'retry_analysis', icon: 'brain', variant: 'ai', label: 'Retry analysis',
      description: 'Re-queue after analysis failed.'
    },
    {
      key: 'preview_fix', icon: 'eye', variant: 'ai', label: 'Preview patch',
      description: 'View the suggested code change.'
    },
    {
      key: 'approve_fix', icon: 'shieldCheck', variant: 'success', label: 'Approve patch',
      description: 'Approve and start apply.'
    },
    {
      key: 'reject_patch_close', icon: 'x', variant: 'danger', label: 'Reject patch',
      description: 'Decline the suggestion.'
    },
    {
      key: 'retry_apply', icon: 'shield', variant: 'success', label: 'Retry Patch',
      description: 'Retry when apply did not finish.'
    },
    {
      key: 'waiting_for_connector', icon: 'clock', variant: 'success', label: 'Waiting for connector',
      description: 'Approved — waiting for the connector.',
      waiting: 'pulse'
    },
    {
      key: 'mark_fixed', icon: 'check', variant: 'success', label: 'Mark as manually patched',
      description: 'Confirm you patched it yourself.'
    },
    {
      key: 'rollback_fix', icon: 'rotateCcw', variant: 'warning', label: 'Rollback patch',
      description: 'Restore the pre-apply backup.'
    },
    {
      key: 'ignore', icon: 'x', variant: 'muted', label: 'Hide Error & Ignore', errorsOnly: true,
      description: 'Hide from the default list.'
    },
    {
      key: 'unignore', icon: 'x', variant: 'success', label: 'Unignore', errorsOnly: true,
      description: 'Return to the active list.'
    },
    {
      key: 'history', icon: 'history', variant: 'neutral', label: 'Detail & history',
      description: 'Open detail and history.'
    },
    {
      key: 'delete', icon: 'trash', variant: 'danger', label: 'Delete',
      description: 'Remove never-applied rows.'
    },
    {
      key: 'in_progress', icon: 'loader', variant: 'success', label: 'In progress', busy: true,
      description: 'Analysis, apply, or rollback is running.'
    }
  ];

  function legendCopy(item) {
    var cfg = (global.PATCHERLY_FORMAT && global.PATCHERLY_FORMAT.actionLegend) || {};
    var t = item.key && cfg[item.key];
    return {
      label: (t && t.label) || item.label,
      description: (t && t.description) || item.description
    };
  }

  function waitingIcon(title) {
    return '<span class="patcherly-icon-btn patcherly-icon-btn--waiting-success patcherly-icon-btn--waiting-pulse patcherly-icon-btn--static" title="' + escHtml(title) + '" aria-label="' + escHtml(title) + '">' + iconHtml('clock') + '</span>';
  }

  function legendHelpFooter(href, label) {
    return '<p class="patcherly-legend-help">'
      + '<a href="' + escHtml(href) + '" target="_blank" rel="noopener noreferrer">'
      + escHtml(label)
      + '</a></p>';
  }

  var LEGEND_COLLAPSED_MAX_PX = 52;
  var LEGEND_PERSIST_STATUS = 'errors-legend-statuses';

  function legendUiCopy() {
    var ui = (global.PATCHERLY_FORMAT && global.PATCHERLY_FORMAT.legendUi) || {};
    return {
      actionIconsTitle: ui.actionIconsTitle || 'Action icons',
      statusBadgesTitle: ui.statusBadgesTitle || 'Status badges',
      showAll: ui.showAll || 'Show all',
      showLess: ui.showLess || 'Show less'
    };
  }

  function readLegendExpanded(key) {
    if (!key || typeof window === 'undefined' || !window.localStorage) return false;
    try {
      return window.localStorage.getItem(key) === '1';
    } catch (_) {
      return false;
    }
  }

  function writeLegendExpanded(key, expanded) {
    if (!key || typeof window === 'undefined' || !window.localStorage) return;
    try {
      window.localStorage.setItem(key, expanded ? '1' : '0');
    } catch (_) {}
  }

  function legendShellOpen(title, options) {
    options = options || {};
    var collapsible = !!options.collapsible;
    var panelId = options.panelId || 'patcherly-legend-panel';
    var copy = legendUiCopy();
    var html = '<div class="patcherly-legend-shell' + (collapsible ? ' patcherly-legend-shell--collapsible' : '') + '">';
    html += '<div class="patcherly-legend-shell__header">';
    html += '<p class="patcherly-legend-shell__title">' + escHtml(title) + '</p>';
    if (collapsible) {
      html += '<button type="button" class="patcherly-legend-shell__toggle" aria-expanded="false" aria-controls="' + escHtml(panelId) + '">' + escHtml(copy.showAll) + '</button>';
    }
    html += '</div>';
    html += '<div class="patcherly-legend-shell__panel' + (collapsible ? ' patcherly-legend-shell__panel--collapsed' : '') + '" id="' + escHtml(panelId) + '">';
    return html;
  }

  function legendShellClose(helpHtml) {
    var html = '</div>';
    if (helpHtml) html += helpHtml;
    html += '</div>';
    return html;
  }

  function wireCollapsibleLegend(root, persistKey) {
    if (!root) return;
    var btn = root.querySelector('.patcherly-legend-shell__toggle');
    var panel = root.querySelector('.patcherly-legend-shell__panel');
    if (!btn || !panel) return;
    var copy = legendUiCopy();
    var expanded = readLegendExpanded(persistKey);
    function apply() {
      btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      btn.textContent = expanded ? copy.showLess : copy.showAll;
      panel.classList.toggle('patcherly-legend-shell__panel--collapsed', !expanded);
      panel.style.maxHeight = expanded ? '' : (LEGEND_COLLAPSED_MAX_PX + 'px');
    }
    apply();
    btn.addEventListener('click', function () {
      expanded = !expanded;
      writeLegendExpanded(persistKey, expanded);
      apply();
    });
  }

  function actionsLegendHtml(opts) {
    opts = opts || {};
    var includeIgnore = opts.includeIgnore !== false;
    var copy = legendUiCopy();
    var html = legendShellOpen(copy.actionIconsTitle, { panelId: 'patcherly-actions-legend-panel' });
    html += '<div class="patcherly-actions-legend">';
    ACTION_LEGEND.forEach(function (item) {
      if (item.errorsOnly && !includeIgnore) return;
      var itemCopy = legendCopy(item);
      var btnCls = 'patcherly-icon-btn';
      if (item.busy || item.waiting) {
        btnCls += ' ' + waitingIconTintClass(item.variant);
        if (item.busy) btnCls += ' is-busy';
        if (item.waiting === 'pulse') btnCls += ' patcherly-icon-btn--waiting-pulse';
        btnCls += ' patcherly-icon-btn--static';
      } else {
        btnCls += ' patcherly-icon-btn--' + item.variant;
      }
      html += '<span class="patcherly-actions-legend__item">'
        + '<span class="' + btnCls + '" aria-hidden="true">' + iconHtml(item.icon) + '</span>'
        + '<span class="patcherly-actions-legend__text">'
        + '<span class="patcherly-actions-legend__label">' + escHtml(itemCopy.label) + '</span>';
      if (itemCopy.description) {
        html += '<span class="patcherly-actions-legend__desc">' + escHtml(itemCopy.description) + '</span>';
      }
      html += '</span></span>';
    });
    html += '</div>';
    html += legendShellClose(
      legendHelpFooter(
        'https://help.patcherly.com/error-management/approving-fixes/',
        'Approving patches in Help'
      )
    );
    return html;
  }

  function mountActionsLegend(containerId, opts) {
    var el = typeof containerId === 'string' ? document.getElementById(containerId) : containerId;
    if (!el) return;
    el.innerHTML = actionsLegendHtml(opts || {});
  }

  // Status-column legend — mirrors dashboard-next/lib/errorStatus.ts ERROR_STATUS_LEGEND_COLUMNS.
  var STATUS_LEGEND_COLUMNS = [
    {
      id: 'detect',
      title: 'Detect / analyze',
      entries: [
        { key: 'pending', status: 'pending', blurb: 'Detected — waiting for analysis.' },
        { key: 'pending_analysis', status: 'pending_analysis', blurb: 'Queued — waiting for AI analysis.' },
        { key: 'analyzed', status: 'analyzed', blurb: 'Not patchable — analysis finished without a draft patch.' },
        { key: 'awaiting_approval', status: 'awaiting_approval', blurb: 'Review and approve the patch.' },
        { key: 'analysis_failed', status: 'analysis_failed', blurb: 'Analysis failed — retry analysis.' },
        { key: 'manual_review_required', status: 'manual_review_required', blurb: 'Needs a human decision before apply.' }
      ]
    },
    {
      id: 'apply',
      title: 'Apply',
      entries: [
        { key: 'approved_waiting', status: 'approved', dispatch: { apply_dispatch_ok: true }, blurb: 'Approved — waiting for the connector.' },
        { key: 'applying', status: 'applying', blurb: 'Writing the patch on your server.' },
        { key: 'fixed', status: 'fixed', blurb: 'Patch applied successfully.' },
        { key: 'approved_dispatch_failed', status: 'approved', dispatch: { apply_dispatch_ok: false }, blurb: 'Could not reach the connector — retry Patch.' },
        { key: 'approved_stalled', status: 'approved', dispatch: { apply_stalled_at: '1970-01-01T00:00:00Z' }, blurb: 'Apply waited too long — retry Patch.' },
        { key: 'failed', status: 'failed', blurb: 'Apply failed — code may be unchanged.' }
      ]
    },
    {
      id: 'rollback',
      title: 'Rollback',
      entries: [
        { key: 'rolling_back', status: 'rolling_back', blurb: 'Restoring the pre-apply backup.' },
        { key: 'rolled_back', status: 'rolled_back', blurb: 'Backup restored.' },
        { key: 'rollback_failed', status: 'rollback_failed', blurb: 'Rollback did not complete.' }
      ]
    },
    {
      id: 'other',
      title: 'Other',
      entries: [
        { key: 'suspicious', flag: 'suspicious', blurb: 'Quarantined — prompt-injection or unsafe context; do not apply.' },
        { key: 'ignored', status: 'ignored', blurb: 'Hidden from the default list.' },
        { key: 'excluded', status: 'excluded', blurb: 'Skipped by a workspace rule.' },
        { key: 'dismissed', status: 'dismissed', blurb: 'Read-only status — use Hide or Reject patch.' },
        { key: 'manual', status: 'manual', blurb: 'Mark as manually patched writes Patched.' }
      ]
    }
  ];
  var STATUS_LEGEND = [];
  STATUS_LEGEND_COLUMNS.forEach(function (col) {
    col.entries.forEach(function (entry) { STATUS_LEGEND.push(entry); });
  });

  function statusLegendHtml() {
    var copy = legendUiCopy();
    var html = legendShellOpen(copy.statusBadgesTitle, {
      collapsible: true,
      panelId: 'patcherly-status-legend-panel'
    });
    html += '<div class="patcherly-status-legend__columns">';
    STATUS_LEGEND_COLUMNS.forEach(function (col) {
      html += '<div class="patcherly-status-legend__column">'
        + '<p class="patcherly-status-legend__column-title">' + escHtml(col.title) + '</p>'
        + '<div class="patcherly-status-legend__grid">';
      col.entries.forEach(function (entry) {
        var blurb = entry.blurb || (entry.status ? formatStatusTooltip(entry.status, entry.dispatch) : '');
        var badgeHtml = entry.flag === 'suspicious'
          ? '<span class="patcherly-status-badge patcherly-status-badge--err" title="Quarantined — prompt-injection markers detected; patch must not be applied">Suspicious</span>'
          : statusBadgeHtml(entry.status, entry.dispatch);
        html += '<span class="patcherly-status-legend__item">'
          + badgeHtml
          + '<span class="patcherly-status-legend__text">';
        if (blurb) {
          html += '<span class="patcherly-status-legend__desc">' + escHtml(blurb) + '</span>';
        }
        html += '</span></span>';
      });
      html += '</div></div>';
    });
    html += '</div>';
    html += '<div class="patcherly-legend-shell__fade" aria-hidden="true"></div>';
    html += legendShellClose(
      legendHelpFooter(
        'https://help.patcherly.com/error-management/understanding-errors/',
        'Error statuses in Help'
      )
    );
    return html;
  }

  function mountStatusLegend(containerId) {
    var el = typeof containerId === 'string' ? document.getElementById(containerId) : containerId;
    if (!el) return;
    el.innerHTML = statusLegendHtml();
    wireCollapsibleLegend(el.querySelector('.patcherly-legend-shell'), LEGEND_PERSIST_STATUS);
  }

  // ── AI confidence ────────────────────────────────────────────────────
  // Mirrors dashboard-next/lib/errorWorkflowActions.ts. Confidence is stored
  // 0..100 upstream, but be defensive about a 0..1 fraction. Never exceeds
  // 100%. Tone grades against the apply threshold (default 90%): high >=
  // threshold, medium >= half threshold, low below.
  var DEFAULT_FIX_MIN_CONFIDENCE = 0.9;
  function normalizeConfidence(value) {
    if (value === null || value === undefined || value === '') return null;
    var x = Number(value);
    if (!isFinite(x)) return null;
    var unit = x > 1 ? x / 100 : x;
    return Math.max(0, Math.min(1, unit));
  }
  function formatConfidencePercent(value) {
    var n = normalizeConfidence(value);
    if (n === null) return '—';
    return Math.round(n * 100) + '%';
  }
  function confidenceTone(value, threshold) {
    var n = normalizeConfidence(value);
    if (n === null) return null;
    var t = typeof threshold === 'number' && threshold > 0 ? threshold : DEFAULT_FIX_MIN_CONFIDENCE;
    if (n >= t) return 'high';
    if (n >= t / 2) return 'medium';
    return 'low';
  }

  // ── Apply dispatch workflow (mirror dashboard-next/lib/errorWorkflowActions.ts) ──
  function isInFlightErrorStatus(status) {
    return Boolean(IN_FLIGHT_ERROR_STATUSES[(status || '').trim()]);
  }
  function hasInFlightError(items) {
    if (!Array.isArray(items)) return false;
    for (var i = 0; i < items.length; i++) {
      if (isInFlightErrorStatus(items[i] && items[i].status)) return true;
    }
    return false;
  }
  /** Poll only while status can change without operator action (not dispatch-failed approved rows). */
  function needsActivePolling(items) {
    if (!Array.isArray(items)) return false;
    for (var i = 0; i < items.length; i++) {
      var item = items[i] || {};
      var st = (item.status || '').trim();
      if (st === 'pending_analysis' || st === 'applying' || st === 'rolling_back') {
        return true;
      }
      if (st === 'approved') {
        if (item.apply_dispatch_ok === false || item.apply_stalled_at) {
          continue;
        }
        return true;
      }
    }
    return false;
  }
  function errorMayHaveAnalysisRecord(status) {
    return !PRE_ANALYSIS_ERROR_STATUSES[(status || 'pending').trim()];
  }
  function isPatchReadyStatus(status) {
    var st = (status || 'pending').trim();
    return st === 'awaiting_approval' || st === 'manual_review_required';
  }
  function analysisRetryingBadgeLabel(error) {
    error = error || {};
    if (!error.analysis_retry_scheduled) return '';
    var n = Number(error.analysis_retry_count);
    var max = Number(error.analysis_retry_max);
    if (isFinite(n) && n > 0 && isFinite(max) && max > 0) {
      return 'Retrying analysis (' + n + '/' + max + ')';
    }
    return 'Retrying analysis';
  }
  function notPatchableBadgeHtml(error) {
    error = error || {};
    if ((error.status || '').trim() !== 'analyzed') return '';
    if (error.suspicious) return '';
    var tip = String(error.analysis_reason_display || '').trim();
    var attrs = 'class="patcherly-status-badge patcherly-status-badge--warn"';
    if (tip) {
      attrs += ' title="' + escHtml(tip) + '"';
      attrs += ' aria-label="' + escHtml('Not patchable — ' + tip) + '"';
    }
    return '<span ' + attrs + '>Not patchable</span>';
  }
  function canShowRejectPatchAction(status) {
    return isPatchReadyStatus(status);
  }
  /** Approve when Ready to Patch — do not require fix_path (parity with dashboard). */
  function canShowApproveFixAction(error) {
    error = error || {};
    if (error.suspicious) return false;
    var st = (error.status || '').trim();
    return isPatchReadyStatus(st);
  }
  /** Not patchable — analyzed + durable no_patch_code (parity with dashboard). */
  function isNotPatchableError(error) {
    error = error || {};
    if ((error.status || '').trim() !== 'analyzed') return false;
    return !!String(error.no_patch_code || '').trim();
  }
  /**
   * Re-analyze / Retry analysis — hide for Not patchable; keep for analysis_failed
   * and rare bare analyzed without no_patch_code (parity with dashboard).
   */
  function canShowReAnalyzeAction(error) {
    error = error || {};
    if (error.suspicious) return false;
    var st = (error.status || '').trim();
    if (st === 'analysis_failed') return true;
    if (st === 'analyzed') return !isNotPatchableError(error);
    return false;
  }
  function reAnalyzeActionTitle(error) {
    return ((error && error.status) || '').trim() === 'analyzed' ? 'Re-analyze' : 'Retry analysis';
  }
  function canShowIgnoreAction(status) {
    var st = (status || '').trim();
    if (!st || st === 'ignored') return false;
    return !!IGNORE_USER_ALLOWED_STATUSES[st];
  }
  function getRejectPatchActionLabel(_status) {
    return 'Reject patch';
  }
  function errorHasAnalysisArtifact(error) {
    if (!error || typeof error !== 'object') return false;
    if (String(error.analyzed_at || '').trim()) return true;
    var conf = normalizeConfidence(error.confidence);
    if (conf != null) return true;
    if (String(error.fix_path || '').trim()) return true;
    return false;
  }
  function canShowFixPreviewForError(error) {
    var st = (error && error.status ? String(error.status) : 'pending').trim();
    if (st === 'dismissed' && !errorHasAnalysisArtifact(error)) return false;
    return errorMayHaveAnalysisRecord(st);
  }
  function canShowFixPreviewAction(status) {
    return errorMayHaveAnalysisRecord(status);
  }
  function isApplyDispatchFailed(error) {
    return (error.status || '').trim() === 'approved' && error.apply_dispatch_ok === false;
  }
  function isEdgeRescueDispatchError(error) {
    error = error || {};
    if (error.target_edge_rescue_blocked === true) return true;
    var err = String(error.apply_dispatch_error || '').toLowerCase();
    return err.indexOf('cloudflare') >= 0 || err.indexOf('edge protection') >= 0 || err.indexOf('bot fight') >= 0;
  }
  function isWordpressRescueDispatchFailure(error) {
    error = error || {};
    var channel = String(error.apply_dispatch_channel || '').trim();
    if (channel === 'agent_poll') return false;
    if (channel === 'rescue') return true;
    return isEdgeRescueDispatchError(error);
  }
  function edgeRescueBlockedSummary() {
    return 'Your website security (Cloudflare) blocked Patcherly from applying the patch automatically.';
  }
  function formatApplyDispatchFailureMessage(error) {
    error = error || {};
    var hint = localCacheApplyFallbackHint(error);
    if (hint) {
      return edgeRescueBlockedSummary() + ' ' + hint;
    }
    var err = String(error.apply_dispatch_error || '').trim();
    return err || 'We could not reach your site to apply the patch. Try Retry Patch or check that your connector is running.';
  }
  function edgeRescueNoticeForError(error) {
    if (!error) return null;
    if (!localCacheApplyFallbackHint(error)) return null;
    return formatApplyDispatchFailureMessage(error);
  }
  function edgeRescueNoticeFromErrors(items) {
    if (!items || !items.length) return null;
    for (var i = 0; i < items.length; i++) {
      var notice = edgeRescueNoticeForError(items[i]);
      if (notice) return notice;
    }
    return null;
  }
  var EDGE_RESCUE_TOAST_DURATION_MS = 0;
  var LOCAL_CACHE_STATUS_REFRESH_HINT =
    'The fix was applied on this site. Error status will refresh in a few moments.';
  function localCacheApplyFallbackHint(error) {
    error = error || {};
    if (!isApplyDispatchFailed(error)) return null;
    if (!isWordpressRescueDispatchFailure(error)) return null;
    if (!isEdgeRescueDispatchError(error)) return null;
    if (error.fix_cached_on_connector) {
      return 'Click Retry Patch to apply the patch saved on this site.';
    }
    return 'Click Retry Patch — the connector will fetch the patch from Patcherly and apply it on this site automatically.';
  }
  function isApplyStalled(error) {
    return (error.status || '').trim() === 'approved' && Boolean(error.apply_stalled_at);
  }
  /** Parity with dashboard APPLY_WAIT_RETRY_MS — 5 minutes after successful dispatch. */
  var APPLY_WAIT_RETRY_MS = 5 * 60 * 1000;
  function _parseIsoMs(iso) {
    if (!iso) return null;
    var ms = Date.parse(String(iso));
    return isFinite(ms) ? ms : null;
  }
  function isApplyWaitingTooLong(error, nowMs) {
    error = error || {};
    var st = (error.status || '').trim();
    if (st !== 'approved' || error.apply_dispatch_ok !== true) return false;
    var ref = _parseIsoMs(error.apply_dispatch_at);
    if (ref === null) ref = _parseIsoMs(error.approved_at);
    if (ref === null) return false;
    var now = typeof nowMs === 'number' ? nowMs : Date.now();
    return now - ref >= APPLY_WAIT_RETRY_MS;
  }
  function isPatchFullyVerified(error) {
    return (error.status || '').trim() === 'fixed';
  }
  function shouldHideApplyRetryActions(error) {
    error = error || {};
    if (isPatchFullyVerified(error)) return true;
    var st = (error.status || '').trim();
    var hasApplyEvidence = Boolean(error.executed_at) && Boolean(String(error.backup_path || '').trim());
    if (!hasApplyEvidence) return false;
    return st === 'failed' || st === 'approved' || st === 'applying';
  }
  var DELETE_BLOCKED_APPLY_WORKFLOW_STATUSES = {
    applying: true,
    rolling_back: true,
    rolled_back: true,
    rollback_failed: true
  };
  function canDeleteError(error) {
    error = error || {};
    var st = (error.status || '').trim();
    if (st === 'fixed') return false;
    if (error.executed_at) return false;
    if (DELETE_BLOCKED_APPLY_WORKFLOW_STATUSES[st]) return false;
    return true;
  }
  function errorDeleteBlockedReason(error) {
    error = error || {};
    var st = (error.status || '').trim();
    if (st === 'fixed') {
      return 'Cannot delete a successfully patched error. Use Hide Error & Ignore instead.';
    }
    if (error.executed_at) {
      return 'Cannot delete an error after a patch apply attempt. Use Hide Error & Ignore instead.';
    }
    if (DELETE_BLOCKED_APPLY_WORKFLOW_STATUSES[st]) {
      return 'Cannot delete while apply or rollback is in progress.';
    }
    return null;
  }
  var MARK_FIXED_MANUAL_STATUSES = {
    analyzed: true,
    awaiting_approval: true,
    manual_review_required: true,
    approved: true,
    applying: true,
    failed: true,
    rolled_back: true,
    rollback_failed: true
  };
  function canMarkFixedManually(error) {
    error = error || {};
    var st = (error.status || '').trim();
    if (!MARK_FIXED_MANUAL_STATUSES[st]) return false;
    return !isPatchFullyVerified(error);
  }
  function showWaitingForConnector(error) {
    error = error || {};
    var st = (error.status || '').trim();
    if (st !== 'approved') return false;
    if (shouldHideApplyRetryActions(error)) return false;
    if (canRetryApply(error)) return false;
    return true;
  }
  function canRetryApply(error) {
    error = error || {};
    if (shouldHideApplyRetryActions(error)) return false;
    var st = (error.status || '').trim();
    if (st === 'approved') {
      return isApplyDispatchFailed(error) || isApplyStalled(error) || isApplyWaitingTooLong(error);
    }
    if (st === 'failed') {
      return errorMayHaveAnalysisRecord(st)
        && Boolean((error.fix_path || '').trim() || error.approved_at);
    }
    return false;
  }
  /** Rollback only when a pre-apply backup exists (patch was actually applied). */
  function canRollbackFix(error) {
    error = error || {};
    var st = (error.status || '').trim();
    var hasBackup = Boolean(String(error.backup_path || '').trim());
    if (!hasBackup) {
      return false;
    }
    return st === 'fixed' || st === 'failed' || st === 'rollback_failed';
  }
  function retryApplyActionTitle(error) {
    if (isApplyDispatchFailed(error)) {
      var err = String(error.apply_dispatch_error || '').trim();
      var base = err ? ('Retry Patch — ' + err) : 'Retry Patch — dispatch failed';
      var cacheHint = localCacheApplyFallbackHint(error);
      return cacheHint ? (base + '. ' + cacheHint) : base;
    }
    if (isApplyStalled(error)) {
      return 'Retry Patch — apply stalled waiting for connector';
    }
    if (isApplyWaitingTooLong(error)) {
      return 'Retry Patch — connector has not applied yet';
    }
    return 'Retry Patch';
  }
  function formatApproveDispatchFeedback(error) {
    error = error || {};
    if (error.apply_dispatch_ok === false) {
      var cacheHint = localCacheApplyFallbackHint(error);
      if (cacheHint) {
        return {
          level: 'info',
          message: 'Patch approved! ' + formatApplyDispatchFailureMessage(error)
        };
      }
      var dispatchErr = String(error.apply_dispatch_error || '').trim();
      var base = dispatchErr
        ? ('Patch approved, but we could not apply automatically: ' + dispatchErr)
        : 'Patch approved, but we could not apply automatically — use Retry Patch.';
      return { level: 'warning', message: base };
    }
    if (error.apply_dispatch_ok === true) {
      var channel = String(error.apply_dispatch_channel || '').trim();
      if (channel === 'rescue') {
        return { level: 'success', message: 'Patch approved — apply dispatched via rescue.' };
      }
      if (channel === 'agent_poll') {
        return {
          level: 'success',
          message: 'Patch approved — the connector will apply on its next poll.'
        };
      }
      return { level: 'success', message: 'Patch approved — apply dispatched.' };
    }
    return { level: 'success', message: 'Patch approved.' };
  }

  global.PatcherlyFormat = {
    formatStatusLabel: formatStatusLabel,
    formatStatusTooltip: formatStatusTooltip,
    statusBadgeKind: statusBadgeKind,
    statusBadgeHtml: statusBadgeHtml,
    resolveApprovedApplyPhase: resolveApprovedApplyPhase,
    isInFlightErrorStatus: isInFlightErrorStatus,
    hasInFlightError: hasInFlightError,
    needsActivePolling: needsActivePolling,
    APPLY_WAIT_RETRY_MS: APPLY_WAIT_RETRY_MS,
    isApplyWaitingTooLong: isApplyWaitingTooLong,
    canRetryApply: canRetryApply,
    canMarkFixedManually: canMarkFixedManually,
    showWaitingForConnector: showWaitingForConnector,
    shouldHideApplyRetryActions: shouldHideApplyRetryActions,
    isPatchFullyVerified: isPatchFullyVerified,
    canDeleteError: canDeleteError,
    errorDeleteBlockedReason: errorDeleteBlockedReason,
    canRollbackFix: canRollbackFix,
    retryApplyActionTitle: retryApplyActionTitle,
    formatApproveDispatchFeedback: formatApproveDispatchFeedback,
    localCacheApplyFallbackHint: localCacheApplyFallbackHint,
    localCacheStatusRefreshHint: function () { return LOCAL_CACHE_STATUS_REFRESH_HINT; },
    formatApplyDispatchFailureMessage: formatApplyDispatchFailureMessage,
    edgeRescueNoticeForError: edgeRescueNoticeForError,
    edgeRescueNoticeFromErrors: edgeRescueNoticeFromErrors,
    EDGE_RESCUE_TOAST_DURATION_MS: EDGE_RESCUE_TOAST_DURATION_MS,
    isEdgeRescueDispatchError: isEdgeRescueDispatchError,
    errorMayHaveAnalysisRecord: errorMayHaveAnalysisRecord,
    errorHasAnalysisArtifact: errorHasAnalysisArtifact,
    canShowFixPreviewForError: canShowFixPreviewForError,
    canShowFixPreviewAction: canShowFixPreviewAction,
    canShowRejectPatchAction: canShowRejectPatchAction,
    canShowApproveFixAction: canShowApproveFixAction,
    isNotPatchableError: isNotPatchableError,
    canShowReAnalyzeAction: canShowReAnalyzeAction,
    reAnalyzeActionTitle: reAnalyzeActionTitle,
    canShowIgnoreAction: canShowIgnoreAction,
    getRejectPatchActionLabel: getRejectPatchActionLabel,
    isPatchReadyStatus: isPatchReadyStatus,
    analysisRetryingBadgeLabel: analysisRetryingBadgeLabel,
    notPatchableBadgeHtml: notPatchableBadgeHtml,
    errorPreviewText: errorPreviewText,
    errorFullText: errorFullText,
    severityBadgeHtml: severityBadgeHtml,
    iconHtml: iconHtml,
    iconButtonHtml: iconButtonHtml,
    waitingIcon: waitingIcon,
    actionsLegendHtml: actionsLegendHtml,
    mountActionsLegend: mountActionsLegend,
    statusLegendHtml: statusLegendHtml,
    mountStatusLegend: mountStatusLegend,
    formatDateTimeIso: formatDateTimeIso,
    normalizeConfidence: normalizeConfidence,
    formatConfidencePercent: formatConfidencePercent,
    confidenceTone: confidenceTone,
    DEFAULT_FIX_MIN_CONFIDENCE: DEFAULT_FIX_MIN_CONFIDENCE,
    STATUS_LABELS: STATUS_LABELS,
    STATUS_TOOLTIPS: STATUS_TOOLTIPS,
    STATUS_KIND: STATUS_KIND
  };
})(window);
