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
    pending_analysis:        'Queued for AI analysis — Patcherly will analyse this shortly.',
    analysis_failed:         "The AI couldn't analyse this one after automatic retries — click Retry analysis to try again.",
    analyzed:                'A draft fix is ready — preview it before you accept.',
    awaiting_approval:       'A draft fix is ready — review it, then click Approve fix in the row actions to apply.',
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
    pending_analysis:        'ai',
    analysis_failed:         'err',
    analyzed:                'ai',
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

  // Approved-row sub-states (mirror dashboard-next/lib/errorStatus.ts).
  var APPROVED_PHASE_LABELS = {
    waiting:         'Waiting for connector',
    dispatch_failed: 'Dispatch failed',
    stalled:         'Apply stalled'
  };
  var APPROVED_PHASE_TOOLTIPS = {
    waiting:         'Fix approved — waiting for the connector to fetch and apply it.',
    dispatch_failed: 'Apply dispatch failed — use Retry apply to try again.',
    stalled:         'Apply stalled — rescue ping failed or the connector is unreachable. Use Retry apply.'
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

  function dispatchFieldsFrom(item) {
    if (!item || typeof item !== 'object') return null;
    if (item.apply_dispatch_ok !== undefined || item.apply_dispatch_ok === null
      || item.apply_stalled_at || item.apply_dispatch_error || item.apply_dispatch_channel
      || item.fix_cached_on_connector || item.target_edge_rescue_blocked) {
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
  function formatStatusLabel(status, dispatch) {
    if (!status) return '—';
    if (status === 'approved' && dispatch) {
      return APPROVED_PHASE_LABELS[resolveApprovedApplyPhase(dispatch)];
    }
    return STATUS_LABELS[status] || String(status).replace(/_/g, ' ');
  }
  function formatStatusTooltip(status, dispatch) {
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
      return 'warn';
    }
    if (status === 'pending_analysis' || status === 'analyzed') return 'ai';
    return STATUS_KIND[status] || 'neutral';
  }
  function statusBadgeHtml(status, itemOrDispatch) {
    var dispatch = typeof itemOrDispatch === 'string' ? null : dispatchFieldsFrom(itemOrDispatch);
    var label = formatStatusLabel(status, dispatch);
    var kind  = statusBadgeKind(status, dispatch);
    var tip   = formatStatusTooltip(status, dispatch);
    // `title` drives the OS-native tooltip on hover; aria-label keeps
    // screen readers in lockstep so the explanation isn't visual-only.
    var attrs = 'class="patcherly-status-badge patcherly-status-badge--' + kind + '"';
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
  var SOURCE_ATTRIBUTION = 'Patcherly Advanced Logger';
  var EMERGENCY_SOURCE_ATTRIBUTION = 'Patcherly Emergency Logger';

  function stripRescueWrapper(line) {
    return String(line || '').replace(RESCUE_FATAL_RE, '').trim();
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

  function errorFullText(item) {
    item = item || {};
    var message = String(item.message || '').trim();
    var logLine = String(item.log_line || '').trim();
    var traceback = String(item.traceback || '').trim();
    var blocks = [];
    if (message) blocks.push(message);
    if (logLine && logLine !== message) blocks.push(logLine);
    if (traceback && traceback !== logLine && traceback !== message) {
      var body = blocks.join('\n\n');
      if (!body || body.indexOf(traceback) === -1) blocks.push(traceback);
    }
    var full = blocks.join('\n\n');
    var attribution = sourceAttributionForError(item, logLine);
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
  //   - variant: one of info|ai|accent|success|warning|danger|muted|neutral
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
  var ACTION_LEGEND = [
    {
      key: 'analyze', icon: 'brain', variant: 'ai', label: 'Analyze with AI',
      description: 'Start AI analysis on a pending error, or retry after a failed or scheduled attempt.'
    },
    {
      key: 'retry_analysis', icon: 'brain', variant: 'ai', label: 'Retry analysis',
      description: 'Re-queue AI analysis after automatic retries were exhausted.'
    },
    {
      key: 'preview_fix', icon: 'eye', variant: 'ai', label: 'Preview fix',
      description: 'View the AI-suggested code change after analysis — including approved, applying, fixed, and failed rows.'
    },
    {
      key: 'approve_fix', icon: 'shieldCheck', variant: 'success', label: 'Approve fix',
      description: 'Approve the AI suggestion; Patcherly dispatches apply via rescue or the connector poll.'
    },
    {
      key: 'close_error', icon: 'x', variant: 'danger', label: 'Close error',
      description: 'Stop work on a pending or pre-fix error without analyzing or applying a patch.'
    },
    {
      key: 'reject_patch_close', icon: 'x', variant: 'danger', label: 'Reject patch and close error',
      description: 'Reject the AI-suggested fix and close the error; restore later if you change your mind.'
    },
    {
      key: 'retry_apply', icon: 'shield', variant: 'success', label: 'Retry apply',
      description: 'Re-dispatch apply when dispatch failed, apply stalled, or a prior apply attempt failed.'
    },
    {
      key: 'waiting_for_connector', icon: 'clock', variant: 'warning', label: 'Waiting for connector',
      description: 'Fix is approved; waiting for the connector to fetch and apply the patch.'
    },
    {
      key: 'mark_fixed', icon: 'check', variant: 'success', label: 'Mark as manually fixed',
      description: 'Confirm the error is resolved manually without another apply attempt.'
    },
    {
      key: 'rollback_fix', icon: 'rotateCcw', variant: 'danger', label: 'Rollback fix',
      description: 'Restore affected files from the connector\u2019s pre-apply backup on this server.'
    },
    {
      key: 'restore_queue', icon: 'check', variant: 'success', label: 'Restore to queue',
      description: 'Bring a dismissed or rolled-back error back into the active list.'
    },
    {
      key: 'ignore', icon: 'x', variant: 'muted', label: 'Hide Error & Ignore', errorsOnly: true,
      description: 'Hide from the default view without deleting the error record.'
    },
    {
      key: 'unignore', icon: 'x', variant: 'success', label: 'Unignore', errorsOnly: true,
      description: 'Return an ignored error to the active list (shown when viewing ignored errors only).'
    },
    {
      key: 'delete', icon: 'trash', variant: 'danger', label: 'Delete',
      description: 'Remove from Patcherly; does not undo patches already applied on your site.'
    },
    {
      key: 'in_progress', icon: 'loader', variant: 'accent', label: 'In progress', busy: true,
      description: 'Analysis, apply, or rollback is running on this row.'
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
    return '<span class="patcherly-icon-btn patcherly-icon-btn--warning patcherly-icon-btn--static" title="' + escHtml(title) + '" aria-label="' + escHtml(title) + '">' + iconHtml('clock') + '</span>';
  }

  function actionsLegendHtml(opts) {
    opts = opts || {};
    var includeIgnore = opts.includeIgnore !== false;
    var html = '';
    ACTION_LEGEND.forEach(function (item) {
      if (item.errorsOnly && !includeIgnore) return;
      var copy = legendCopy(item);
      var btnCls = 'patcherly-icon-btn patcherly-icon-btn--' + item.variant
        + (item.busy ? ' is-busy' : '');
      html += '<span class="patcherly-actions-legend__item">'
        + '<span class="' + btnCls + '" aria-hidden="true">' + iconHtml(item.icon) + '</span>'
        + '<span class="patcherly-actions-legend__text">'
        + '<span class="patcherly-actions-legend__label">' + escHtml(copy.label) + '</span>';
      if (copy.description) {
        html += '<span class="patcherly-actions-legend__desc">' + escHtml(copy.description) + '</span>';
      }
      html += '</span></span>';
    });
    return html;
  }

  function mountActionsLegend(containerId, opts) {
    var el = typeof containerId === 'string' ? document.getElementById(containerId) : containerId;
    if (!el) return;
    el.innerHTML = actionsLegendHtml(opts || {});
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
    return st === 'analyzed' || st === 'awaiting_approval' || st === 'manual_review_required';
  }
  var DISMISSABLE_ERROR_STATUSES = {
    pending: true,
    pending_analysis: true,
    analysis_failed: true,
    analyzed: true,
    awaiting_approval: true,
    manual_review_required: true,
    manual: true
  };
  function canShowDismissAction(status) {
    var st = (status || '').trim();
    if (!st || st === 'excluded') return false;
    return Boolean(DISMISSABLE_ERROR_STATUSES[st]);
  }
  function getDismissActionLabel(status) {
    return isPatchReadyStatus(status)
      ? 'Reject patch and close error'
      : 'Close error';
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
    return 'Your website security (Cloudflare) blocked Patcherly from applying the fix automatically.';
  }
  function formatApplyDispatchFailureMessage(error) {
    error = error || {};
    var hint = localCacheApplyFallbackHint(error);
    if (hint) {
      return edgeRescueBlockedSummary() + ' ' + hint;
    }
    var err = String(error.apply_dispatch_error || '').trim();
    return err || 'We could not reach your site to apply the fix. Try Retry apply or check that your connector is running.';
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
  function localCacheApplyFallbackHint(error) {
    error = error || {};
    if (!isApplyDispatchFailed(error)) return null;
    if (!isWordpressRescueDispatchFailure(error)) return null;
    if (!isEdgeRescueDispatchError(error) && !error.fix_cached_on_connector) return null;
    if (error.fix_cached_on_connector) {
      return 'Click Retry apply to apply the fix saved on this site.';
    }
    return 'Click Retry apply — the connector will fetch the fix from Patcherly and apply it on this site automatically.';
  }
  function isApplyStalled(error) {
    return (error.status || '').trim() === 'approved' && Boolean(error.apply_stalled_at);
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
    rollback_failed: true,
    restored: true
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
    restored: true,
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
      return isApplyDispatchFailed(error) || isApplyStalled(error);
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
      var base = err ? ('Retry apply — ' + err) : 'Retry apply — dispatch failed';
      var cacheHint = localCacheApplyFallbackHint(error);
      return cacheHint ? (base + '. ' + cacheHint) : base;
    }
    if (isApplyStalled(error)) {
      return 'Retry apply — apply stalled waiting for connector';
    }
    return 'Retry apply';
  }
  function formatApproveDispatchFeedback(error) {
    error = error || {};
    if (error.apply_dispatch_ok === false) {
      var cacheHint = localCacheApplyFallbackHint(error);
      if (cacheHint) {
        return {
          level: 'info',
          message: 'Fix approved! ' + formatApplyDispatchFailureMessage(error)
        };
      }
      var dispatchErr = String(error.apply_dispatch_error || '').trim();
      var base = dispatchErr
        ? ('Fix approved, but we could not apply automatically: ' + dispatchErr)
        : 'Fix approved, but we could not apply automatically — use Retry apply.';
      return { level: 'warning', message: base };
    }
    if (error.apply_dispatch_ok === true) {
      var channel = String(error.apply_dispatch_channel || '').trim();
      if (channel === 'rescue') {
        return { level: 'success', message: 'Fix approved — apply dispatched via rescue.' };
      }
      if (channel === 'agent_poll') {
        return {
          level: 'success',
          message: 'Fix approved — the connector will apply on its next poll.'
        };
      }
      return { level: 'success', message: 'Fix approved — apply dispatched.' };
    }
    return { level: 'success', message: 'Fix approved.' };
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
    formatApplyDispatchFailureMessage: formatApplyDispatchFailureMessage,
    edgeRescueNoticeForError: edgeRescueNoticeForError,
    edgeRescueNoticeFromErrors: edgeRescueNoticeFromErrors,
    EDGE_RESCUE_TOAST_DURATION_MS: EDGE_RESCUE_TOAST_DURATION_MS,
    isEdgeRescueDispatchError: isEdgeRescueDispatchError,
    errorMayHaveAnalysisRecord: errorMayHaveAnalysisRecord,
    canShowFixPreviewAction: canShowFixPreviewAction,
    canShowDismissAction: canShowDismissAction,
    getDismissActionLabel: getDismissActionLabel,
    isPatchReadyStatus: isPatchReadyStatus,
    errorPreviewText: errorPreviewText,
    errorFullText: errorFullText,
    severityBadgeHtml: severityBadgeHtml,
    iconHtml: iconHtml,
    iconButtonHtml: iconButtonHtml,
    waitingIcon: waitingIcon,
    actionsLegendHtml: actionsLegendHtml,
    mountActionsLegend: mountActionsLegend,
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
