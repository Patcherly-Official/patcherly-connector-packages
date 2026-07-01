/**
 * Patcherly Demo Mode — front-end controller.
 *
 * Strict contract (locked by tests/test-demo-self-contained.php):
 *   - NO `wp_remote_*` (PHP side) — this file is JS-only anyway.
 *   - NO `fetch(ajaxurl)` / `admin-ajax.php` calls.
 *   - NO `localStorage` (sessionStorage only — per-tab).
 *   - The ONLY network call is `fetch(cfg.dataUrl)` against the bundled
 *     `demo/demo_data.json` URL, which is a local plugin asset.
 *
 * If you change this file, re-run `php tests/test-demo-self-contained.php`
 * before committing.
 */
(function () {
  var i18n = window.PATCHERLY_DEMO_I18N || {};
  var STATE_KEY = 'patcherly_demo_state_v1';
  var TOUR_SEEN_KEY = 'patcherly_demo_tour_seen_v1';
  // sessionStorage only — localStorage forbidden by tests/test-demo-self-contained.php.
  var COLS_KEY = 'patcherly_demo_columns_v1';

  var wrap = document.querySelector('[data-patcherly-demo]');
  if (!wrap) { return; }
  var dataUrl = wrap.getAttribute('data-demo-data-url') || '';

  // Column visibility — mirrors the real Errors page; Language hidden by default.
  var COLUMNS = [
    { id: 'created',  label: 'Detected',  required: false },
    { id: 'severity', label: 'Severity',  required: false },
    { id: 'status',   label: 'Status',    required: false },
    { id: 'language', label: 'Language',  required: false },
    { id: 'message',  label: 'Error',     required: false },
    { id: 'actions',  label: 'Actions',   required: true  }
  ];
  var COLS_DEFAULT_VISIBLE = ['created', 'severity', 'status', 'message', 'actions'];
  function loadVisibleCols() {
    try {
      var raw = window.sessionStorage.getItem(COLS_KEY);
      if (raw) {
        var arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          if (arr.indexOf('actions') === -1) arr.push('actions');
          return arr;
        }
      }
    } catch (_) {}
    return COLS_DEFAULT_VISIBLE.slice();
  }
  function saveVisibleCols(arr) {
    try { window.sessionStorage.setItem(COLS_KEY, JSON.stringify(arr)); } catch (_) {}
  }
  var visibleCols = loadVisibleCols();
  function isColVisible(id) { return visibleCols.indexOf(id) !== -1; }
  function applyColumnVisibility() {
    var nodes = document.querySelectorAll('[data-col]');
    for (var i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute('data-col');
      nodes[i].style.display = isColVisible(id) ? '' : 'none';
    }
  }

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    if (s == null) return '';
    return ('' + s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]);
    });
  }
  function fmtDate(iso) {
    var dtCfg = window.PATCHERLY_DEMO_DT || {};
    var F = window.PatcherlyFormat;
    if (F && F.formatDateTimeIso) {
      return F.formatDateTimeIso(iso, { timezone: dtCfg.timezone, locale: dtCfg.locale, hour12: dtCfg.hour12 });
    }
    try { var d = new Date(iso); if (!isNaN(d)) return d.toLocaleString(); } catch (_) {}
    return iso || '';
  }
  function errorPreviewForRow(e) {
    var F = window.PatcherlyFormat;
    if (F && F.errorPreviewText) {
      return F.errorPreviewText({
        message: e.message,
        log_line: e.log_line,
        code_language: e.code_language || e.language || '',
      });
    }
    return (e && (e.message || e.log_line)) || '';
  }

  function dashboardTourLinks() {
    var cfg = window.PATCHERLY_DEMO || {};
    var base = String(cfg.dashboardUrl || 'https://app.patcherly.com').replace(/\/$/, '');
    return {
      home: base + '/',
      errors: base + '/errors',
      audit: base + '/audit',
      billing: base + '/profile?tab=billing',
      settings: String(cfg.settingsUrl || '')
    };
  }
  function tourExternalLink(href, label) {
    if (!href) return esc(label);
    return '<a class="patcherly-demo-tour__link" href="' + esc(href) + '" target="_blank" rel="noopener noreferrer">' + esc(label) + '</a>';
  }
  function buildOutroTourBodyHtml() {
    var links = dashboardTourLinks();
    return 'This ' + tourExternalLink(links.errors, t('tour_link_errors_page', 'Errors page'))
      + ' is a focused, single-site view of your Patcherly account. The full '
      + tourExternalLink(links.home, t('tour_link_dashboard', 'dashboard'))
      + ' adds: cross-site monitoring, per-fix AI confidence, custom auto-apply policies, team approvals, '
      + tourExternalLink(links.audit, t('tour_link_audit_logs', 'audit logs'))
      + ', ' + tourExternalLink(links.billing, t('tour_link_billing', 'billing'))
      + ', and rollback history. Connect this site from the '
      + tourExternalLink(links.settings, t('tour_link_settings', 'Settings page'))
      + ' to start receiving real errors here — and see everything else in your '
      + tourExternalLink(links.home, t('tour_link_dashboard', 'dashboard')) + '.';
  }
  function renderTourBodyAndCta(bubble, step) {
    var bodyEl = bubble.querySelector('.patcherly-demo-tour__body');
    var ctaEl = bubble.querySelector('.patcherly-demo-tour__cta');
    if (!bodyEl) return;
    if (step.outro) {
      bodyEl.innerHTML = buildOutroTourBodyHtml();
      if (ctaEl) {
        var home = dashboardTourLinks().home;
        ctaEl.hidden = false;
        ctaEl.innerHTML = '<a class="patcherly-demo-tour__cta-btn" href="' + esc(home) + '" target="_blank" rel="noopener noreferrer">'
          + esc(t('tour_outro_go_dashboard', 'Go To Dashboard')) + '</a>';
      }
    } else {
      bodyEl.textContent = step.body || '';
      if (ctaEl) {
        ctaEl.hidden = true;
        ctaEl.innerHTML = '';
      }
    }
  }

  function fmt(str, args) {
    var i = 0;
    return String(str).replace(/%(\d+\$)?[sd]/g, function (token) {
      if (token.indexOf('$') !== -1) {
        var idx = parseInt(token, 10) - 1;
        return args[idx] != null ? String(args[idx]) : '';
      }
      var v = args[i++];
      return v != null ? String(v) : '';
    });
  }

  // ── Mock state machine ────────────────────────────────────────────────
  var transitions = {};
  var baseData = [];
  function loadState() {
    try {
      var raw = window.sessionStorage.getItem(STATE_KEY);
      if (raw) {
        var p = JSON.parse(raw);
        if (p && Array.isArray(p.errors)) { return p.errors; }
      }
    } catch (_) {}
    return null;
  }
  function saveState(errors) {
    try { window.sessionStorage.setItem(STATE_KEY, JSON.stringify({ errors: errors, ts: Date.now() })); } catch (_) {}
  }
  function clearState() {
    try { window.sessionStorage.removeItem(STATE_KEY); } catch (_) {}
  }

  var current = [];

  function nextStatus(status, action) {
    var rules = transitions[status] || {};
    return rules[action] || null;
  }

  // ── Render ────────────────────────────────────────────────────────────
  function severityBadge(sev) {
    if (window.PatcherlyFormat && PatcherlyFormat.severityBadgeHtml) {
      return PatcherlyFormat.severityBadgeHtml(sev);
    }
    var label = String(sev || 'Low');
    return '<span class="patcherly-badge">' + esc(label) + '</span>';
  }
  // Shared PatcherlyFormat helper so demo labels match the real Errors page.
  function statusPill(status) {
    if (window.PatcherlyFormat && PatcherlyFormat.statusBadgeHtml) {
      return PatcherlyFormat.statusBadgeHtml(status);
    }
    var cls = 'patcherly-demo-pill is-' + esc(status || 'pending');
    return '<span class="' + cls + '">' + esc(status || 'pending') + '</span>';
  }
  // Row actions use the shared PatcherlyFormat.iconButtonHtml helper for visual parity.
  function iconBtn(opts) {
    if (window.PatcherlyFormat && PatcherlyFormat.iconButtonHtml) {
      return PatcherlyFormat.iconButtonHtml(opts);
    }
    return '<button type="button" class="button button-small" data-act="' + esc(opts.act) + '" title="' + esc(opts.title) + '">' + esc(opts.title) + '</button>';
  }
  function busyIcon(title) {
    if (window.PatcherlyFormat && PatcherlyFormat.iconButtonHtml) {
      return PatcherlyFormat.iconButtonHtml({ busy: true, title: title, variant: 'accent' });
    }
    return '<span class="patcherly-row-busy" aria-label="' + esc(title) + '">…</span>';
  }
  function rowActions(e) {
    var st = e.status || '';
    var html = '<div class="patcherly-row-actions__buttons">';
    if (st === 'pending_analysis')      html += busyIcon('Analyzing…');
    else if (st === 'applying')         html += busyIcon('Applying…');
    else if (st === 'rolling_back')     html += busyIcon('Rolling back…');
    if (st === 'pending') {
      html += iconBtn({ act: 'analyze', title: 'Approve for Analysis', icon: 'check', variant: 'success' });
    } else if (st === 'analysis_failed') {
      html += iconBtn({ act: 'analyze', title: 'Approve for Analysis', icon: 'check', variant: 'success' });
    }
    if (st === 'analyzed' || st === 'awaiting_approval' || st === 'manual_review_required' || st === 'approved') {
      html += iconBtn({ act: 'preview', title: 'Preview fix', icon: 'eye', variant: 'neutral' });
    }
    if (st === 'analyzed') {
      html += iconBtn({ act: 'accept',  title: 'Accept fix', icon: 'check', variant: 'success' });
      html += iconBtn({ act: 'dismiss', title: 'Dismiss',    icon: 'x',     variant: 'warning' });
    }
    if (st === 'awaiting_approval' || st === 'manual_review_required') {
      html += iconBtn({ act: 'approve', title: st === 'manual_review_required' ? 'Approve after review' : 'Approve fix', icon: 'check', variant: 'success' });
    }
    if (st === 'approved') {
      html += iconBtn({ act: 'apply', title: 'Apply fix', icon: 'check', variant: 'success' });
    }
    if (st === 'fixed' || st === 'failed' || st === 'rollback_failed') {
      html += iconBtn({ act: 'rollback', title: 'Rollback fix', icon: 'rotateCcw', variant: 'warning' });
    }
    if (st === 'ignored' || st === 'rolled_back' || st === 'restored' || st === 'dismissed') {
      html += iconBtn({ act: 'restore', title: 'Restore', icon: 'refreshCw', variant: 'info' });
    }
    html += iconBtn({ act: 'delete', title: 'Delete', icon: 'trash', variant: 'danger' });
    html += '</div>';
    return html;
  }
  function applyFilters(rows) {
    var s = $('patcherly-demo-flt-status').value || '';
    var sev = $('patcherly-demo-flt-sev').value || '';
    var lang = ($('patcherly-demo-flt-lang').value || '').trim().toLowerCase();
    return rows.filter(function (e) {
      if (s && e.status !== s) return false;
      if (sev && e.severity !== sev) return false;
      if (lang && String(e.language || '').toLowerCase().indexOf(lang) === -1) return false;
      return true;
    });
  }
  function render() {
    var tbody = $('patcherly-demo-tbody');
    if (!tbody) return;
    var rows = applyFilters(current);
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="99" style="text-align:center;color:#666">' + esc(t('noResults', 'No errors')) + '</td></tr>';
      applyColumnVisibility();
      return;
    }
    var html = '';
    rows.forEach(function (e) {
      html += '<tr data-id="' + esc(e.id) + '">';
      html += '<td class="patcherly-col-cb patcherly-errors-table__cb"><input type="checkbox" class="patcherly-demo-row-cb patcherly-row-cb" aria-label="' + esc(t('selectRow', 'Select row')) + '" /></td>';
      html += '<td data-col="created">' + esc(fmtDate(e.created_at)) + '</td>';
      html += '<td data-col="severity">' + severityBadge(e.severity) + '</td>';
      html += '<td data-col="status">' + statusPill(e.status) + '</td>';
      html += '<td data-col="language">' + esc(e.language || '') + '</td>';
      html += '<td data-col="message" class="patcherly-msg-cell patcherly-errors-msg-cell" title="' + esc(e.log_line || '') + '">' + esc(errorPreviewForRow(e) || '') + '</td>';
      html += '<td data-col="actions" class="patcherly-row-actions">' + rowActions(e) + '</td>';
      html += '</tr>';
    });
    tbody.innerHTML = html;
    applyColumnVisibility();
  }

  function toast(message) {
    var el = $('patcherly-demo-toast');
    if (!el) return;
    el.textContent = message;
    el.hidden = false;
    el.classList.add('is-visible');
    clearTimeout(toast._t);
    toast._t = setTimeout(function () {
      el.classList.remove('is-visible');
      setTimeout(function () { el.hidden = true; }, 350);
    }, 2400);
  }

  // ── Actions (all in-memory) ──────────────────────────────────────────
  // Toast copy is action-specific (not just "Status: %s") so the demo
  // narrates what each click actually accomplished — matches what the
  // real Patcherly product would tell the operator after the API call
  // succeeds. Sourced from PATCHERLY_DEMO_I18N (demo.php) so all copy
  // remains translatable through WordPress's i18n.
  // "preview" is read-only; the rest walk the lifecycle from demo_data.json.
  // Each verb produces a status-aware toast that narrates what the real API would do.
  var TOASTS = {
    analyze:  ['toast_analyzing',   'AI analysis started (mock).'],
    accept:   ['toast_accepted',    'Fix accepted — ready for Approve fix (mock).'],
    approve:  ['toast_applying',    'Applying the AI-drafted fix (mock).'],
    apply:    ['toast_applying',    'Applying the AI-drafted fix (mock).'],
    dismiss:  ['toast_dismissed',   'Error dismissed (mock).'],
    rollback: ['toast_rolled_back', 'Restored from backup (mock).'],
    restore:  ['toast_restored',    'Restored to active queue (mock).']
  };
  function performAction(id, action) {
    var idx = current.findIndex(function (e) { return e.id === id; });
    if (idx === -1) return;
    var e = current[idx];
    if (action === 'delete') {
      current.splice(idx, 1);
      saveState(current);
      render();
      toast(t('toast_deleted', 'Deleted (mock).'));
      return;
    }
    if (action === 'preview') {
      // Preview is read-only — open a tiny inline modal that mirrors the
      // real Errors page Preview Fix modal. The mocked diff stays
      // generic so the demo never implies we shipped a working AI fix.
      openMockPreview(e);
      return;
    }
    var nxt = nextStatus(e.status, action);
    if (!nxt) return;
    e.status = nxt;
    saveState(current);
    render();
    var tc = TOASTS[action];
    if (tc) toast(t(tc[0], tc[1]));
    // For long-running transitions (pending_analysis → analyzed,
    // applying → fixed, rolling_back → rolled_back), schedule an
    // auto-tick a couple of seconds later so the demo shows the
    // lifecycle continuing without the operator having to refresh.
    if (e.status === 'pending_analysis' || e.status === 'applying' || e.status === 'rolling_back') {
      setTimeout(function () {
        var still = current.find(function (x) { return x.id === id; });
        if (!still) return;
        var after = nextStatus(still.status, 'tick');
        if (!after) return;
        still.status = after;
        saveState(current);
        render();
        if (still.status === 'fixed') toast(t('toast_fix_applied', 'AI-drafted fix applied (mock).'));
        else if (still.status === 'rolled_back') toast(t('toast_rolled_back', 'Restored from backup (mock).'));
      }, 1800);
    }
  }

  // Lightweight inline preview-fix modal (mock). Mirrors the structure of
  // the real Errors page modal so the demo experience prepares the
  // operator for what they'll see once paired.
  function openMockPreview(e) {
    var existing = document.getElementById('patcherly-demo-fix-modal');
    if (existing) existing.remove();
    var modal = document.createElement('div');
    modal.id = 'patcherly-demo-fix-modal';
    modal.className = 'patcherly-fix-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.innerHTML = ''
      + '<div class="patcherly-fix-modal__backdrop" data-close="1"></div>'
      + '<div class="patcherly-fix-modal__panel" tabindex="-1">'
        + '<div class="patcherly-fix-modal__head">'
          + '<h3>' + esc(t('preview_title', 'Preview proposed fix (mock)')) + '</h3>'
          + '<button type="button" class="button-link" data-close="1" aria-label="Close">✕</button>'
        + '</div>'
        + '<div class="patcherly-fix-modal__body">'
          + '<p class="patcherly-fix-modal__status">' + esc(e.file || '') + (e.line ? ':' + esc(e.line) : '') + '</p>'
          + '<pre class="patcherly-fix-modal__diff">'
          + esc('--- a/' + (e.file || 'unknown.php') + '\n'
              + '+++ b/' + (e.file || 'unknown.php') + '\n'
              + '@@ ~line ' + (e.line || 0) + ' @@\n'
              + '- (illustrative — in the real product this is the live AI-drafted patch)\n'
              + '+ // The actual diff will appear here once your site is paired with Patcherly.\n')
          + '</pre>'
        + '</div>'
      + '</div>';
    document.body.appendChild(modal);
    modal.addEventListener('click', function (ev) {
      if (ev.target && ev.target.getAttribute && ev.target.getAttribute('data-close') === '1') modal.remove();
    });
    document.addEventListener('keydown', function esc(ev) {
      if (ev.key === 'Escape') {
        document.removeEventListener('keydown', esc);
        if (modal.parentNode) modal.remove();
      }
    });
  }
  function bulkDelete() {
    var ids = Array.from(document.querySelectorAll('.patcherly-demo-row-cb:checked'))
      .map(function (cb) { var row = cb.closest('tr'); return row && row.getAttribute('data-id'); })
      .filter(Boolean);
    if (!ids.length) return;
    current = current.filter(function (e) { return ids.indexOf(e.id) === -1; });
    saveState(current);
    render();
    toast(t('toast_deleted', 'Deleted (mock).'));
  }

  // ── In-house guided tour ─────────────────────────────────────────────
  // Steps with `selector: null` render as centered modals (no DOM target,
  // no highlight). Used for the intro/outro narrative cards. The intro
  // explains Patcherly in plain language for non-tech operators, the body
  // steps walk through the Errors page features, and the outro frames this
  // page as a simplified view of the full Patcherly dashboard.
  var TOUR = [
    {
      selector: null,
      title: 'Welcome to Patcherly',
      body: 'Patcherly watches your WordPress site for errors and bugs. When it spots one, our AI drafts a fix and shows you a clear before/after. You approve, and Patcherly patches your code safely — with a backup and one-click rollback. This is a safe demo: no real changes, no AI calls, no data leaves your server.'
    },
    { selector: '[data-tour="severity"]', placement: 'below', title: 'Severity', body: 'Errors use the same Low / Medium / High / Critical scale as your Patcherly dashboard — the loudest fires stand out first.' },
    { selector: '[data-tour="status"]', placement: 'below', title: 'Status', body: 'Each error moves through familiar stages: Pending → Analyzing → Analyzed → Approve fix → Applying → Fixed (or Dismissed). From Pending, use Approve for Analysis first — then Accept fix, then Approve fix before apply. Hover any status pill for details.' },
    // Per-verb explanations live in icon-button tooltips; this step narrates the top-level pattern.
    { selector: '[data-tour="actions"]', placement: 'below', title: 'Row actions', body: 'Each row has icon buttons for the actions Patcherly can take on it. They change with the error\'s state — hover any icon for what it does. In this demo they only mutate this tab; on a paired site they call the Patcherly API.' },
    { selector: '[data-tour="bulk"]', placement: 'below', title: 'Bulk delete', body: 'Tick the boxes and click "Delete selected" to clear noisy rows in one pass. Delete is dashboard-only — it never undoes a fix already applied (use Rollback) and never touches the pre-apply backups on your server.' },
    { selector: '[data-tour="filter-status"]', placement: 'below', title: 'Filters', body: 'Filter by status, severity, or language to focus on what matters right now. Useful when you have hundreds of errors and only want to see the unresolved critical ones.' },
    { selector: '[data-tour="filter-severity"]', placement: 'below', title: 'Severity filter', body: 'Want only Critical or High items? Pick a severity and the table updates live — no page refresh needed.' },
    {
      selector: null,
      title: 'This is a simplified view',
      outro: true
    }
  ];
  var tourIdx = -1;

  function positionTourBubble(target, bubble, step) {
    var margin = 20;
    var gap = 12;
    var placement = step.placement || 'auto';

    function measureAndPlace() {
      var rect = target.getBoundingClientRect();
      var bw = bubble.offsetWidth || 340;
      var bh = bubble.offsetHeight || 200;
      var vw = window.innerWidth;
      var vh = window.innerHeight;
      var top;
      var left;

      if (placement === 'below') {
        top = rect.bottom + gap;
        if (top + bh + margin > vh) {
          try {
            window.scrollBy(0, top + bh + margin - vh);
          } catch (_) {}
          rect = target.getBoundingClientRect();
          top = rect.bottom + gap;
        }
        top = Math.min(top, vh - bh - margin);
        top = Math.max(top, rect.bottom + gap);
      } else if (placement === 'above') {
        top = rect.top - bh - gap;
        top = Math.max(margin, top);
      } else {
        top = rect.bottom + gap;
        if (top + bh + margin > vh) {
          var above = rect.top - bh - gap;
          if (above >= margin) {
            top = above;
          } else {
            top = Math.max(rect.bottom + gap, margin);
            top = Math.min(top, vh - bh - margin);
          }
        }
        if (top < margin) top = margin;
      }

      // Never cover the highlighted target (table headers were overlapping on step 2).
      if (top + bh > rect.top && top < rect.bottom) {
        top = rect.bottom + gap;
      }

      left = rect.left;
      if (left + bw + margin > vw) left = vw - bw - margin;
      if (left < margin) left = margin;
      bubble.style.top = top + 'px';
      bubble.style.left = left + 'px';
    }

    try { target.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}
    requestAnimationFrame(function () {
      requestAnimationFrame(function () {
        requestAnimationFrame(measureAndPlace);
      });
    });
  }

  function startTour(force) {
    try {
      if (!force && window.sessionStorage.getItem(TOUR_SEEN_KEY)) { return; }
    } catch (_) {}
    tourIdx = 0;
    showTourStep();
  }
  function showTourStep() {
    var overlay = $('patcherly-demo-tour-overlay');
    var bubble = overlay && overlay.querySelector('.patcherly-demo-tour__bubble');
    if (!overlay || !bubble) return;
    if (tourIdx < 0 || tourIdx >= TOUR.length) { closeTour(true); return; }
    var step = TOUR[tourIdx];
    document.querySelectorAll('.patcherly-demo-tour-highlight').forEach(function (n) {
      n.classList.remove('patcherly-demo-tour-highlight');
    });
    var target = step.selector ? document.querySelector(step.selector) : null;
    if (step.selector && !target) { tourIdx++; showTourStep(); return; }
    overlay.hidden = false;
    overlay.querySelector('.patcherly-demo-tour__title').textContent = step.title;
    renderTourBodyAndCta(bubble, step);
    if (!target) {
      // Centered modal — no anchor, no highlight. Inline styles defend against leaked
      // admin CSS that could otherwise strand the bubble in the top-left corner.
      bubble.classList.add('is-centered');
      bubble.style.position = 'fixed';
      bubble.style.top = '50%';
      bubble.style.left = '50%';
      bubble.style.transform = 'translate(-50%, -50%)';
      try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch (_) {}
      return;
    }
    // Anchored bubble — measure target in VIEWPORT coords (the bubble
    // is position:fixed so window.scrollY must NOT be added) and clamp
    // inside the viewport on both axes. If there isn't room below the
    // target we flip the bubble above it; if there isn't room above
    // either, we fall back to the closest viewport edge with a 20px
    // margin so it never spills off-screen.
    bubble.classList.remove('is-centered');
    bubble.style.position = 'fixed';
    bubble.style.transform = '';
    target.classList.add('patcherly-demo-tour-highlight');
    positionTourBubble(target, bubble, step);
  }
  function closeTour(remember) {
    var overlay = $('patcherly-demo-tour-overlay');
    if (overlay) overlay.hidden = true;
    document.querySelectorAll('.patcherly-demo-tour-highlight').forEach(function (n) {
      n.classList.remove('patcherly-demo-tour-highlight');
    });
    if (remember) {
      try { window.sessionStorage.setItem(TOUR_SEEN_KEY, '1'); } catch (_) {}
      toast(t('tour_done', 'Tour finished — explore as you like.'));
    }
  }

  // ── Bootstrap ────────────────────────────────────────────────────────
  function bind() {
    document.querySelectorAll('#patcherly-demo-flt-status,#patcherly-demo-flt-sev,#patcherly-demo-flt-lang')
      .forEach(function (el) {
        el.addEventListener('input', render);
        el.addEventListener('change', render);
      });
    var resetBtn = $('patcherly-demo-reset');
    if (resetBtn) resetBtn.addEventListener('click', function () {
      clearState();
      current = JSON.parse(JSON.stringify(baseData));
      render();
      toast(t('reset', 'Demo state reset.'));
    });
    var tourBtn = $('patcherly-demo-tour');
    if (tourBtn) tourBtn.addEventListener('click', function () { startTour(true); });

    var tbody = $('patcherly-demo-tbody');
    if (tbody) tbody.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.dataset || !t.dataset.act) return;
      e.preventDefault();
      var row = t.closest('tr');
      var id = row && row.getAttribute('data-id');
      if (!id) return;
      performAction(id, t.dataset.act);
    });
    var selAll = $('patcherly-demo-cb-all');
    if (selAll) selAll.addEventListener('change', function () {
      document.querySelectorAll('.patcherly-demo-row-cb').forEach(function (cb) { cb.checked = selAll.checked; });
    });
    var bulkBtn = $('patcherly-demo-del-selected');
    if (bulkBtn) bulkBtn.addEventListener('click', function (e) { e.preventDefault(); bulkDelete(); });

    var overlay = $('patcherly-demo-tour-overlay');
    if (overlay) overlay.addEventListener('click', function (e) {
      var act = e.target && e.target.getAttribute && e.target.getAttribute('data-tour-act');
      if (act) {
        if (act === 'next') { tourIdx++; showTourStep(); }
        else if (act === 'back') { tourIdx = Math.max(0, tourIdx - 1); showTourStep(); }
        else if (act === 'skip') { closeTour(true); }
        return;
      }
      // Click outside the bubble closes the tour; closest() avoids accidental dismissals
      // from clicks inside the card. (`pointer-events: auto` on the backdrop is set in
      // the click.)
      var bubble = overlay.querySelector('.patcherly-demo-tour__bubble');
      if (bubble && e.target && bubble.contains(e.target)) return;
      closeTour(true);
    });

    // Column manager dropdown (sessionStorage only) — mirrors patcherly-errors.js.
    bindDemoColumnsMenu();
    applyColumnVisibility();

    if (window.PatcherlyFormat && PatcherlyFormat.mountActionsLegend) {
      PatcherlyFormat.mountActionsLegend('patcherly-demo-actions-legend', { includeIgnore: false });
    }
  }

  function bindDemoColumnsMenu() {
    var wrap   = document.getElementById('patcherly-demo-columns-wrap');
    var toggle = document.getElementById('patcherly-demo-columns-toggle');
    var menu   = document.getElementById('patcherly-demo-columns-menu');
    if (!wrap || !toggle || !menu) return;
    var items = '';
    COLUMNS.forEach(function (c) {
      if (c.required) return;
      var checked = isColVisible(c.id) ? ' checked' : '';
      items += '<label class="patcherly-columns-menu__item">'
        + '<input type="checkbox" data-col-toggle="' + esc(c.id) + '"' + checked + ' /> '
        + esc(c.label)
        + '</label>';
    });
    items += '<div class="patcherly-columns-menu__sep"></div>'
      + '<div class="patcherly-columns-menu__actions">'
      + '<button type="button" class="button-link" data-cols-act="all">Show all</button>'
      + '<button type="button" class="button-link" data-cols-act="reset">Reset</button>'
      + '</div>';
    menu.innerHTML = items;

    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      menu.hidden = !menu.hidden;
    });
    menu.addEventListener('change', function (e) {
      var cb = e.target;
      if (!cb || !cb.matches || !cb.matches('input[data-col-toggle]')) return;
      var id = cb.getAttribute('data-col-toggle');
      var idx = visibleCols.indexOf(id);
      if (cb.checked && idx === -1) visibleCols.push(id);
      if (!cb.checked && idx !== -1) visibleCols.splice(idx, 1);
      saveVisibleCols(visibleCols);
      applyColumnVisibility();
    });
    menu.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('[data-cols-act]') : null;
      if (!btn) return;
      var act = btn.getAttribute('data-cols-act');
      if (act === 'all') {
        visibleCols = COLUMNS.map(function (c) { return c.id; });
      } else if (act === 'reset') {
        visibleCols = COLS_DEFAULT_VISIBLE.slice();
      }
      saveVisibleCols(visibleCols);
      menu.querySelectorAll('input[data-col-toggle]').forEach(function (cb) {
        cb.checked = isColVisible(cb.getAttribute('data-col-toggle'));
      });
      applyColumnVisibility();
    });
    document.addEventListener('click', function (e) {
      if (menu.hidden) return;
      if (wrap.contains(e.target)) return;
      menu.hidden = true;
    });
  }

  function bootstrap() {
    var stored = loadState();
    fetch(dataUrl, { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (json) {
        baseData = Array.isArray(json.errors) ? json.errors : [];
        transitions = json.transitions || {};
        current = stored && stored.length ? stored : JSON.parse(JSON.stringify(baseData));
        render();
        bind();
        setTimeout(function () { startTour(false); }, 600);
      })
      .catch(function () {
        var tbody = $('patcherly-demo-tbody');
        if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#a00">Demo data failed to load.</td></tr>';
      });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', bootstrap);
  } else {
    bootstrap();
  }
})();
