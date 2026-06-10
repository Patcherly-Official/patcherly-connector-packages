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

  var wrap = document.querySelector('[data-patcherly-demo]');
  if (!wrap) { return; }
  var dataUrl = wrap.getAttribute('data-demo-data-url') || '';

  function $(id) { return document.getElementById(id); }
  function esc(s) {
    if (s == null) return '';
    return ('' + s).replace(/[&<>"']/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]);
    });
  }
  function fmtDate(iso) {
    try { var d = new Date(iso); if (!isNaN(d)) return d.toLocaleString(); } catch (_) {}
    return iso || '';
  }
  function t(key, fallback) { return Object.prototype.hasOwnProperty.call(i18n, key) ? i18n[key] : fallback; }
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
    var label = String(sev || 'info');
    var cls = 'patcherly-badge';
    if (label === 'critical' || label === 'error') cls += ' danger';
    else if (label === 'warning') cls += ' warn';
    else if (label === 'info') cls += ' success';
    var aria = t('severity_' + label, label);
    return '<span class="' + cls + '" aria-label="' + esc(aria) + '">' + esc(label) + '</span>';
  }
  function statusPill(status) {
    var cls = 'patcherly-demo-pill is-' + esc(status || 'pending');
    return '<span class="' + cls + '">' + esc(status || 'pending') + '</span>';
  }
  // Action affordances mirror the REAL Errors page (see
  // assets/js/patcherly-errors.js around line 85): Approve + Dismiss only
  // appear on `awaiting_approval` rows — the single human decision point
  // where the AI has analyzed the error and drafted a fix that needs
  // explicit human approval before being applied. Pending and analyzed
  // rows have NO action buttons because in the real product Patcherly
  // auto-advances them as the AI analyzes the error and drafts a fix.
  // Rollback shows on `fixed` rows. Delete shows on every row.
  function rowActions(e) {
    var html = '<div class="patcherly-demo-actions">';
    if (e.status === 'awaiting_approval') {
      html += '<button class="button button-small button-primary" data-act="approve">' + esc(t('btn_approve', 'Approve & apply fix')) + '</button>';
      html += ' <button class="button button-small" data-act="dismiss">' + esc(t('btn_dismiss', 'Dismiss')) + '</button>';
    }
    if (e.status === 'fixed') {
      html += '<button class="button button-small" data-act="rollback">' + esc(t('btn_rollback', 'Rollback')) + '</button>';
    }
    html += ' <button class="button button-link patcherly-demo-del" data-act="delete">' + esc(t('btn_delete', 'Delete')) + '</button>';
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
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666">' + esc(t('noResults', 'No errors')) + '</td></tr>';
      return;
    }
    var html = '';
    rows.forEach(function (e) {
      html += '<tr data-id="' + esc(e.id) + '">';
      html += '<td><input type="checkbox" class="patcherly-demo-row-cb" /></td>';
      html += '<td>' + esc(fmtDate(e.created_at)) + '</td>';
      html += '<td>' + severityBadge(e.severity) + '</td>';
      html += '<td>' + statusPill(e.status) + '</td>';
      html += '<td>' + esc(e.language || '') + '</td>';
      html += '<td style="white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:540px" title="' + esc(e.log_line || '') + '">' + esc(e.log_line || '') + '</td>';
      html += '<td>' + rowActions(e) + '</td>';
      html += '</tr>';
    });
    tbody.innerHTML = html;
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
    var nxt = nextStatus(e.status, action);
    if (!nxt) return;
    e.status = nxt;
    saveState(current);
    render();
    if (action === 'approve')      toast(t('toast_fix_applied', 'AI-drafted fix applied (mock).'));
    else if (action === 'dismiss') toast(t('toast_dismissed', 'Error dismissed (mock).'));
    else if (action === 'rollback') toast(t('toast_rolled_back', 'Restored from backup (mock).'));
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
    { selector: '[data-tour="severity"]', title: 'Severity', body: 'Errors are colour-coded so the loudest fires are immediately visible — critical and error first, then warnings, then informational notices.' },
    { selector: '[data-tour="status"]', title: 'Status', body: 'Each error walks through a lifecycle: pending → analyzed → awaiting approval → fixed (or dismissed). The pill tells you exactly where every error is right now.' },
    { selector: '[data-tour="actions"]', title: 'Actions', body: 'Patcherly auto-analyzes every pending error and asks the AI to draft a fix — so Approve & Dismiss only appear once a row reaches "awaiting approval", the one moment a human decision is actually needed. Approve applies the AI-drafted patch to your code (with a pre-apply backup); Dismiss marks the error as ignored; Rollback restores that backup on already-fixed rows; Delete removes the row from the Patcherly dashboard only (see the next step for the full story). In the real plugin these talk to the Patcherly API; here they only mutate this tab.' },
    { selector: '[data-tour="bulk"]', title: 'Bulk delete', body: 'Tick the boxes and click "Delete selected" to clear resolved or noisy rows in one pass. Important: in the real Patcherly product Delete is dashboard-only — a hard delete of the row (no trash, no undo) recorded in your audit trail. Platform-wide error metrics (success rates, time saved, AI confidence trends across all Patcherly users) are always preserved in fully anonymized form — no tenant ID, no error ID, no PII — so your decision to delete never silently shrinks the cross-customer learnings. Delete does NOT roll back a patch already applied to your site (use Rollback for that), does NOT refund a fix to your monthly quota, and does NOT touch the pre-apply backups Patcherly keeps on your own server.' },
    { selector: '[data-tour="filter-status"]', title: 'Filters', body: 'Filter by status, severity, or language to focus on what matters right now. Useful when you have hundreds of errors and only want to see the unresolved critical ones.' },
    { selector: '[data-tour="filter-severity"]', title: 'Severity filter', body: 'Want only the critical fires? Pick a severity and the table updates live — no page refresh needed.' },
    {
      selector: null,
      title: 'This is a simplified view',
      body: 'This Errors page is a focused, single-site view of your Patcherly account. The full dashboard at app.patcherly.com adds: cross-site monitoring, per-fix AI confidence, custom auto-apply policies, team approvals, audit logs, billing, and rollback history. Connect this site from the Settings page to start receiving real errors here — and see everything else in your dashboard.'
    }
  ];
  var tourIdx = -1;
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
    // Always clear prior highlight before deciding what to do this step.
    document.querySelectorAll('.patcherly-demo-tour-highlight').forEach(function (n) {
      n.classList.remove('patcherly-demo-tour-highlight');
    });
    var target = step.selector ? document.querySelector(step.selector) : null;
    // For anchored steps whose selector matched nothing (e.g. a layout
    // changed), skip silently rather than dead-ending the tour.
    if (step.selector && !target) { tourIdx++; showTourStep(); return; }
    overlay.hidden = false;
    overlay.querySelector('.patcherly-demo-tour__title').textContent = step.title;
    overlay.querySelector('.patcherly-demo-tour__body').textContent = step.body;
    if (!target) {
      // Centered modal — no anchor, no highlight. Width is set in CSS via
      // the .is-centered modifier so we don't override it inline.
      bubble.classList.add('is-centered');
      bubble.style.top = '';
      bubble.style.left = '';
      try { window.scrollTo({ top: 0, behavior: 'smooth' }); } catch (_) {}
      return;
    }
    bubble.classList.remove('is-centered');
    target.classList.add('patcherly-demo-tour-highlight');
    var rect = target.getBoundingClientRect();
    var top = Math.max(20, window.scrollY + rect.bottom + 12);
    var left = Math.min(Math.max(20, window.scrollX + rect.left), window.scrollX + window.innerWidth - 360);
    bubble.style.top = top + 'px';
    bubble.style.left = left + 'px';
    try { target.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (_) {}
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
      if (!act) return;
      if (act === 'next') { tourIdx++; showTourStep(); }
      else if (act === 'back') { tourIdx = Math.max(0, tourIdx - 1); showTourStep(); }
      else if (act === 'skip') { closeTour(true); }
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
