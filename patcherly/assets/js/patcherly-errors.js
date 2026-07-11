(function(){
  var cfg = window.PATCHERLY_ERRORS || { url: '', ttl: 60, defaultLimit: 25, adminNonce: '', oauthConnected: true, settingsUrl: '' };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  function esc(s){ if(s==null) return ''; return (''+s).replace(/[&<>]/g, function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]);}); }
  function fmtDate(s){
    if (s == null || s === '') return '—';
    var F = window.PatcherlyFormat;
    if (F && F.formatDateTimeIso) {
      return F.formatDateTimeIso(s, {
        timezone: cfg.timezone,
        locale: cfg.locale,
        hour12: cfg.hour12,
        date_format: cfg.date_format,
        time_format: cfg.time_format
      });
    }
    try{ var d=new Date(s); if(!isNaN(d)) return d.toLocaleString(); }catch(_){ }
    return s;
  }

  // Column visibility — every column except Actions is togglable; choice persists in localStorage.
  // The Demo page uses a sibling module with sessionStorage so the demo can't touch WP state.
  // Defaults match the dashboard minus Language (hidden by default; one click in the Columns menu).
  var COLUMNS = [
    { id: 'created',  label: 'Detected',  required: false },
    { id: 'severity', label: 'Severity',  required: false },
    { id: 'status',   label: 'Status',    required: false },
    { id: 'language', label: 'Language',  required: false },
    { id: 'message',  label: 'Error',     required: false },
    { id: 'actions',  label: 'Actions',   required: true  }
  ];
  var COLUMNS_DEFAULT_VISIBLE = ['created', 'severity', 'status', 'message', 'actions'];
  var COLUMNS_KEY = 'patcherly_errors_columns_v2';
  var COLUMNS_KEY_LEGACY = 'patcherly_errors_columns_v1';
  function normalizeVisibleColumnIds(arr) {
    var known = {};
    COLUMNS.forEach(function (c) { known[c.id] = true; });
    var out = [];
    for (var i = 0; i < arr.length; i++) {
      var id = arr[i];
      // v1 stored the error-text column as `error` before we split Language vs Error.
      if (id === 'error') { id = 'message'; }
      if (known[id] && out.indexOf(id) === -1) { out.push(id); }
    }
    if (out.indexOf('actions') === -1) { out.push('actions'); }
    return out;
  }
  function loadVisible() {
    try {
      var raw = window.localStorage.getItem(COLUMNS_KEY);
      if (!raw) { raw = window.localStorage.getItem(COLUMNS_KEY_LEGACY); }
      if (raw) {
        var arr = normalizeVisibleColumnIds(JSON.parse(raw));
        if (Array.isArray(arr) && arr.length) {
          // After the Message→Error rename, stale prefs often hid the text column entirely.
          if (arr.indexOf('message') === -1) {
            var actionsIdx = arr.indexOf('actions');
            if (actionsIdx === -1) { arr.push('message'); }
            else { arr.splice(actionsIdx, 0, 'message'); }
          }
          if (!window.localStorage.getItem(COLUMNS_KEY)) { saveVisible(arr); }
          return arr;
        }
      }
    } catch (_) { /* fall through to defaults */ }
    return COLUMNS_DEFAULT_VISIBLE.slice();
  }
  function saveVisible(arr) {
    try { window.localStorage.setItem(COLUMNS_KEY, JSON.stringify(arr)); } catch (_) {}
  }
  var visibleColumns = loadVisible();
  var errorsById = {};
  var listMeta = { total: 0, offset: 0, limit: 25, pageIndex: 0 };
  var pollTimer = null;
  var actionInFlight = false;

  function copy(key, fallback) {
    return (cfg && cfg[key]) || fallback;
  }
  function apiDownMessage() {
    return copy('errApiDown', 'API is down — Retry in a few minutes.');
  }
  function isApiDownStatus(status) {
    return status === 502 || status === 503 || status === 504 || (typeof status === 'number' && status >= 500);
  }
  function isApiDownPayload(payload) {
    if (!payload || typeof payload !== 'object') return false;
    if (typeof payload.http_code === 'number' && payload.http_code >= 500) return true;
    var text = (typeof payload.error === 'string' && payload.error)
      || (typeof payload.message === 'string' && payload.message)
      || '';
    if (!text) return false;
    var lc = text.toLowerCase();
    return lc.indexOf('upstream http 5') === 0
      || lc.indexOf('api server unavailable') === 0
      || lc.indexOf('api server timeout') === 0
      || lc.indexOf('api server connection failed') === 0
      || lc.indexOf('connection failed') === 0
      || lc.indexOf('request failed') === 0;
  }
  function friendlyHttpError(status, payload) {
    if (isApiDownStatus(status) || isApiDownPayload(payload)) return apiDownMessage();
    if (payload && typeof payload.message === 'string' && payload.message) return payload.message;
    if (payload && typeof payload.error === 'string' && payload.error) return payload.error;
    return 'HTTP ' + status;
  }
  async function parseAjaxResponse(r) {
    var j = null;
    try { j = await r.json(); } catch (_) { /* non-JSON body (proxy HTML, etc.) */ }
    if (!r.ok) {
      var data = (j && typeof j === 'object' && j.data && typeof j.data === 'object') ? j.data : null;
      var err = new Error(friendlyHttpError(r.status, data));
      err.payload = data;
      err.httpStatus = r.status;
      throw err;
    }
    return j || {};
  }

  function getPageSize() {
    var el = $('patcherly-flt-limit');
    var n = parseInt((el && el.value) || String(cfg.defaultLimit || 25), 10);
    if (!n || n < 1) n = 25;
    if (n > 100) n = 100;
    return n;
  }

  function getPageCount(total, pageSize) {
    var size = Math.max(1, pageSize || 1);
    return Math.max(1, Math.ceil(Math.max(0, total) / size));
  }

  function clampPageIndex(pageIndex, total, pageSize) {
    var maxIndex = getPageCount(total, pageSize) - 1;
    if (pageIndex < 0) return 0;
    if (pageIndex > maxIndex) return maxIndex;
    return pageIndex;
  }

  function renderPagination(meta) {
    var summary = $('patcherly-pagination-summary');
    var statusEl = $('patcherly-page-status');
    var btnFirst = $('patcherly-page-first');
    var btnPrev = $('patcherly-page-prev');
    var btnNext = $('patcherly-page-next');
    var btnLast = $('patcherly-page-last');
    var total = Math.max(0, meta.total || 0);
    var pageSize = Math.max(1, meta.limit || getPageSize());
    var offset = Math.max(0, meta.offset || 0);
    var pageIndex = clampPageIndex(meta.pageIndex || 0, total, pageSize);
    var pageCount = getPageCount(total, pageSize);
    var rangeStart = total === 0 ? 0 : offset + 1;
    var rangeEnd = total === 0 ? 0 : Math.min(offset + pageSize, total);

    if (summary) {
      summary.textContent = total
        ? (rangeStart + '–' + rangeEnd + ' of ' + total + ' items')
        : '0 items';
    }
    if (statusEl) {
      statusEl.textContent = 'Page ' + (pageIndex + 1) + ' of ' + pageCount;
    }
    var atStart = pageIndex <= 0;
    var atEnd = pageIndex >= pageCount - 1 || total === 0;
    [btnFirst, btnPrev].forEach(function (btn) {
      if (!btn) return;
      btn.disabled = atStart;
    });
    [btnNext, btnLast].forEach(function (btn) {
      if (!btn) return;
      btn.disabled = atEnd;
    });
  }

  function renderLoadingRows() {
    var tbody = $('patcherly-errors-tbody');
    if (!tbody) return;
    tbody.innerHTML = '<tr class="patcherly-errors-loading-row"><td colspan="99" style="text-align:center;padding:20px;color:#666">'
      + '<span class="patcherly-row-busy" aria-hidden="true">…</span> Loading errors…'
      + '</td></tr>';
  }

  function renderErrorRows(items) {
    var tbody = $('patcherly-errors-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';
    if (!Array.isArray(items) || !items.length) {
      tbody.innerHTML = '<tr><td colspan="99" style="text-align:center;color:#666">No matching errors</td></tr>';
      return;
    }
    errorsById = {};
    for (var i = 0; i < items.length; i++) {
      var it = items[i];
      if (it && it.id) errorsById[it.id] = it;
      var tr = document.createElement('tr');
      tr.setAttribute('data-id', it.id || '');
      tr.innerHTML =
        '<td class="patcherly-col-cb" style="width:28px"><input type="checkbox" class="patcherly-row-cb" /></td>' +
        '<td data-col="created">' + esc(fmtDate(it.created_at)) + '</td>' +
        '<td data-col="severity">' + severityCellHtml(it.severity) + '</td>' +
        '<td data-col="status">' + formatStatus(it) + '</td>' +
        '<td data-col="language">' + esc(it.language || it.code_language || '') + '</td>' +
        '<td data-col="message" class="patcherly-msg-cell">' + messageCellHtml(it) + '</td>' +
        '<td data-col="actions" class="patcherly-row-actions"><div class="patcherly-row-actions__buttons">' + rowActionsHtml(it) + '</div></td>';
      tbody.appendChild(tr);
    }
    applyColumnVisibility();
  }

  function resetToFirstPage() {
    listMeta.pageIndex = 0;
  }
  function isColVisible(id) { return visibleColumns.indexOf(id) !== -1; }
  function applyColumnVisibility() {
    // Every `[data-col]` th / td either renders normally or is removed
    // from the layout entirely (display:none, not visibility:hidden, so
    // the next column closes the gap). Re-runs after every render so
    // newly-injected tbody cells inherit the saved prefs.
    var nodes = document.querySelectorAll('[data-col]');
    for (var i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute('data-col');
      nodes[i].style.display = isColVisible(id) ? '' : 'none';
    }
  }
  function bindColumnsMenu() {
    var wrap   = document.getElementById('patcherly-columns-wrap');
    var toggle = document.getElementById('patcherly-columns-toggle');
    var menu   = document.getElementById('patcherly-columns-menu');
    if (!wrap || !toggle || !menu) return;
    // Build the menu items from COLUMNS so future columns "just work"
    // without touching the PHP.
    var items = '';
    COLUMNS.forEach(function (c) {
      if (c.required) return; // Actions column is always on
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

    function openMenu()  { menu.hidden = false; }
    function closeMenu() { menu.hidden = true; }
    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      if (menu.hidden) openMenu(); else closeMenu();
    });
    menu.addEventListener('change', function (e) {
      var cb = e.target;
      if (!cb || !cb.matches || !cb.matches('input[data-col-toggle]')) return;
      var id = cb.getAttribute('data-col-toggle');
      var idx = visibleColumns.indexOf(id);
      if (cb.checked && idx === -1) visibleColumns.push(id);
      if (!cb.checked && idx !== -1) visibleColumns.splice(idx, 1);
      saveVisible(visibleColumns);
      applyColumnVisibility();
    });
    menu.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('[data-cols-act]') : null;
      if (!btn) return;
      var act = btn.getAttribute('data-cols-act');
      if (act === 'all') {
        visibleColumns = COLUMNS.map(function (c) { return c.id; });
      } else if (act === 'reset') {
        visibleColumns = COLUMNS_DEFAULT_VISIBLE.slice();
      }
      saveVisible(visibleColumns);
      // Sync the checkboxes to the new state.
      menu.querySelectorAll('input[data-col-toggle]').forEach(function (cb) {
        cb.checked = isColVisible(cb.getAttribute('data-col-toggle'));
      });
      applyColumnVisibility();
    });
    // Outside-click closes the menu.
    document.addEventListener('click', function (e) {
      if (menu.hidden) return;
      if (wrap.contains(e.target)) return;
      closeMenu();
    });
  }
  // Append the shared admin AJAX nonce to a query-string URL.
  function withAdminNonce(url){
    if (!cfg.adminNonce) return url;
    return url + (url.indexOf('?') === -1 ? '?' : '&') + '_ajax_nonce=' + encodeURIComponent(cfg.adminNonce);
  }

  // Connector Status lives on the Home page; the Errors page doesn't render or init it.

  // Stale-token notice is gated on `target_status === 'removed'` from the connector-status
  // endpoint to avoid false alarms from transient 401/403s (stale nonce, WAF, etc).
  async function maybeShowStaleTokenNotice() {
    try {
      var r = await fetch(withAdminNonce((typeof ajaxurl !== 'undefined' ? ajaxurl : '') + '?action=patcherly_smart_connect'), { method: 'POST' });
      if (!r.ok) return false;
      var j = await r.json();
      var data = (j && (j.data || j)) || {};
      if (data.target_status === 'removed') {
        var el = $('patcherly-stale-token');
        if (el) el.style.display = '';
        return true;
      }
    } catch (_) { /* swallow — fall back to generic message */ }
    return false;
  }

  // Helpers for the status column and the expandable message column.
  function formatStatus(item){
    var status = typeof item === 'string' ? item : (item && item.status) || '';
    var row = typeof item === 'object' ? item : null;
    if (window.PatcherlyFormat && PatcherlyFormat.statusBadgeHtml) {
      return PatcherlyFormat.statusBadgeHtml(status, row);
    }
    return esc(status || '—');
  }
  function hasInFlightError(items) {
    if (window.PatcherlyFormat && PatcherlyFormat.hasInFlightError) {
      return PatcherlyFormat.hasInFlightError(items);
    }
    if (!Array.isArray(items)) return false;
    return items.some(function (it) {
      var st = (it && it.status) || '';
      return st === 'approved' || st === 'applying' || st === 'rolling_back' || st === 'pending_analysis';
    });
  }
  function canRetryApply(item) {
    if (window.PatcherlyFormat && PatcherlyFormat.canRetryApply) {
      return PatcherlyFormat.canRetryApply(item);
    }
    return false;
  }
  function retryApplyActionTitle(item) {
    if (window.PatcherlyFormat && PatcherlyFormat.retryApplyActionTitle) {
      return PatcherlyFormat.retryApplyActionTitle(item);
    }
    return 'Retry apply';
  }
  function formatApproveDispatchFeedback(item) {
    if (window.PatcherlyFormat && PatcherlyFormat.formatApproveDispatchFeedback) {
      return PatcherlyFormat.formatApproveDispatchFeedback(item);
    }
    return { level: 'success', message: 'Fix approved.' };
  }
  function managePolling(items) {
    if (pollTimer) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
    if (!hasInFlightError(items) && !actionInFlight) return;
    var intervalMs = actionInFlight ? 3000 : 8000;
    pollTimer = setInterval(function () { loadErrors(true); }, intervalMs);
  }
  function errorPreviewText(item) {
    if (window.PatcherlyFormat && PatcherlyFormat.errorPreviewText) {
      return PatcherlyFormat.errorPreviewText(item);
    }
    return (item && (item.log_line || item.message)) || '';
  }
  function errorFullText(item) {
    if (window.PatcherlyFormat && PatcherlyFormat.errorFullText) {
      return PatcherlyFormat.errorFullText(item);
    }
    return errorPreviewText(item);
  }
  function severityCellHtml(severity) {
    if (window.PatcherlyFormat && PatcherlyFormat.severityBadgeHtml) {
      return PatcherlyFormat.severityBadgeHtml(severity);
    }
    return esc(severity || '');
  }
  function setMsgExpanded(msgEl, expanded) {
    if (!msgEl) return;
    msgEl.classList.toggle('is-expanded', expanded);
    msgEl.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    var tr = msgEl.closest('tr');
    var errId = tr && tr.getAttribute('data-id');
    var item = (errId && errorsById[errId]) ? errorsById[errId] : {};
    var textEl = msgEl.querySelector('.patcherly-msg__text');
    if (!textEl) return;
    textEl.textContent = expanded
      ? (errorFullText(item) || errorPreviewText(item) || '—')
      : (errorPreviewText(item) || '—');
  }
  function messageCellHtml(item){
    var preview = errorPreviewText(item) || '—';
    return (
      '<div class="patcherly-msg" role="button" tabindex="0" aria-expanded="false"' +
        ' title="Click to expand · double-click for full view">' +
        '<span class="patcherly-msg__text">' + esc(preview) + '</span>' +
        '<span class="patcherly-msg__hint">Click to expand · double-click for modal</span>' +
      '</div>'
    );
  }

  // ── Error management actions (proxied through WP AJAX for OAuth signing) ──

  async function doErrorAction(action, id, extra){
    var fd = new FormData();
    fd.set('action', action);
    fd.set('error_id', id);
    fd.set('_ajax_nonce', cfg.adminNonce || '');
    if (extra) { Object.keys(extra).forEach(function(k){ fd.set(k, extra[k]); }); }
    var r = await fetch(ajaxurl, { method: 'POST', body: fd });
    return parseAjaxResponse(r);
  }

  // Surface an action failure next to the originating button as a brief
  // tooltip-style label. The reload happens on the next user interaction;
  // we deliberately avoid auto-reload so the operator sees what went wrong.
  function showActionFailure(btn, json, err){
    var msg = (err && err.message) || (json && json.data && (json.data.message || json.data.error)) || 'Action failed';
    try {
      btn.setAttribute('title', msg);
      var prev = btn.textContent;
      btn.textContent = '✕ ' + (msg.length > 40 ? msg.slice(0, 40) + '…' : msg);
      btn.classList.add('patcherly-action-failed');
      setTimeout(function(){
        btn.textContent = prev;
        btn.classList.remove('patcherly-action-failed');
      }, 4000);
    } catch (_) { /* DOM removed mid-flight; nothing to do */ }
  }

  // Transient bottom-right toast for action outcomes. Used where the button
  // that triggered the action is gone by the time we have a result (delete
  // removes its row, so showActionFailure's button anchor no longer exists).
  // The wrapper carries aria-live so screen readers announce the outcome.
  function showToast(message, type){
    try {
      var wrap = $('patcherly-toast-wrap');
      if (!wrap) {
        wrap = document.createElement('div');
        wrap.id = 'patcherly-toast-wrap';
        wrap.className = 'patcherly-toast-wrap';
        wrap.setAttribute('role', 'status');
        wrap.setAttribute('aria-live', 'polite');
        document.body.appendChild(wrap);
      }
      var el = document.createElement('div');
      var toastType = type === 'error' ? 'error' : (type === 'warning' ? 'warning' : 'success');
      el.className = 'patcherly-toast patcherly-toast--' + toastType;
      if (toastType === 'warning' && !document.querySelector('style[data-patcherly-toast-warning]')) {
        var style = document.createElement('style');
        style.setAttribute('data-patcherly-toast-warning', '1');
        style.textContent = '.patcherly-toast--warning{background:#d97706;}';
        document.head.appendChild(style);
      }
      el.textContent = message;
      wrap.appendChild(el);
      void el.offsetWidth; // reflow so the enter transition runs
      el.classList.add('is-visible');
      setTimeout(function(){
        el.classList.remove('is-visible');
        setTimeout(function(){ if (el.parentNode) el.parentNode.removeChild(el); }, 250);
      }, 3500);
    } catch (_) { /* non-fatal UI affordance */ }
  }

  function closeErrorModal(){
    var modal = $('patcherly-error-modal');
    if (modal) modal.hidden = true;
  }
  function buildErrorModal(){
    if ($('patcherly-error-modal')) return $('patcherly-error-modal');
    var modal = document.createElement('div');
    modal.id = 'patcherly-error-modal';
    modal.className = 'patcherly-error-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'patcherly-error-modal-title');
    modal.innerHTML = ''
      + '<div class="patcherly-error-modal__backdrop" data-close="1"></div>'
      + '<div class="patcherly-error-modal__panel" tabindex="-1">'
        + '<div class="patcherly-error-modal__head">'
          + '<h3 id="patcherly-error-modal-title">Error details</h3>'
          + '<button type="button" class="button-link" data-close="1" aria-label="Close">✕</button>'
        + '</div>'
        + '<div class="patcherly-error-modal__body"><pre></pre></div>'
      + '</div>';
    document.body.appendChild(modal);
    modal.addEventListener('click', function(e){
      if (e.target && e.target.getAttribute && e.target.getAttribute('data-close') === '1') {
        closeErrorModal();
      }
    });
    document.addEventListener('keydown', function(e){
      if (e.key === 'Escape' && modal && !modal.hidden) closeErrorModal();
    });
    modal.hidden = true;
    return modal;
  }
  function openErrorModal(text, title){
    var modal = buildErrorModal();
    var pre = modal.querySelector('pre');
    var heading = modal.querySelector('#patcherly-error-modal-title');
    if (heading) heading.textContent = title || 'Error details';
    if (pre) pre.textContent = text || '—';
    modal.hidden = false;
    var panel = modal.querySelector('.patcherly-error-modal__panel');
    if (panel && panel.focus) panel.focus();
  }

  // ── Preview Fix modal ────────────────────────────────────────────────────
  // Fetches GET /v1/errors/{id}/fix via the WP proxy and renders the AI
  // comment, confidence (coloured vs the apply threshold), proposed diff
  // (with +/- line colouring), and prior-patch memory — mirroring the
  // dashboard fix-preview (dashboard-next/.../errors/page.tsx FixPreviewBody).
  // Close on Escape, click outside, or the close button. No third-party
  // modal lib — the admin-page chrome + tiny stylesheet is enough.
  function buildPreviewModal(){
    if ($('patcherly-fix-modal')) return $('patcherly-fix-modal');
    var modal = document.createElement('div');
    modal.id = 'patcherly-fix-modal';
    modal.className = 'patcherly-fix-modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');
    modal.setAttribute('aria-labelledby', 'patcherly-fix-modal-title');
    modal.innerHTML = ''
      + '<div class="patcherly-fix-modal__backdrop" data-close="1"></div>'
      + '<div class="patcherly-fix-modal__panel" tabindex="-1">'
        + '<div class="patcherly-fix-modal__head">'
          + '<h3 id="patcherly-fix-modal-title">Preview proposed fix</h3>'
          + '<button type="button" class="button-link" data-close="1" aria-label="Close">✕</button>'
        + '</div>'
        + '<div class="patcherly-fix-modal__body">'
          + '<p class="patcherly-fix-modal__status">Loading…</p>'
          + '<div class="patcherly-fix-modal__content" hidden></div>'
        + '</div>'
      + '</div>';
    document.body.appendChild(modal);
    modal.addEventListener('click', function(e){
      if (e.target && e.target.getAttribute && e.target.getAttribute('data-close') === '1') {
        closePreviewModal();
      }
    });
    document.addEventListener('keydown', function(e){
      if (e.key === 'Escape' && !modal.hidden) closePreviewModal();
    });
    modal.hidden = true;
    return modal;
  }
  function closePreviewModal(){
    var modal = $('patcherly-fix-modal');
    if (modal) modal.hidden = true;
  }

  // Escape HTML for safe innerHTML composition (mirrors escHtml in format lib).
  function escFixHtml(s){
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  // Render a unified diff with +/- line colouring; plain <pre> fallback.
  function renderDiffHtml(text){
    var lines = String(text).split('\n');
    var looksDiff = lines.some(function(l){
      return l.charAt(0) === '+' || l.charAt(0) === '-' || l.indexOf('@@') === 0 || l.indexOf('diff ') === 0;
    });
    if (!looksDiff) {
      return '<pre class="patcherly-fix-modal__diff">' + escFixHtml(text) + '</pre>';
    }
    var out = '';
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      var cls = 'patcherly-diff__ctx';
      if ((line.charAt(0) === '+' && line.indexOf('+++') !== 0)) cls = 'patcherly-diff__add';
      else if ((line.charAt(0) === '-' && line.indexOf('---') !== 0)) cls = 'patcherly-diff__del';
      else if (line.indexOf('@@') === 0 || line.indexOf('diff ') === 0 || line.indexOf('index ') === 0
        || line.indexOf('+++') === 0 || line.indexOf('---') === 0) cls = 'patcherly-diff__meta';
      out += '<div class="' + cls + '">' + escFixHtml(line || ' ') + '</div>';
    }
    return '<pre class="patcherly-fix-modal__diff patcherly-fix-modal__diff--colored">' + out + '</pre>';
  }

  async function openPreviewModal(id){
    var modal = buildPreviewModal();
    var statusEl  = modal.querySelector('.patcherly-fix-modal__status');
    var contentEl = modal.querySelector('.patcherly-fix-modal__content');
    statusEl.textContent = 'Loading…';
    statusEl.hidden = false;
    contentEl.hidden = true;
    contentEl.innerHTML = '';
    modal.hidden = false;
    var panel = modal.querySelector('.patcherly-fix-modal__panel');
    if (panel && panel.focus) panel.focus();
    var F = window.PatcherlyFormat || {};
    try {
      var j = await doErrorAction('patcherly_error_preview_fix', id);
      // j.data.fix is the upstream AnalysisResult: { fix, explanation,
      // confidence, error_type, patch:{patch,files_affected,lines_changed},
      // similar_failed_patch_found, failed_patch_info }.
      var fix = j && j.data && j.data.fix ? j.data.fix : null;
      if (!fix || typeof fix !== 'object') {
        statusEl.textContent = 'No proposed fix payload was returned.';
        return;
      }
      var patchObj = fix.patch && typeof fix.patch === 'object' ? fix.patch : null;
      var diffText = (patchObj && patchObj.patch) || fix.diff || fix.proposed_fix || fix.suggestion || fix.fix || '';
      var html = '';

      // Meta row: error type + coloured confidence.
      var metaBits = '';
      if (fix.error_type) {
        metaBits += '<span class="patcherly-fix-meta__item"><span class="patcherly-fix-meta__label">Error type</span> '
          + escFixHtml(fix.error_type) + '</span>';
      }
      if (fix.confidence !== null && fix.confidence !== undefined && F.confidenceTone) {
        var tone = F.confidenceTone(fix.confidence);
        var pct = F.formatConfidencePercent(fix.confidence);
        if (tone) {
          metaBits += '<span class="patcherly-fix-meta__item"><span class="patcherly-fix-meta__label">AI confidence</span> '
            + '<span class="patcherly-conf patcherly-conf--' + tone + '">' + escFixHtml(pct) + '</span></span>';
        }
      }
      if (metaBits) html += '<div class="patcherly-fix-meta">' + metaBits + '</div>';

      // AI comment (explanation).
      if (fix.explanation) {
        html += '<div class="patcherly-fix-section">'
          + '<p class="patcherly-fix-section__label">AI comment</p>'
          + '<p class="patcherly-fix-comment">' + escFixHtml(fix.explanation) + '</p>'
          + '</div>';
      }

      // Proposed diff + files/lines summary.
      if (diffText) {
        var summary = '';
        var files = patchObj && Array.isArray(patchObj.files_affected) ? patchObj.files_affected : [];
        var linesChanged = patchObj && typeof patchObj.lines_changed === 'number' ? patchObj.lines_changed : 0;
        if (files.length) summary += files.length + (files.length === 1 ? ' file' : ' files');
        if (linesChanged > 0) summary += (summary ? ' · ' : '') + linesChanged + (linesChanged === 1 ? ' line' : ' lines') + ' changed';
        html += '<div class="patcherly-fix-section">'
          + '<div class="patcherly-fix-section__head">'
            + '<p class="patcherly-fix-section__label">Proposed diff</p>'
            + (summary ? '<span class="patcherly-fix-section__meta">' + escFixHtml(summary) + '</span>' : '')
          + '</div>';
        if (files.length) {
          html += '<ul class="patcherly-fix-files">';
          for (var fi = 0; fi < files.length; fi++) {
            html += '<li>' + escFixHtml(files[fi]) + '</li>';
          }
          html += '</ul>';
        }
        html += renderDiffHtml(diffText) + '</div>';
      }

      // Prior-patch memory (why the AI avoided a known-bad patch).
      if (fix.similar_failed_patch_found && fix.failed_patch_info && typeof fix.failed_patch_info === 'object') {
        var fp = fix.failed_patch_info;
        var rows = '';
        if (fp.file_path)      rows += '<dt>File</dt><dd>' + escFixHtml(fp.file_path) + '</dd>';
        if (fp.failure_reason) rows += '<dt>Why it failed</dt><dd>' + escFixHtml(fp.failure_reason) + '</dd>';
        if (fp.failed_at)      rows += '<dt>When</dt><dd>' + escFixHtml(F.formatDateTimeIso ? F.formatDateTimeIso(fp.failed_at) : fp.failed_at) + '</dd>';
        html += '<div class="patcherly-fix-section">'
          + '<p class="patcherly-fix-section__label">Patch memory used</p>'
          + '<div class="patcherly-fix-memory">'
            + '<p>A similar prior patch on your site failed, so the AI was asked to avoid repeating it.</p>'
            + (rows ? '<dl>' + rows + '</dl>' : '')
          + '</div>'
          + '</div>';
      }

      if (!html) {
        statusEl.textContent = 'No proposed fix payload was returned.';
        return;
      }
      contentEl.innerHTML = html;
      contentEl.hidden = false;
      statusEl.hidden = true;
    } catch (err) {
      statusEl.textContent = 'Could not load preview: ' + (err && err.message ? err.message : 'unknown error');
    }
  }

  async function loadErrors(force, pageOverride){
    var msg = $('patcherly-list-msg'); var tbody = $('patcherly-errors-tbody');
    if (typeof pageOverride === 'number') {
      listMeta.pageIndex = pageOverride;
    }
    if (cfg.oauthConnected === false) {
      setText(msg, '');
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666">—</td></tr>';
      renderPagination({ total: 0, offset: 0, limit: getPageSize(), pageIndex: 0 });
      managePolling([]);
      return;
    }
    if(!cfg.url){ setText(msg,'Missing Patcherly URL'); return; }
    setText(msg,'Loading…');
    renderLoadingRows();
    applyColumnVisibility();
    try{
      var pageSize = getPageSize();
      listMeta.limit = pageSize;
      listMeta.pageIndex = clampPageIndex(listMeta.pageIndex, listMeta.total || 0, pageSize);
      var offset = listMeta.pageIndex * pageSize;
      listMeta.offset = offset;

      var s   = ($('patcherly-flt-status') && $('patcherly-flt-status').value) || '';
      var sev = ($('patcherly-flt-sev')    && $('patcherly-flt-sev').value)    || '';
      var lang = ($('patcherly-flt-lang')  && $('patcherly-flt-lang').value)   || '';
      var ttlToUse = force ? 0 : (parseInt(cfg.ttl,10)||0);
      var fd = new FormData();
      fd.set('action', 'patcherly_errors_list');
      if (s) fd.set('status', s);
      if (sev) fd.set('severity', sev);
      if (lang) fd.set('language', lang);
      fd.set('limit', String(pageSize));
      fd.set('offset', String(offset));
      fd.set('ttl', ttlToUse > 0 ? String(ttlToUse) : '0');
      fd.set('_ajax_nonce', cfg.adminNonce || '');
      var r = await fetch((typeof ajaxurl !== 'undefined' ? ajaxurl : ''), {
        method: 'POST',
        body: fd,
        credentials: 'same-origin'
      });
      var payload = await parseAjaxResponse(r);
      var items = [];
      var total = 0;
      var respOffset = offset;
      var respLimit = pageSize;
      if (payload && Array.isArray(payload.items)) {
        items = payload.items;
        total = typeof payload.total === 'number' ? payload.total : items.length;
        respOffset = typeof payload.offset === 'number' ? payload.offset : offset;
        respLimit = typeof payload.limit === 'number' ? payload.limit : pageSize;
      } else if (Array.isArray(payload)) {
        items = payload;
        total = items.length;
      }
      listMeta.total = total;
      listMeta.offset = respOffset;
      listMeta.limit = respLimit;
      listMeta.pageIndex = respLimit > 0 ? Math.floor(respOffset / respLimit) : 0;
      listMeta.pageIndex = clampPageIndex(listMeta.pageIndex, total, respLimit);

      renderErrorRows(items);
      renderPagination(listMeta);
      setText(msg, total ? ('Loaded ' + items.length + ' of ' + total) : 'Loaded 0');
      managePolling(items);

      if (!items.length && total > 0 && listMeta.pageIndex > 0) {
        listMeta.pageIndex = listMeta.pageIndex - 1;
        return loadErrors(force, listMeta.pageIndex);
      }
    }catch(e){
      var displayMsg = (e && e.message) ? e.message : 'Failed to load errors';
      if (tbody) {
        tbody.innerHTML = '<tr><td colspan="99" style="text-align:center;color:#b32d2e">'
          + esc(displayMsg)
          + '</td></tr>';
      }
      renderPagination({ total: 0, offset: 0, limit: getPageSize(), pageIndex: 0 });
      managePolling([]);
      if (e && e.message) {
        // 401/403 → ask the API why. If `target_status === 'removed'` the
        // PHP-rendered banner at the top of the page is unhidden; any other
        // cause (stale nonce, transient WAF, PHP-FPM reboot) gets a
        // contextual inline message instead of a misleading "site removed"
        // banner.
        if (e.message.indexOf('401') !== -1 || e.message.indexOf('403') !== -1) {
          maybeShowStaleTokenNotice().then(function(shown){
            if (shown) {
              setText(msg, '');
            } else {
              setText(msg, 'Patcherly rejected the request — reload this page and try again.');
            }
          });
          return;
        }
        if (isApiDownStatus(e.httpStatus) || isApiDownPayload(e.payload) || e.message === apiDownMessage()) {
          setText(msg, apiDownMessage());
          return;
        }
        if (e.message.indexOf('Failed to fetch') !== -1 || e.message.indexOf('NetworkError') !== -1) {
          setText(msg, apiDownMessage());
          return;
        }
      }
      setText(msg, 'Failed: ' + displayMsg);
    }
  }

  // Per-status icon-button set, mirroring the dashboard Errors table.
  // Glyphs/colours live in patcherly-format.js; canonical verbs flow through `data-act`.
  function iconBtn(opts){
    if (window.PatcherlyFormat && PatcherlyFormat.iconButtonHtml) {
      return PatcherlyFormat.iconButtonHtml(opts);
    }
    return '<button type="button" class="button-link" data-act="' + esc(opts.act) + '" title="' + esc(opts.title) + '">' + esc(opts.title) + '</button>';
  }
  function busyIcon(title){
    if (window.PatcherlyFormat && PatcherlyFormat.iconButtonHtml) {
      return PatcherlyFormat.iconButtonHtml({ busy: true, title: title, variant: 'accent' });
    }
    return '<span class="patcherly-row-busy" aria-label="' + esc(title) + '" title="' + esc(title) + '">…</span>';
  }
  function waitingIcon(title){
    if (window.PatcherlyFormat && PatcherlyFormat.waitingIcon) {
      return PatcherlyFormat.waitingIcon(title);
    }
    return busyIcon(title);
  }
  function rowActionsHtml(it){
    var st = it.status || '';
    var html = '';
    // Spinner takes the slot during long-running transitions so the
    // row visibly narrates what Patcherly is doing.
    if (st === 'pending_analysis') {
      if (it.analysis_retry_scheduled) html += busyIcon('Retry scheduled');
      else html += busyIcon('Pending analysis');
    }
    else if (st === 'applying') html += busyIcon('Applying…');
    else if (window.PatcherlyFormat && PatcherlyFormat.showWaitingForConnector && PatcherlyFormat.showWaitingForConnector(it)) {
      html += waitingIcon('Waiting for connector to fetch and apply the fix');
    }
    else if (st === 'rolling_back') html += busyIcon('Rolling back…');
    // Queue for AI analysis — forced analyze is dashboard superadmin-only, not here.
    if (st === 'pending') {
      html += iconBtn({ act: 'analyze', title: 'Analyze with AI', icon: 'brain', variant: 'ai' });
    }
    if (st === 'analysis_failed') {
      html += iconBtn({ act: 'retry_analysis', title: 'Retry analysis', icon: 'brain', variant: 'ai' });
    }
    // Preview fix whenever analysis metadata may exist; approve only pre-apply.
    if (window.PatcherlyFormat && PatcherlyFormat.canShowFixPreviewAction(st)) {
      html += iconBtn({ act: 'preview_fix', title: 'Preview fix', icon: 'eye', variant: 'ai' });
    }
    if (st === 'analyzed' || st === 'awaiting_approval' || st === 'manual_review_required') {
      html += iconBtn({ act: 'approve_fix', title: 'Approve fix', icon: 'shieldCheck', variant: 'success' });
    }
    if (canRetryApply(it)) {
      html += iconBtn({
        act: 'retry_apply',
        title: retryApplyActionTitle(it),
        icon: 'shield',
        variant: 'success'
      });
    }
    if (window.PatcherlyFormat && PatcherlyFormat.canMarkFixedManually && PatcherlyFormat.canMarkFixedManually(it)) {
      html += iconBtn({ act: 'mark_fixed', title: 'Mark as manually fixed', icon: 'check', variant: 'success' });
    }
    if (window.PatcherlyFormat && PatcherlyFormat.canShowDismissAction && PatcherlyFormat.canShowDismissAction(st)) {
      html += iconBtn({
        act: 'dismiss',
        title: PatcherlyFormat.getDismissActionLabel
          ? PatcherlyFormat.getDismissActionLabel(st)
          : 'Close error',
        icon: 'x',
        variant: 'danger'
      });
    }
    // Rollback reverts applied patches from the connector's on-server backup; Restore re-queues dismissed/rolled-back errors.
    if (window.PatcherlyFormat && PatcherlyFormat.canRollbackFix && PatcherlyFormat.canRollbackFix(it)) {
      html += iconBtn({ act: 'rollback', title: 'Rollback fix (restore files from backup)', icon: 'rotateCcw', variant: 'danger' });
    }
    if (st === 'ignored') {
      html += iconBtn({ act: 'restore', title: 'Unignore', icon: 'x', variant: 'success' });
    } else if (st === 'rolled_back' || st === 'restored' || st === 'dismissed') {
      html += iconBtn({ act: 'restore', title: 'Restore to queue', icon: 'check', variant: 'success' });
    }
    if (st !== 'ignored' && st !== 'excluded') {
      html += iconBtn({ act: 'ignore', title: 'Hide Error & Ignore', icon: 'x', variant: 'muted' });
    }
    if (window.PatcherlyFormat && PatcherlyFormat.canDeleteError && PatcherlyFormat.canDeleteError(it)) {
      html += iconBtn({ act: 'delete', title: 'Delete', icon: 'trash', variant: 'danger' });
    }
    return html;
  }

  // Keyboard activation for the expandable message cell — Enter / Space
  // matches the `role="button"` + `tabindex="0"` contract on the element.
  function maybeToggleMsg(e){
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var el = e.target && e.target.closest ? e.target.closest('.patcherly-msg') : null;
    if (!el) return;
    e.preventDefault();
    setMsgExpanded(el, !el.classList.contains('is-expanded'));
  }

  function bind(){
    var btn = $('patcherly-btn-refresh');
    if (btn) btn.addEventListener('click', function(e){
      e.preventDefault();
      setText($('patcherly-list-msg'),'Refreshing…');
      fetch(withAdminNonce((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_flush_errors_cache'), { method:'POST' })
        .finally(function(){ loadErrors(true); });
    });

    var fltLimit = $('patcherly-flt-limit');
    if (fltLimit) {
      var allowed = ['10', '25', '50', '100'];
      var initial = String((cfg && cfg.defaultLimit) ? cfg.defaultLimit : '25');
      if (allowed.indexOf(initial) === -1) initial = '25';
      fltLimit.value = initial;
      listMeta.limit = parseInt(initial, 10) || 25;
      fltLimit.addEventListener('change', function(){
        try{
          var fd = new FormData();
          fd.set('action','patcherly_save_default_limit');
          fd.set('value', this.value);
          fd.set('_ajax_nonce', cfg.adminNonce || '');
          fetch((typeof ajaxurl!=='undefined'?ajaxurl:''), { method:'POST', body: fd });
        }catch(_){ }
        resetToFirstPage();
        loadErrors(false);
      });
    }

    function bindFilterReset(el) {
      if (!el) return;
      el.addEventListener('change', function () {
        resetToFirstPage();
        loadErrors(false);
      });
    }
    bindFilterReset($('patcherly-flt-status'));
    bindFilterReset($('patcherly-flt-sev'));
    var fltLang = $('patcherly-flt-lang');
    if (fltLang) {
      fltLang.addEventListener('change', function () { resetToFirstPage(); loadErrors(false); });
      fltLang.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); resetToFirstPage(); loadErrors(false); }
      });
    }

    function goToPage(pageIndex) {
      listMeta.pageIndex = pageIndex;
      loadErrors(false, pageIndex);
    }
    var btnFirst = $('patcherly-page-first');
    var btnPrev = $('patcherly-page-prev');
    var btnNext = $('patcherly-page-next');
    var btnLast = $('patcherly-page-last');
    if (btnFirst) btnFirst.addEventListener('click', function (e) { e.preventDefault(); goToPage(0); });
    if (btnPrev) btnPrev.addEventListener('click', function (e) {
      e.preventDefault();
      goToPage(Math.max(0, listMeta.pageIndex - 1));
    });
    if (btnNext) btnNext.addEventListener('click', function (e) {
      e.preventDefault();
      goToPage(listMeta.pageIndex + 1);
    });
    if (btnLast) btnLast.addEventListener('click', function (e) {
      e.preventDefault();
      var pageCount = getPageCount(listMeta.total, getPageSize());
      goToPage(Math.max(0, pageCount - 1));
    });

    // Row actions — lifecycle dispatcher; buttons emit `data-act` (analyze, preview_fix,
    // approve_fix, rollback, restore, dismiss, delete) → matching AJAX endpoint.
    var tbody = $('patcherly-errors-tbody');
    // Column manager — open/close + persistence to localStorage; menu UI ships in PHP.
    bindColumnsMenu();
    applyColumnVisibility();

    if (window.PatcherlyFormat && PatcherlyFormat.mountActionsLegend) {
      PatcherlyFormat.mountActionsLegend('patcherly-actions-legend', { includeIgnore: true });
    }

    if (tbody) tbody.addEventListener('keydown', maybeToggleMsg);
    if (tbody) tbody.addEventListener('click', async function(e){
      var t = e.target;

      // Expandable error column — click toggles inline; double-click opens modal.
      var msgEl = t && (t.closest ? t.closest('.patcherly-msg') : null);
      if (msgEl && !t.closest('.patcherly-row-actions')) {
        if (e.detail >= 2) {
          var trMsg = msgEl.closest('tr');
          var errId = trMsg && trMsg.getAttribute('data-id');
          var item = (errId && errorsById[errId]) ? errorsById[errId] : {};
          openErrorModal(errorFullText(item), errId ? ('Error ' + errId) : 'Error details');
          return;
        }
        var expanded = !msgEl.classList.contains('is-expanded');
        setMsgExpanded(msgEl, expanded);
        return;
      }

      var actBtn = t && (t.closest ? t.closest('button[data-act]') : null);
      if (!actBtn) return;
      e.preventDefault();
      var act = actBtn.getAttribute('data-act');
      var tr  = actBtn.closest('tr');
      var id  = tr && tr.getAttribute('data-id');
      if (!id || !act) return;

      if (act === 'preview_fix') {
        await openPreviewModal(id);
        return;
      }
      if (act === 'rollback') {
        var reason = window.prompt('Why are you rolling back this fix? (optional)') || '';
        try {
          var jR = await doErrorAction('patcherly_error_rollback', id, { reason: reason });
          if (jR && jR.success !== false) loadErrors(true);
          else showActionFailure(actBtn, jR);
        } catch (err) { showActionFailure(actBtn, null, err); }
        return;
      }
      if (act === 'delete') {
        var delItem = errorsById[id];
        if (window.PatcherlyFormat && PatcherlyFormat.canDeleteError && !PatcherlyFormat.canDeleteError(delItem)) {
          showToast(
            (PatcherlyFormat.errorDeleteBlockedReason && PatcherlyFormat.errorDeleteBlockedReason(delItem))
              || 'Delete is not allowed for this error.',
            'error'
          );
          return;
        }
        try {
          var jD = await doErrorAction('patcherly_error_delete', id);
          if (jD && jD.success !== false) { tr.remove(); showToast('Error deleted.', 'success'); }
          else showActionFailure(actBtn, jD);
        } catch (err) { showActionFailure(actBtn, null, err); }
        return;
      }
      // analyze | accept_fix | apply_fix | dismiss | restore — map to ajax handlers.
      var handlerMap = {
        analyze:           'patcherly_error_analyze',
        retry_analysis:    'patcherly_error_retry_analysis',
        approve_fix:       'patcherly_error_apply_fix',
        accept_fix:        'patcherly_error_apply_fix',
        apply_fix:         'patcherly_error_apply_fix',
        retry_apply:       'patcherly_error_retry_apply',
        mark_fixed:        'patcherly_error_mark_fixed',
        rollback:          'patcherly_error_rollback',
        restore:           'patcherly_error_restore',
        dismiss:           'patcherly_error_dismiss',
        ignore:            'patcherly_error_ignore'
      };
      var handler = handlerMap[act];
      if (!handler) return;
      actBtn.disabled = true;
      actionInFlight = true;
      managePolling(Object.keys(errorsById).map(function (k) { return errorsById[k]; }));
      try {
        var jX = await doErrorAction(handler, id);
        if (jX && jX.success !== false) {
          if (act === 'approve_fix' || act === 'accept_fix' || act === 'apply_fix') {
            var localApply = jX.data && jX.data.local_cache_apply ? jX.data.local_cache_apply : null;
            if (localApply && localApply.attempted && localApply.success) {
              showToast('Fix applied from local cache on this site.', 'success');
            } else if (localApply && localApply.attempted && !localApply.success) {
              showToast(
                localApply.message ? ('Local cache apply failed: ' + localApply.message) : 'Local cache apply failed.',
                'warning'
              );
            } else {
              var upstream = jX.data && jX.data.upstream ? jX.data.upstream : null;
              if (upstream) {
                var feedback = formatApproveDispatchFeedback(upstream);
                showToast(feedback.message, feedback.level === 'warning' ? 'warning' : (feedback.level === 'info' ? 'info' : 'success'));
              } else {
                showToast('Fix approved.', 'success');
              }
            }
          } else if (act === 'retry_apply') {
            var retryUpstream = jX.data && jX.data.upstream ? jX.data.upstream : null;
            if (retryUpstream && retryUpstream.apply_dispatch_ok === false) {
              var retryErr = String(retryUpstream.apply_dispatch_error || '').trim();
              var retryHint = window.PatcherlyFormat && PatcherlyFormat.localCacheApplyFallbackHint
                ? PatcherlyFormat.localCacheApplyFallbackHint(retryUpstream)
                : null;
              showToast(
                retryHint || (retryErr ? ('Retry apply failed to dispatch: ' + retryErr) : 'Retry apply failed to dispatch.'),
                retryHint ? 'info' : 'warning'
              );
            } else {
              showToast('Apply re-dispatched — waiting for the connector.', 'success');
            }
          }
          await loadErrors(true);
        } else {
          showActionFailure(actBtn, jX);
        }
      } catch (err) {
        showActionFailure(actBtn, null, err);
      } finally {
        actBtn.disabled = false;
        actionInFlight = false;
        managePolling(Object.keys(errorsById).map(function (k) { return errorsById[k]; }));
      }
      return;
    });

    // Bulk select + delete
    var selAll = document.getElementById('patcherly-cb-all');
    if (selAll && tbody){
      selAll.addEventListener('change', function(){
        tbody.querySelectorAll('.patcherly-row-cb').forEach(function(cb){ cb.checked = selAll.checked; });
      });
    }
    var bulkBtn = document.getElementById('patcherly-btn-del-selected');
    if (bulkBtn && tbody){
      bulkBtn.addEventListener('click', async function(e){
        e.preventDefault();
        var ids = Array.from(tbody.querySelectorAll('tr'))
          .filter(function(row){ var cb = row.querySelector('.patcherly-row-cb'); return cb && cb.checked; })
          .map(function(row){ return row.getAttribute('data-id'); })
          .filter(Boolean);
        if (!ids.length) return;
        var deletable = ids.filter(function(id) {
          var item = errorsById[id];
          if (window.PatcherlyFormat && PatcherlyFormat.canDeleteError) {
            return PatcherlyFormat.canDeleteError(item);
          }
          return true;
        });
        if (!deletable.length) {
          showToast('Selected errors cannot be deleted after apply. Use Hide Error & Ignore instead.', 'error');
          return;
        }
        if (deletable.length < ids.length) {
          var skipped = ids.length - deletable.length;
          if (!window.confirm(
            'Delete ' + deletable.length + ' of ' + ids.length + ' selected error(s)? '
            + skipped + ' cannot be deleted after apply — use Hide Error & Ignore for those.'
          )) {
            return;
          }
        }
        try{
          var fd = new FormData();
          fd.set('action', 'patcherly_error_bulk_delete');
          fd.set('ids', JSON.stringify(deletable));
          fd.set('_ajax_nonce', cfg.adminNonce || '');
          var r = await fetch(ajaxurl, { method: 'POST', body: fd });
          var j = await parseAjaxResponse(r);
          if (j && j.success !== false) {
            Array.from(tbody.querySelectorAll('tr')).forEach(function(row){
              if (deletable.indexOf(row.getAttribute('data-id')) !== -1) row.remove();
            });
            try { await fetch(withAdminNonce((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_flush_errors_cache'), { method:'POST' }); }catch(_){ }
            loadErrors(true);
            showToast(deletable.length === 1 ? '1 error deleted.' : (deletable.length + ' errors deleted.'), 'success');
          } else {
            var bmsg = (j && j.data && (j.data.message || j.data.error)) || 'Delete failed.';
            showToast(bmsg, 'error');
          }
        }catch(err){
          var bulkMsg = (err && err.message) ? err.message : 'Delete failed.';
          showToast('Delete failed: ' + bulkMsg, 'error');
        }
      });
    }
  }

  if (document.readyState === 'complete') { bind(); loadErrors(false); }
  else { window.addEventListener('load', function(){ bind(); loadErrors(false); }); }
})();
