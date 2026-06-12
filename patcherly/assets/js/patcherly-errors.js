(function(){
  var cfg = window.PATCHERLY_ERRORS || { url: '', ttl: 60, defaultLimit: 20, adminNonce: '', oauthConnected: true, settingsUrl: '' };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  function esc(s){ if(s==null) return ''; return (''+s).replace(/[&<>]/g, function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]);}); }
  function fmtDate(s){ try{ var d=new Date(s); if(!isNaN(d)) return d.toLocaleString(); }catch(_){ } return s; }

  // Column visibility — every column except Actions is togglable; choice persists in localStorage.
  // The Demo page uses a sibling module with sessionStorage so the demo can't touch WP state.
  // Defaults match the dashboard minus Language (hidden by default; one click in the Columns menu).
  var COLUMNS = [
    { id: 'created',  label: 'Detected',  required: false },
    { id: 'severity', label: 'Severity',  required: false },
    { id: 'status',   label: 'Status',    required: false },
    { id: 'language', label: 'Language',  required: false },
    { id: 'message',  label: 'Message',   required: false },
    { id: 'actions',  label: 'Actions',   required: true  }
  ];
  var COLUMNS_DEFAULT_VISIBLE = ['created', 'severity', 'status', 'message', 'actions'];
  var COLUMNS_KEY = 'patcherly_errors_columns_v1';
  function loadVisible() {
    try {
      var raw = window.localStorage.getItem(COLUMNS_KEY);
      if (raw) {
        var arr = JSON.parse(raw);
        if (Array.isArray(arr)) {
          // Always keep `actions` visible — it's required by COLUMNS.
          if (arr.indexOf('actions') === -1) arr.push('actions');
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

  // Connector Status lives on the Settings page; the Errors page doesn't render or init it.

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
  function formatStatus(status){
    if (window.PatcherlyFormat && PatcherlyFormat.statusBadgeHtml) return PatcherlyFormat.statusBadgeHtml(status);
    return esc(status || '—');
  }
  function messageCellHtml(text){
    // Two-line clamp by default; click toggles the full message inline.
    var raw = (text == null) ? '' : String(text);
    return (
      '<div class="patcherly-msg" role="button" tabindex="0" aria-expanded="false"' +
        ' title="' + esc(raw) + '">' +
        '<span class="patcherly-msg__text">' + esc(raw) + '</span>' +
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
    // Try to parse the JSON body even on non-2xx so the caller can show
    // a structured error message from the upstream (e.g. "Cannot rollback:
    // already restored") instead of swallowing the response into "HTTP 409".
    var j = null;
    try { j = await r.json(); } catch (_) { /* fall through */ }
    if (!r.ok) {
      var msg = (j && j.data && (j.data.message || j.data.error)) || ('HTTP ' + r.status);
      var err = new Error(msg);
      err.payload = j && j.data ? j.data : null;
      throw err;
    }
    return j || {};
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

  // ── Preview Fix modal ────────────────────────────────────────────────────
  // Fetches GET /api/errors/{id}/fix via the WP proxy and renders the
  // proposed diff in a lightweight inline modal. Close on Escape, click
  // outside, or the close button. No third-party modal lib — we already
  // have admin-page chrome and a tiny stylesheet, an extra dependency is
  // overkill for a read-only diff viewer.
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
          + '<pre class="patcherly-fix-modal__diff" hidden></pre>'
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
  async function openPreviewModal(id){
    var modal = buildPreviewModal();
    var statusEl = modal.querySelector('.patcherly-fix-modal__status');
    var diffEl   = modal.querySelector('.patcherly-fix-modal__diff');
    statusEl.textContent = 'Loading…';
    statusEl.hidden = false;
    diffEl.hidden = true;
    diffEl.textContent = '';
    modal.hidden = false;
    var panel = modal.querySelector('.patcherly-fix-modal__panel');
    if (panel && panel.focus) panel.focus();
    try {
      var j = await doErrorAction('patcherly_error_preview_fix', id);
      var fix = j && j.data && j.data.fix ? j.data.fix : null;
      // The upstream payload shape varies: some endpoints return
      // `{patch: "..."}`, others `{diff: "..."}` or wrap the proposal
      // under `proposed_fix`. Try the common keys in order so the modal
      // shows something useful regardless of which shape the API ships.
      var text = '';
      if (fix) {
        text = fix.diff || fix.patch || fix.proposed_fix || fix.suggestion || '';
        if (!text && typeof fix === 'object') text = JSON.stringify(fix, null, 2);
      }
      if (text) {
        diffEl.textContent = text;
        diffEl.hidden = false;
        statusEl.hidden = true;
      } else {
        statusEl.textContent = 'No proposed fix payload was returned.';
      }
    } catch (err) {
      statusEl.textContent = 'Could not load preview: ' + (err && err.message ? err.message : 'unknown error');
    }
  }

  async function loadErrors(force){
    var msg = $('patcherly-list-msg'); var tbody = $('patcherly-errors-tbody');
    // v1.49.x — short-circuit when the site isn't paired. The PHP renders
    // a friendly notice at the top of the page in this state; we don't
    // need to also surface an inline "Failed:" message.
    if (cfg.oauthConnected === false) {
      setText(msg, '');
      if (tbody) tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666">—</td></tr>';
      return;
    }
    if(!cfg.url){ setText(msg,'Missing Patcherly URL'); return; }
    setText(msg,'Loading…');
    // Re-apply visibility before each render — `applyColumnVisibility()`
    // is also called once during bind() so the static `<thead>` matches
    // the saved prefs at first paint, but a render between toggles needs
    // the same pass for the newly-injected tbody cells.
    applyColumnVisibility();
    try{
      var p = new URLSearchParams();
      var s   = ($('patcherly-flt-status') && $('patcherly-flt-status').value) || '';
      var sev = ($('patcherly-flt-sev')    && $('patcherly-flt-sev').value)    || '';
      var lang = ($('patcherly-flt-lang')  && $('patcherly-flt-lang').value)   || '';
      var lim = ($('patcherly-flt-limit')  && $('patcherly-flt-limit').value)  || String(cfg.defaultLimit || '50');
      if (s)   p.set('status', s);
      if (sev) p.set('severity', sev);
      if (lang) p.set('language', lang);
      if (lim) p.set('limit', lim);
      var ttlToUse = force ? 0 : (parseInt(cfg.ttl,10)||0);
      if (ttlToUse > 0) p.set('ttl', String(ttlToUse)); else p.set('ttl','0');
      var r = await fetch(
        withAdminNonce((typeof ajaxurl !== 'undefined' ? ajaxurl : '') +
        '?action=patcherly_errors_list' + (p.toString() ? ('&' + p.toString()) : '')),
        { headers: { 'X-APR-Proxy': '1' } }
      );
      if(!r.ok) throw new Error('HTTP '+r.status);
      var items = await r.json();
      tbody.innerHTML='';
      if (!Array.isArray(items) || !items.length){
        // colspan=99 spans every visible column without us having to
        // recompute the count each render (the cells we DON'T emit just
        // shrink the colspan virtually — there's no actual column slot
        // to fill since rendered rows above have the same hidden cells).
        tbody.innerHTML = '<tr><td colspan="99" style="text-align:center;color:#666">No data</td></tr>';
        setText(msg,'Loaded 0');
        return;
      }
      for (var i=0;i<items.length;i++){
        var it = items[i];
        var tr = document.createElement('tr');
        tr.setAttribute('data-id', it.id || '');
        // Always emit every cell with a `data-col` attribute and let
        // applyColumnVisibility() flip display:none on the hidden ones.
        // This keeps column toggling instant (no re-fetch, no rebuild)
        // and the thead/tbody alignment is always 1:1.
        tr.innerHTML =
          '<td class="patcherly-col-cb" style="width:28px"><input type="checkbox" class="patcherly-row-cb" /></td>'+
          '<td data-col="created">'+esc(fmtDate(it.created_at))+'</td>'+
          '<td data-col="severity">'+esc(it.severity||'')+'</td>'+
          '<td data-col="status">'+formatStatus(it.status)+'</td>'+
          '<td data-col="language">'+esc(it.language||'')+'</td>'+
          '<td data-col="message" class="patcherly-msg-cell">'+messageCellHtml(it.log_line||'')+'</td>'+
          '<td data-col="actions" class="patcherly-row-actions"><div class="patcherly-row-actions__buttons">'+rowActionsHtml(it)+'</div></td>';
        tbody.appendChild(tr);
      }
      setText(msg,'Loaded '+items.length);
    }catch(e){
      tbody.innerHTML = '<tr><td colspan="99" style="text-align:center;color:#666">No data</td></tr>';
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
        if (e.message.indexOf('503') !== -1) { setText(msg,'API server unavailable — please try again later'); return; }
        if (e.message.indexOf('502') !== -1) { setText(msg,'API gateway error — please try again later'); return; }
        if (e.message.indexOf('504') !== -1) { setText(msg,'API server timeout — please try again later'); return; }
        if (e.message.indexOf('Failed to fetch') !== -1 || e.message.indexOf('NetworkError') !== -1) {
          setText(msg,'Connection failed — check your network'); return;
        }
      }
      setText(msg,'Failed: '+(e&&e.message?e.message:'error'));
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
  function rowActionsHtml(it){
    var st = it.status || '';
    var html = '';
    // Spinner takes the slot during long-running transitions so the
    // row visibly narrates what Patcherly is doing.
    if (st === 'pending_analysis') html += busyIcon('Analyzing…');
    else if (st === 'applying')     html += busyIcon('Applying…');
    else if (st === 'rolling_back') html += busyIcon('Rolling back…');
    // Analyze / re-analyze.
    if (st === 'pending' || st === 'analysis_failed') {
      html += iconBtn({ act: 'analyze', title: 'Analyze with AI', icon: 'brain', variant: 'accent' });
    }
    // Preview fix.
    if (st === 'analyzed' || st === 'awaiting_approval' || st === 'manual_review_required' || st === 'approved') {
      html += iconBtn({ act: 'preview_fix', title: 'Preview fix', icon: 'eye', variant: 'info' });
    }
    // Accept after analysis.
    if (st === 'analyzed') {
      html += iconBtn({ act: 'accept_fix', title: 'Accept fix', icon: 'check', variant: 'success' });
      html += iconBtn({ act: 'dismiss',    title: 'Dismiss',    icon: 'x',     variant: 'warning' });
    }
    if (st === 'awaiting_approval' || st === 'manual_review_required') {
      html += iconBtn({ act: 'apply_fix', title: st === 'manual_review_required' ? 'Approve after review' : 'Approve fix', icon: 'check', variant: 'success' });
    }
    if (st === 'approved') {
      html += iconBtn({ act: 'apply_fix', title: 'Apply fix', icon: 'check', variant: 'success' });
    }
    // Rollback / restore.
    if (st === 'fixed' || st === 'failed' || st === 'rollback_failed') {
      html += iconBtn({ act: 'rollback', title: 'Rollback fix', icon: 'rotateCcw', variant: 'warning' });
    }
    if (st === 'ignored' || st === 'rolled_back' || st === 'restored' || st === 'dismissed') {
      html += iconBtn({ act: 'restore', title: 'Restore', icon: 'refreshCw', variant: 'info' });
    }
    // Delete is always available.
    html += iconBtn({ act: 'delete', title: 'Delete', icon: 'trash', variant: 'danger' });
    return html;
  }

  // Keyboard activation for the expandable message cell — Enter / Space
  // matches the `role="button"` + `tabindex="0"` contract on the element.
  function maybeToggleMsg(e){
    if (e.key !== 'Enter' && e.key !== ' ') return;
    var el = e.target && e.target.closest ? e.target.closest('.patcherly-msg') : null;
    if (!el) return;
    e.preventDefault();
    var expanded = el.classList.toggle('is-expanded');
    el.setAttribute('aria-expanded', expanded ? 'true' : 'false');
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
      var allowed = ['20','50','100'];
      var initial = String((cfg && cfg.defaultLimit) ? cfg.defaultLimit : '20');
      if (allowed.indexOf(initial) === -1) initial = '20';
      fltLimit.value = initial;
      fltLimit.addEventListener('change', function(){
        try{
          var fd = new FormData();
          fd.set('action','patcherly_save_default_limit');
          fd.set('value', this.value);
          fd.set('_ajax_nonce', cfg.adminNonce || '');
          fetch((typeof ajaxurl!=='undefined'?ajaxurl:''), { method:'POST', body: fd });
        }catch(_){ }
        loadErrors(false);
      });
    }

    // Row actions — dashboard-parity dispatcher; buttons emit `data-act` (analyze, preview_fix,
    // accept_fix, apply_fix, rollback, restore, dismiss, delete) → matching AJAX endpoint.
    var tbody = $('patcherly-errors-tbody');
    // Column manager — open/close + persistence to localStorage; menu UI ships in PHP.
    bindColumnsMenu();
    applyColumnVisibility();

    if (tbody) tbody.addEventListener('keydown', maybeToggleMsg);
    if (tbody) tbody.addEventListener('click', async function(e){
      var t = e.target;

      // Expandable message column — click the clamped text to toggle the
      // full message inline (CSS handles the visual transition).
      var msgEl = t && (t.closest ? t.closest('.patcherly-msg') : null);
      if (msgEl && !t.closest('.patcherly-row-actions')) {
        var expanded = msgEl.classList.toggle('is-expanded');
        msgEl.setAttribute('aria-expanded', expanded ? 'true' : 'false');
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
        try {
          var jD = await doErrorAction('patcherly_error_delete', id);
          if (jD && jD.success !== false) tr.remove();
          else showActionFailure(actBtn, jD);
        } catch (err) { showActionFailure(actBtn, null, err); }
        return;
      }
      // analyze | accept_fix | apply_fix | dismiss | restore — all map to
      // a same-named ajax handler and re-load the list on success so the
      // status badge + action set transitions in lockstep with the server.
      var handlerMap = {
        analyze:    'patcherly_error_analyze',
        accept_fix: 'patcherly_error_accept_fix',
        apply_fix:  'patcherly_error_apply_fix',
        dismiss:    'patcherly_error_dismiss',
        restore:    'patcherly_error_restore'
      };
      var handler = handlerMap[act];
      if (!handler) return;
      actBtn.disabled = true;
      try {
        var jX = await doErrorAction(handler, id);
        if (jX && jX.success !== false) loadErrors(true);
        else showActionFailure(actBtn, jX);
      } catch (err) {
        showActionFailure(actBtn, null, err);
      } finally {
        actBtn.disabled = false;
      }
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
        try{
          var fd = new FormData();
          fd.set('action', 'patcherly_error_bulk_delete');
          fd.set('ids', JSON.stringify(ids));
          fd.set('_ajax_nonce', cfg.adminNonce || '');
          var r = await fetch(ajaxurl, { method: 'POST', body: fd });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          if (j && j.success !== false) {
            Array.from(tbody.querySelectorAll('tr')).forEach(function(row){
              if (ids.indexOf(row.getAttribute('data-id')) !== -1) row.remove();
            });
            try { await fetch(withAdminNonce((typeof ajaxurl!=='undefined'?ajaxurl:'') + '?action=patcherly_flush_errors_cache'), { method:'POST' }); }catch(_){ }
            loadErrors(true);
          }
        }catch(_){ }
      });
    }
  }

  if (document.readyState === 'complete') { bind(); loadErrors(false); }
  else { window.addEventListener('load', function(){ bind(); loadErrors(false); }); }
})();
