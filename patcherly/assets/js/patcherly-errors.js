(function(){
  var cfg = window.PATCHERLY_ERRORS || { url: '', ttl: 60, defaultLimit: 20, adminNonce: '', oauthConnected: true, settingsUrl: '' };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  function esc(s){ if(s==null) return ''; return (''+s).replace(/[&<>]/g, function(c){return ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]);}); }
  function fmtDate(s){ try{ var d=new Date(s); if(!isNaN(d)) return d.toLocaleString(); }catch(_){ } return s; }
  // Append the shared admin AJAX nonce to a query-string URL.
  function withAdminNonce(url){
    if (!cfg.adminNonce) return url;
    return url + (url.indexOf('?') === -1 ? '?' : '&') + '_ajax_nonce=' + encodeURIComponent(cfg.adminNonce);
  }

  // v1.49.x — Connector Status was relocated to the Settings page; the
  // Errors page no longer renders the status panel, no longer enqueues
  // patcherly-status.js, and no longer calls PatcherlyStatus.init().
  // The shared status JS is now enqueued only on the Settings page where
  // PATCHERLY_SETTINGS owns the binding.

  // v1.49.5 — the stale-token notice is reserved for the specific case the
  // copy talks about ("The Patcherly API rejected this site's credentials.
  // The site or target may have been removed from your dashboard.").
  // Before this version, ANY 401/403 — including a stale nonce, an
  // OAuth-bundle decryption mismatch, or a transient WAF block — flipped
  // the same notice on, which produced false alarms after operators
  // rebooted PHP-FPM. Gate it on the API confirming the cause:
  // `target_status === 'removed'` from `/api/targets/connector-status`.
  // Other 401/403s fall back to a generic inline message in the table area.
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
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666">No data</td></tr>';
        setText(msg,'Loaded 0');
        return;
      }
      for (var i=0;i<items.length;i++){
        var it = items[i];
        var tr = document.createElement('tr');
        tr.setAttribute('data-id', it.id || '');
        tr.innerHTML =
          '<td style="width:28px"><input type="checkbox" class="patcherly-row-cb" /></td>'+
          '<td>'+esc(fmtDate(it.created_at))+'</td>'+
          '<td>'+esc(it.severity||'')+'</td>'+
          '<td>'+formatStatus(it.status)+'</td>'+
          '<td>'+esc(it.language||'')+'</td>'+
          '<td class="patcherly-msg-cell">'+messageCellHtml(it.log_line||'')+'</td>'+
          '<td class="patcherly-row-actions">'+rowActionsHtml(it)+'</td>';
        tbody.appendChild(tr);
      }
      setText(msg,'Loaded '+items.length);
    }catch(e){
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:#666">No data</td></tr>';
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

  // v1.49.5 — per-status action set that mirrors
  // dashboard-next/app/(dashboard)/errors/page.tsx so any action the user
  // can drive from the dashboard table they can also drive from inside
  // wp-admin. Each button carries the canonical action name in
  // `data-act` so the click handler is one switch instead of N classes.
  function btn(act, label, cls){
    return '<button type="button" class="button-link ' + (cls || '') + '" data-act="' + act + '">' + esc(label) + '</button>';
  }
  function rowActionsHtml(it){
    var st = it.status || '';
    var html = '';
    // Analyze / re-analyze.
    if (st === 'pending' || st === 'analysis_failed') {
      html += btn('analyze', 'Analyze');
    }
    if (st === 'pending_analysis' || st === 'applying' || st === 'rolling_back') {
      html += '<span class="patcherly-row-busy" aria-label="Working…">…</span>';
    }
    // Preview fix.
    if (st === 'analyzed' || st === 'awaiting_approval' || st === 'manual_review_required' || st === 'approved') {
      html += btn('preview_fix', 'Preview');
    }
    // Accept / dismiss after analysis.
    if (st === 'analyzed') {
      html += btn('accept_fix', 'Accept fix');
      html += btn('dismiss',    'Dismiss', 'patcherly-warning-link');
    }
    if (st === 'awaiting_approval' || st === 'manual_review_required') {
      html += btn('apply_fix', 'Approve fix');
    }
    if (st === 'approved') {
      html += btn('apply_fix', 'Apply fix');
    }
    // Rollback / restore.
    if (st === 'fixed' || st === 'failed' || st === 'rollback_failed') {
      html += btn('rollback', 'Rollback', 'patcherly-warning-link');
    }
    if (st === 'ignored' || st === 'rolled_back' || st === 'restored' || st === 'dismissed') {
      html += btn('restore', 'Restore');
    }
    // Delete is always available.
    html += btn('delete', 'Delete', 'patcherly-danger-link');
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

    // Row actions — v1.49.5 dashboard-parity dispatcher. Buttons emit a
    // canonical `data-act` attribute (analyze, preview_fix, accept_fix,
    // apply_fix, rollback, restore, dismiss, delete); the table maps each
    // to the matching `patcherly_error_*` AJAX endpoint and refreshes (or
    // removes) the row on success.
    var tbody = $('patcherly-errors-tbody');
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
