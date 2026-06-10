(function(){
  var cfg = window.PATCHERLY_SETTINGS || {
    url: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '',
    ajaxNonce: '', adminNonce: '', clientId: '',
    stepLabels: {}, stepCopy: {}
  };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }
  // Append the shared admin AJAX nonce to a query-string URL. Used by every
  // non-OAuth call (the OAuth flow has its own dedicated nonce).
  function withAdminNonce(url){
    if (!cfg.adminNonce) return url;
    return url + (url.indexOf('?') === -1 ? '?' : '&') + '_ajax_nonce=' + encodeURIComponent(cfg.adminNonce);
  }

  function initStatus(){
    if (window.PatcherlyStatus) window.PatcherlyStatus.init('patcherly', cfg.url);
  }

  // ── OAuth pairing step engine ────────────────────────────────────────────
  //
  // The PHP renders an empty `<ol id="patcherly-oauth-steps">`. This engine
  // populates it during the OAuth round-trip so the user gets clear,
  // human-readable feedback ("Contacting the Patcherly API ✓", "Waiting for
  // you to approve at the dashboard…", etc.) instead of a silent spinner.

  var STEP_IDS = ['contact', 'device', 'approve', 'save', 'done'];
  function L(id) {
    return (cfg.stepLabels && cfg.stepLabels[id]) || id;
  }
  function copy(key, fallback) {
    return (cfg.stepCopy && cfg.stepCopy[key]) || fallback;
  }

  function renderSteps() {
    var ol = $('patcherly-oauth-steps');
    if (!ol) return;
    ol.innerHTML = '';
    STEP_IDS.forEach(function(id) {
      var li = document.createElement('li');
      li.setAttribute('data-step', id);
      li.className = 'is-pending';
      var dot = document.createElement('span');
      dot.className = 'patcherly-step__dot';
      dot.setAttribute('aria-hidden', 'true');
      var label = document.createElement('span');
      label.className = 'patcherly-step__label';
      label.textContent = L(id);
      var detail = document.createElement('span');
      detail.className = 'patcherly-step__detail';
      detail.setAttribute('data-role', 'detail');
      var body = document.createElement('div');
      body.appendChild(label);
      body.appendChild(detail);
      li.appendChild(dot);
      li.appendChild(body);
      ol.appendChild(li);
    });
  }
  function setStep(id, state, detail) {
    var ol = $('patcherly-oauth-steps');
    if (!ol) return;
    var li = ol.querySelector('li[data-step="' + id + '"]');
    if (!li) return;
    li.classList.remove('is-pending', 'is-running', 'is-success', 'is-error');
    li.classList.add('is-' + state);
    if (typeof detail === 'string') {
      var d = li.querySelector('[data-role="detail"]');
      if (d) d.textContent = detail;
    }
  }
  function showSteps() {
    var ol = $('patcherly-oauth-steps');
    if (!ol) return;
    ol.hidden = false;
    try { ol.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}
  }
  function hideSteps() {
    var ol = $('patcherly-oauth-steps');
    if (ol) { ol.hidden = true; }
  }

  // ── OAuth device-grant flow ──────────────────────────────────────────────

  var oauthPollTimer = null;

  async function startOAuth(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-connect-oauth');
    if (btn) btn.disabled = true;
    renderSteps();
    showSteps();
    setStep('contact', 'running');
    setText($('patcherly-oauth-result'), '');
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_start');
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) {
        var bodyText = '';
        try { bodyText = await r.text(); } catch (_) {}
        var hint = '';
        if (r.status === 502 || r.status === 503 || r.status === 504) {
          hint = ' (your own site replied ' + r.status + ' — usually a transient PHP-FPM hiccup or an outdated plugin; reload and try again)';
        }
        throw new Error('HTTP ' + r.status + (bodyText ? ': ' + bodyText.slice(0, 200) : '') + hint);
      }
      var j = await r.json();
      if (!j.success) throw new Error((j.data && j.data.error) ? j.data.error : 'Failed to start OAuth');
      var d = j.data;
      // Step 1 succeeded: we have a server URL pinned + a device code.
      setStep('contact', 'success', (copy('connected_to', 'Connected to') + ' ' + (d.server_url || cfg.url || 'api.patcherly.com')));
      setStep('device', 'success', d.user_code ? (copy('code_label', 'Code') + ': ' + d.user_code) : '');
      // Show user_code + verification_uri (legacy block still rendered).
      setText($('patcherly-oauth-user-code'), d.user_code || '');
      var link = $('patcherly-oauth-verify-link');
      if (link) { link.href = d.verification_uri || '#'; link.textContent = d.verification_uri || ''; }
      var box = $('patcherly-oauth-pending');
      if (box) box.style.display = 'block';
      setStep('approve', 'running', d.verification_uri ? (copy('open_at', 'Open at') + ': ' + d.verification_uri) : '');
      // Poll for token
      oauthPollTimer = setInterval(function(){ pollOAuth(d.device_code); }, 5000);
    } catch(err) {
      setStep('contact', 'error', (err && err.message) ? err.message : 'Unknown error');
      setText($('patcherly-oauth-result'), copy('pairing_error', 'Pairing failed') + ': ' + (err.message || 'Unknown'));
      if (btn) btn.disabled = false;
    }
  }

  async function pollOAuth(deviceCode){
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_poll');
      fd.set('device_code', deviceCode);
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      // 202 = authorization_pending / slow_down, keep polling silently
      if (r.status === 202) return;
      var j = await r.json().catch(function(){ return {}; });
      if (r.ok && j.success && j.data && j.data.access_token) {
        clearInterval(oauthPollTimer); oauthPollTimer = null;
        var box = $('patcherly-oauth-pending');
        if (box) box.style.display = 'none';
        setStep('approve', 'success');
        setStep('save', 'running');
        // The bundle is already persisted server-side by the PHP handler
        // before it sends the success response, so jump straight to done.
        setStep('save', 'success');
        setStep('done', 'success', copy('pairing_done', 'All set — reloading the page.'));
        setText($('patcherly-oauth-result'), copy('pairing_done', 'All set — reloading the page.'));
        setTimeout(function(){ location.reload(); }, 1000);
        return;
      }
      // Hard error (502 etc.): stop polling and surface the message.
      if (!r.ok && r.status !== 202) {
        clearInterval(oauthPollTimer); oauthPollTimer = null;
        var msg = (j && j.data && j.data.error) ? j.data.error : ('HTTP ' + r.status);
        setStep('approve', 'error', msg);
        setText($('patcherly-oauth-result'), copy('pairing_error', 'Pairing failed') + ': ' + msg);
        var btn = $('patcherly-btn-connect-oauth');
        if (btn) btn.disabled = false;
      }
    } catch(_){ }
  }

  async function refreshContext(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-refresh-context');
    if (btn) btn.disabled = true;
    setText($('patcherly-oauth-result'), 'Refreshing site context…');
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_refresh_context');
      fd.set('_ajax_nonce', cfg.adminNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      var j = await r.json().catch(function(){ return {}; });
      if (!r.ok || !j.success) {
        var msg = (j && j.data && j.data.error) ? j.data.error : ('HTTP ' + r.status);
        throw new Error(msg);
      }
      setText($('patcherly-oauth-result'), 'Site context refreshed.');
    } catch(err) {
      setText($('patcherly-oauth-result'), 'Refresh failed: ' + (err.message || 'Unknown'));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function disconnectOAuth(e){
    if (e) e.preventDefault();
    if (!confirm('Disconnect Patcherly OAuth? This site will no longer send errors until re-paired.')) return;
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_disconnect');
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      hideSteps();
      setText($('patcherly-oauth-result'), 'Disconnected.');
      setTimeout(function(){ location.reload(); }, 600);
    } catch(err) {
      setText($('patcherly-oauth-result'), 'Error: ' + (err.message || 'Unknown'));
    }
  }

  // ── Other settings actions ───────────────────────────────────────────────

  async function testConnection(e){
    if(e) e.preventDefault();
    if(!cfg.url){ setText($('patcherly-test-result'),'Missing Patcherly URL'); return false; }
    setText($('patcherly-test-result'),'Testing…');
    try {
      var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_test_connection'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) throw new Error('HTTP '+r.status);
      var j = await r.json();
      var dbt = (j.database_type) || '';
      var deploy = (j.deployment_type) || '';
      setText($('patcherly-test-result'), 'OK' + ((dbt||deploy)?(' ('+ [dbt&&('db='+dbt), deploy&&('deploy='+deploy)].filter(Boolean).join(', ') +')') : ''));
      if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
    } catch(err){ setText($('patcherly-test-result'),'Failed: '+(err&&err.message?err.message:'error')); }
    return false;
  }

  async function sendSample(e){
    if(e) e.preventDefault();
    if(!cfg.url){ setText($('patcherly-sample-result'),'Missing Patcherly URL'); return false; }
    if(!cfg.oauthConnected){ setText($('patcherly-sample-result'),'Not connected — use Connect button first'); return false; }
    setText($('patcherly-sample-result'),'Sending…');
    try{
      var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_send_sample'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) {
        var errorData = await r.json().catch(function(){ return {}; });
        var errorMsg = errorData.data && errorData.data.error ? errorData.data.error : ('HTTP ' + r.status);
        throw new Error(errorMsg);
      }
      var result = await r.json();
      if (result.success) {
        setText($('patcherly-sample-result'), result.data && result.data.message ? result.data.message : 'Ingested successfully');
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
      } else {
        throw new Error(result.data && result.data.error ? result.data.error : 'Unknown error');
      }
    }catch(err){ setText($('patcherly-sample-result'),'Failed: '+(err&&err.message?err.message:'error')); }
    return false;
  }

  function bind(){
    var t = $('patcherly-form-test'); if (t) t.addEventListener('submit', testConnection);
    var s = $('patcherly-form-sample'); if (s) s.addEventListener('submit', sendSample);

    var connectBtn = $('patcherly-btn-connect-oauth');
    if (connectBtn) connectBtn.addEventListener('click', startOAuth);

    var disconnectBtn = $('patcherly-btn-disconnect-oauth');
    if (disconnectBtn) disconnectBtn.addEventListener('click', disconnectOAuth);

    var refreshCtxBtn = $('patcherly-btn-refresh-context');
    if (refreshCtxBtn) refreshCtxBtn.addEventListener('click', refreshContext);

    var resyncBtn = $('patcherly-btn-force-resync');
    if (resyncBtn) {
      resyncBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        setText($('patcherly-resync-result'), 'Resyncing…');
        try {
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_force_resync'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          if (j.success === false) {
            setText($('patcherly-resync-result'), 'Failed: ' + (j.message || 'Unknown error'));
          } else {
            setText($('patcherly-resync-result'), 'Resync completed successfully');
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(err) {
          setText($('patcherly-resync-result'), 'Failed: ' + (err.message || 'error'));
        }
      });
    }

    var debugBtn = $('patcherly-btn-debug-endpoints');
    if (debugBtn) {
      debugBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        try {
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_debug_endpoints'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) throw new Error('HTTP ' + r.status);
          var j = await r.json();
          var debugInfo = $('patcherly-debug-info');
          var debugContent = $('patcherly-debug-content');
          if (debugInfo && debugContent) {
            debugContent.textContent = JSON.stringify(j, null, 2);
            debugInfo.style.display = 'block';
          }
        } catch(err) {
          alert('Debug failed: ' + (err.message || 'error'));
        }
      });
    }
  }

  if (document.readyState === 'complete') { initStatus(); bind(); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); }); }
})();
