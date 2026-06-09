(function(){
  var cfg = window.PATCHERLY_SETTINGS || { url: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '', ajaxNonce: '', adminNonce: '', clientId: '' };
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

  // ── OAuth device-grant flow ──────────────────────────────────────────────

  var oauthPollTimer = null;

  async function startOAuth(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-connect-oauth');
    if (btn) btn.disabled = true;
    setText($('patcherly-oauth-result'), 'Starting…');
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_start');
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var j = await r.json();
      if (!j.success) throw new Error((j.data && j.data.error) ? j.data.error : 'Failed to start OAuth');
      var d = j.data;
      // Show user_code + verification_uri
      setText($('patcherly-oauth-user-code'), d.user_code || '');
      var link = $('patcherly-oauth-verify-link');
      if (link) { link.href = d.verification_uri || '#'; link.textContent = d.verification_uri || ''; }
      var box = $('patcherly-oauth-pending');
      if (box) box.style.display = 'block';
      setText($('patcherly-oauth-result'), 'Waiting for approval…');
      // Poll for token
      oauthPollTimer = setInterval(function(){ pollOAuth(d.device_code); }, 5000);
    } catch(err) {
      setText($('patcherly-oauth-result'), 'Error: ' + (err.message || 'Unknown'));
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
      // Success path: the OAuth Device Grant token endpoint returns the
      // bundle directly (access_token, refresh_token, expires_at, ...).
      // The previous `j.data.status === 'authorized'` check was a leftover
      // from a different flow design and would never match — the entire
      // pairing UI hung forever even when the server-side authorization
      // had completed.
      if (r.ok && j.success && j.data && j.data.access_token) {
        clearInterval(oauthPollTimer); oauthPollTimer = null;
        var box = $('patcherly-oauth-pending');
        if (box) box.style.display = 'none';
        setText($('patcherly-oauth-result'), 'Connected!');
        setTimeout(function(){ location.reload(); }, 800);
        return;
      }
      // Hard error (502 etc.): stop polling and surface the message.
      if (!r.ok && r.status !== 202) {
        clearInterval(oauthPollTimer); oauthPollTimer = null;
        var msg = (j && j.data && j.data.error) ? j.data.error : ('HTTP ' + r.status);
        setText($('patcherly-oauth-result'), 'Pairing failed: ' + msg);
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
