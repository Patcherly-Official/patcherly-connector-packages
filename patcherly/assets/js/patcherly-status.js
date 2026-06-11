(function(){
  if (window.PatcherlyStatus) return;
  function setText(el, text){ if(el) el.textContent = text; }
  function setHTML(el, html){ if(el) el.innerHTML = html; }
  // Pull the shared admin AJAX nonce from whichever page-level localized
  // config object exists. Avoids a third localize call dedicated to status.
  function adminNonce(){
    var s = window.PATCHERLY_SETTINGS, e = window.PATCHERLY_ERRORS;
    return (s && s.adminNonce) || (e && e.adminNonce) || '';
  }
  function withAdminNonce(url){
    var n = adminNonce();
    if (!n) return url;
    return url + (url.indexOf('?') === -1 ? '?' : '&') + '_ajax_nonce=' + encodeURIComponent(n);
  }

  // v1.49.5 — formatters for the new minimal ConnectorStatus shape.
  // Kept inline so we don't pull in a shared "format" module just for the
  // four labels that appear in this one panel.
  function formatOAuth(status, expiresIso) {
    if (status === 'active')   return 'Active' + (expiresIso ? ' (until ' + formatDate(expiresIso) + ')' : '');
    if (status === 'expiring') return 'Expiring soon' + (expiresIso ? ' (' + formatDate(expiresIso) + ')' : '');
    if (status === 'expired')  return 'Expired';
    if (status === 'unknown')  return 'Not paired';
    return status || '—';
  }
  function formatTargetStatus(status) {
    if (status === 'active')   return ''; // success — no badge needed beyond the name
    if (status === 'removed')  return ' (removed on Patcherly)';
    return '';
  }
  function formatPluginVersion(cur, latest, outdated) {
    if (!cur) return '—';
    if (latest && outdated === true)  return cur + ' — update available (latest ' + latest + ')';
    if (latest && outdated === false) return cur + ' — up to date';
    return cur;
  }
  function formatDate(iso) {
    if (!iso) return '';
    try { return (new Date(iso)).toLocaleString(); }
    catch (_) { return iso; }
  }
  function badge(html, kind) {
    var cls = 'patcherly-status-badge patcherly-status-badge--' + (kind || 'neutral');
    return '<span class="' + cls + '">' + html + '</span>';
  }

  window.PatcherlyStatus = {
    init: function(prefix, serverUrl){
      var $ = function(id){ return document.getElementById(prefix + id); };
      var els = {
        api:            $('-api-status'),
        pluginVersion:  $('-plugin-version'),
        oauth:          $('-oauth'),
        hmac:           $('-hmac'),
        tenant:         $('-tenant'),
        target:         $('-target'),
        lastConnected:  $('-last-connected'),
        meta:           $('-status-meta'),
        btn:            $('-status-refresh')
      };
      var isRefreshing = false;

      function clearTable(message) {
        setText(els.api, '—');
        setText(els.pluginVersion, '—');
        setText(els.oauth, '—');
        setText(els.hmac, '—');
        setText(els.tenant, '—');
        setText(els.target, '—');
        setText(els.lastConnected, '—');
        setText(els.meta, message || 'Not checked yet.');
      }

      async function refresh(){
        if (isRefreshing) return;
        isRefreshing = true;
        if (!serverUrl){ setText(els.meta, 'No Patcherly Server URL configured.'); isRefreshing = false; return; }
        // v1.49.5 — every outbound check is routed through wp-admin/admin-ajax.php,
        // never directly to the Patcherly host. The PHP handler
        // (`ajax_smart_connect`) short-circuits with `step: need_oauth` when the
        // site isn't paired yet, so the plugin never phones home before the
        // operator clicks "Connect with Patcherly". WP.org reviewer contract:
        // tests/test-no-phone-home-before-pairing.php pins this.
        if (typeof ajaxurl === 'undefined') {
          setText(els.meta, 'WordPress admin-ajax not available.');
          isRefreshing = false;
          return;
        }
        setText(els.meta, 'Connecting…');
        try{
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_smart_connect'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if(!r.ok) throw new Error('HTTP '+r.status);
          var j = await r.json();

          if (j.success === false) {
            if (j.step === 'need_oauth') {
              clearTable(j.message || 'Use the Connect button to pair this site with Patcherly.');
              setHTML(els.oauth, badge('Not paired', 'warn'));
              return;
            }
            throw new Error(j.message || 'Connection failed');
          }

          var data = j.data || j;

          // API reachability — single boolean from the server.
          setHTML(els.api, data.api_ok ? badge('Reachable', 'ok') : badge('Unavailable', 'err'));

          // Plugin version vs latest released.
          setText(els.pluginVersion, formatPluginVersion(data.plugin_version, data.plugin_latest_version, data.plugin_outdated));

          // OAuth posture (active / expiring / expired / unknown).
          var oauthKind = 'neutral';
          if (data.oauth_status === 'active')   oauthKind = 'ok';
          if (data.oauth_status === 'expiring') oauthKind = 'warn';
          if (data.oauth_status === 'expired' || data.oauth_status === 'unknown') oauthKind = 'err';
          setHTML(els.oauth, badge(formatOAuth(data.oauth_status, data.oauth_expires_at), oauthKind));

          // HMAC signing — always on in v1.46+; we keep the row as a
          // visible reassurance to operators auditing the security posture.
          setHTML(els.hmac, data.hmac_enabled === false
            ? badge('Disabled', 'err')
            : badge('Enabled', 'ok'));

          // Workspace + Target.
          var tName = data.tenant_name ? String(data.tenant_name) : '—';
          if (data.tenant_status && data.tenant_status !== 'active') {
            tName += ' (' + data.tenant_status + ')';
          }
          setText(els.tenant, tName);

          var targetLabel;
          if (data.target_status === 'removed') {
            targetLabel = (data.target_name ? String(data.target_name) + ' ' : '') + '(removed on Patcherly)';
            setHTML(els.target, badge(targetLabel, 'err'));
          } else if (data.target_name) {
            targetLabel = String(data.target_name);
            setHTML(els.target, badge(targetLabel + formatTargetStatus(data.target_status), 'ok'));
          } else {
            setText(els.target, '—');
          }

          setText(els.lastConnected, data.last_connected_at ? formatDate(data.last_connected_at) : '—');

          window.__PATCHERLY_TENANT_ID__ = (data.tenant_id != null ? String(data.tenant_id) : (window.__PATCHERLY_TENANT_ID__ || null));
          window.__PATCHERLY_TARGET_ID__ = (data.target_id != null ? String(data.target_id) : (window.__PATCHERLY_TARGET_ID__ || null));
          window.__PATCHERLY_CURRENT_TARGET_ID__ = window.__PATCHERLY_TARGET_ID__;

          try{
            if (typeof ajaxurl !== 'undefined' && (data.tenant_id != null || data.target_id != null)){
              var fd = new FormData();
              fd.set('action','patcherly_save_ids');
              if (data.tenant_id != null) fd.set('tenant_id', String(data.tenant_id));
              if (data.target_id != null) fd.set('target_id', String(data.target_id));
              fd.set('_ajax_nonce', adminNonce());
              await fetch(ajaxurl, { method:'POST', body: fd });
            }
          }catch(_){ }

          var successMsg = 'Connected successfully';
          if (j.step === 'connected' && j.message) successMsg = j.message;
          setText(els.meta, successMsg + ' at ' + (new Date()).toLocaleString());
        }catch(e){
          var errorMsg = 'Check failed';
          if (e && e.message) {
            if (e.message.indexOf('503') !== -1) errorMsg = 'Service unavailable';
            else if (e.message.indexOf('502') !== -1) errorMsg = 'Bad gateway';
            else if (e.message.indexOf('504') !== -1) errorMsg = 'Gateway timeout';
            else if (e.message.indexOf('Failed to fetch') !== -1 || e.message.indexOf('NetworkError') !== -1) errorMsg = 'Connection failed';
            else errorMsg = e.message;
          }
          clearTable();
          setHTML(els.api, badge('Unavailable', 'err'));
          setText(els.meta, 'Check failed at ' + (new Date()).toLocaleString() + ': ' + errorMsg);
        } finally { isRefreshing = false; }
      }

      if (els.btn){ els.btn.addEventListener('click', function(ev){ ev.preventDefault(); refresh(); }); }
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(refresh, 150);
      } else {
        window.addEventListener('load', function(){ setTimeout(refresh, 150); });
      }
      if (!window.__PATCHERLY_STATUS__) window.__PATCHERLY_STATUS__ = {};
      window.__PATCHERLY_STATUS__[prefix] = { refresh: refresh };
    },
    refresh: function(prefix){ if (window.__PATCHERLY_STATUS__ && window.__PATCHERLY_STATUS__[prefix]) window.__PATCHERLY_STATUS__[prefix].refresh(); }
  };
})();
