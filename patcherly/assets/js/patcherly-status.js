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

  // Inline formatters for the minimal ConnectorStatus shape (kept inline — only four labels).
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
  function formatTestMode(enabled, expiresIso) {
    if (enabled === true) {
      return expiresIso
        ? 'On — window closes ' + formatDate(expiresIso)
        : 'On';
    }
    return 'Off — open from Patcherly dashboard to send a sample event.';
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

  // Mirrors the placeholder PHP renders into HMAC / Workspace / Target /
  // Last connected / Test Mode rows when the site is unpaired (see
  // ``render_status_module``). Kept in sync by the connector-status-shape
  // test so a copy drift on one side fails CI immediately.
  var UNPAIRED_PLACEHOLDER = 'Site not connected yet, pair it with Patcherly to run Diagnostics';

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
        testMode:       $('-test-mode'),
        meta:           $('-status-meta'),
        btn:            $('-status-refresh'),
        panel:          $('-status-panel')
      };
      // Read paired-state once at init from the data attribute PHP stamped on
      // the panel. Lets the JS distinguish "user has not paired yet"
      // (preserve server-rendered placeholders, only update the API row from
      // an explicit Refresh probe) from "paired and we expect live data".
      var initialPaired = els.panel && els.panel.getAttribute('data-patcherly-paired') === '1';
      var isRefreshing = false;

      // Wipe the table only when we actually have a paired site whose
      // round-trip failed — for unpaired sites we leave PHP's server-rendered
      // "Site not connected yet, pair it..." copy in place so the operator
      // gets the helpful hint instead of a wall of em-dashes.
      function clearTable(message) {
        setText(els.api, '—');
        setText(els.pluginVersion, '—');
        setText(els.oauth, '—');
        setText(els.hmac, '—');
        setText(els.tenant, '—');
        setText(els.target, '—');
        setText(els.lastConnected, '—');
        setText(els.testMode, formatTestMode(false, null));
        setText(els.meta, message || 'Not checked yet.');
      }

      // Refresh the unpaired panel without trashing the server-rendered
      // placeholders. Only the API row + meta line are touched; OAuth stays
      // "Not paired", every other row keeps the UNPAIRED_PLACEHOLDER copy.
      function renderUnpaired(payload) {
        setHTML(els.oauth, badge('Not paired', 'warn'));
        // Don't overwrite Plugin version — PHP rendered the real version from
        // the plugin header and we want that visible regardless of pairing.
        setText(els.hmac, UNPAIRED_PLACEHOLDER);
        setText(els.tenant, UNPAIRED_PLACEHOLDER);
        setText(els.target, UNPAIRED_PLACEHOLDER);
        setText(els.lastConnected, UNPAIRED_PLACEHOLDER);
        setText(els.testMode, UNPAIRED_PLACEHOLDER);

        // The API row is the one piece of live data we *do* fetch for an
        // unpaired site, but only when the user clicked Refresh (server
        // gates the probe on POST['probe_health']=1 — see ajax_smart_connect).
        if (payload && typeof payload.api_ok === 'boolean') {
          setHTML(els.api, payload.api_ok ? badge('Reachable', 'ok') : badge('Unavailable', 'err'));
          var cacheNote = payload.api_cache_hit ? ' (cached)' : '';
          var when = payload.api_probed_at ? (' at ' + formatDate(payload.api_probed_at)) : '';
          var detail = payload.api_ok ? ('Patcherly API reachable' + when + cacheNote)
                                      : ('Patcherly API unavailable' + when + (payload.api_error ? ' — ' + payload.api_error : ''));
          setText(els.meta, detail + '. ' + (payload.message || 'Pair this site to run the full diagnostics.'));
        } else {
          // No probe was requested this round (auto-load) — leave API as the
          // server-rendered "—" and surface the helpful "click Refresh" hint
          // in the meta line.
          setText(els.api, '—');
          setText(els.meta, payload && payload.message ? payload.message : 'Not connected. Use the Connect button to pair this site with Patcherly.');
        }
      }

      async function refresh(opts){
        if (isRefreshing) return;
        isRefreshing = true;
        var isManual = !!(opts && opts.manual);
        if (!serverUrl){ setText(els.meta, 'No Patcherly Server URL configured.'); isRefreshing = false; return; }
        // Every check goes through admin-ajax → ajax_smart_connect; never directly to the Patcherly
        // host. Pinned by tests/test-no-phone-home-before-pairing.php.
        if (typeof ajaxurl === 'undefined') {
          setText(els.meta, 'WordPress admin-ajax not available.');
          isRefreshing = false;
          return;
        }
        // Don't blank the meta line for the silent auto-load on an unpaired
        // site — the PHP-rendered "Not connected. Use the Connect button…"
        // hint is more useful than a transient "Connecting…" flicker.
        if (initialPaired || isManual) {
          setText(els.meta, 'Connecting…');
        }
        try{
          // Manual click opts in to a public /health/summary probe so the
          // unpaired operator can confirm "is the Patcherly API up?"
          // without pairing first. Auto-load stays silent (no probe param).
          var url = ajaxurl + '?action=patcherly_smart_connect';
          var body = isManual ? 'probe_health=1' : '';
          var r = await fetch(withAdminNonce(url), {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body
          });
          if(!r.ok) throw new Error('HTTP '+r.status);
          var j = await r.json();

          if (j.success === false) {
            if (j.step === 'need_oauth') {
              renderUnpaired(j);
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

          // HMAC signing — always on; we keep the row as a
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

          // Test Mode (v1.49.0). ingest_test_enabled comes from
          // /targets/connector-status; emerald ON badge when the window is
          // open, plain "Off + dashboard prompt" otherwise. Wrapped in the
          // shared badge() helper so the visual matches HMAC/OAuth posture
          // rows.
          var testEnabled = data.ingest_test_enabled === true;
          if (testEnabled) {
            setHTML(els.testMode, badge(formatTestMode(true, data.ingest_test_expires_at), 'ok'));
          } else {
            setText(els.testMode, formatTestMode(false, null));
          }

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
          // Preserve the unpaired-state placeholders on transport failure —
          // wiping them and showing "—" loses the helpful "Site not connected
          // yet, pair it..." copy the operator was looking at.
          if (initialPaired) {
            clearTable();
          }
          setHTML(els.api, badge('Unavailable', 'err'));
          setText(els.meta, 'Check failed at ' + (new Date()).toLocaleString() + ': ' + errorMsg);
        } finally { isRefreshing = false; }
      }

      if (els.btn){ els.btn.addEventListener('click', function(ev){ ev.preventDefault(); refresh({ manual: true }); }); }
      if (document.readyState === 'complete' || document.readyState === 'interactive') {
        setTimeout(function(){ refresh({ manual: false }); }, 150);
      } else {
        window.addEventListener('load', function(){ setTimeout(function(){ refresh({ manual: false }); }, 150); });
      }
      if (!window.__PATCHERLY_STATUS__) window.__PATCHERLY_STATUS__ = {};
      window.__PATCHERLY_STATUS__[prefix] = { refresh: refresh };
    },
    refresh: function(prefix){ if (window.__PATCHERLY_STATUS__ && window.__PATCHERLY_STATUS__[prefix]) window.__PATCHERLY_STATUS__[prefix].refresh({ manual: true }); }
  };
})();
