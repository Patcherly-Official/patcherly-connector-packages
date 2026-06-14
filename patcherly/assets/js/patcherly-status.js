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
  // The OAuth row used to surface 'expiring' as a scary yellow badge that made
  // operators think they had to manually reconnect before some deadline. In
  // reality the bundle is auto-rotated inside the plugin's `sign_request()` ->
  // `maybe_refresh_oauth_bundle()` path on every signed call to Patcherly: as
  // soon as the access token gets within 30 s of `expires_at` the refresh_token
  // is used to mint a new bundle, and the rotation is invisible to the
  // operator. The only state that actually requires manual reconnection is
  // 'expired' (which means the refresh_token itself was revoked or aged out),
  // so we collapse 'active' and 'expiring' into one reassuring "Active
  // (auto-renews ...)" line.
  function formatOAuth(status, expiresIso) {
    if (status === 'active' || status === 'expiring') {
      // Both states are the SAME from the operator's POV -- the next signed call
      // either keeps using the current bundle ('active') or transparently mints a
      // new one ('expiring' = within the 30 s rotation window). We never want to
      // signal "you must reconnect" here.
      return expiresIso
        ? 'Active (auto-renews before ' + formatDate(expiresIso) + ')'
        : 'Active (auto-renews on the next signed call to Patcherly)';
    }
    if (status === 'expired')  return 'Expired — click Disconnect, then Connect with Patcherly again to re-pair';
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
    // 'Off' state is rendered separately (renderTestModeOff) so the
    // "Patcherly dashboard" portion can be wrapped in a real <a> tag
    // that opens /targets in a new tab. This function only returns the
    // 'On' label; the 'Off' caller handles its own HTML.
    return 'Off — open from Patcherly dashboard to send a sample event.';
  }
  // Renders the Test Mode 'Off' cell with the "Patcherly dashboard" words
  // wrapped in a real anchor that deep-links to /targets in a new tab.
  // Falls back to plain text if no dashboard URL is available so the
  // operator at least sees the prose even if the panel was rendered by an
  // older PHP build that didn't stamp `data-patcherly-dashboard-url`.
  function renderTestModeOff(cell, dashboardUrl) {
    if (!cell) return;
    if (!dashboardUrl) {
      cell.textContent = formatTestMode(false);
      return;
    }
    cell.textContent = '';
    cell.appendChild(document.createTextNode('Off — open from '));
    var a = document.createElement('a');
    a.href = dashboardUrl.replace(/\/+$/, '') + '/targets';
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = 'Patcherly dashboard';
    cell.appendChild(a);
    cell.appendChild(document.createTextNode(' to send a sample event.'));
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
      // Dashboard URL is server-derived (api.* -> app.*, apidev.* -> appdev.*)
      // and stamped onto the panel by render_status_module() so renderTestModeOff
      // can deep-link to /targets without duplicating the host-rewrite logic
      // in JS or requiring a separate localize call.
      var dashboardUrl = (els.panel && els.panel.getAttribute('data-patcherly-dashboard-url')) || '';
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
        renderTestModeOff(els.testMode, dashboardUrl);
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

          // Plugin version vs latest released. data.plugin_version is
          // injected server-side in ajax_smart_connect (the API itself
          // doesn't know the LOCAL plugin version). If a future refactor
          // forgets that injection we'd flip the PHP-rendered version to
          // '—' the moment the first refresh resolves -- defensive guard:
          // only overwrite the cell when we have a real value.
          if (data.plugin_version) {
            setText(els.pluginVersion, formatPluginVersion(data.plugin_version, data.plugin_latest_version, data.plugin_outdated));
          }

          // OAuth posture (active / expiring / expired / unknown).
          // 'expiring' is INTENTIONALLY collapsed into the 'ok' bucket because the
          // plugin's sign_request() -> maybe_refresh_oauth_bundle() path auto-rotates
          // the bundle 30 s before expiry. From the operator's POV both states are
          // "Active, will silently renew on the next signed call" -- surfacing
          // 'expiring' as a 'warn' badge produced a "scary yellow alarm" UX that
          // implied manual reconnection was required, when it wasn't. Only
          // 'expired' / 'unknown' (refresh_token itself dead or no bundle at all)
          // genuinely require operator action -- those stay 'err'.
          var oauthKind = 'neutral';
          if (data.oauth_status === 'active' || data.oauth_status === 'expiring') oauthKind = 'ok';
          if (data.oauth_status === 'expired' || data.oauth_status === 'unknown') oauthKind = 'err';
          setHTML(els.oauth, badge(formatOAuth(data.oauth_status, data.oauth_expires_at), oauthKind));

          // HMAC signing — always on; we keep the row as a
          // visible reassurance to operators auditing the security posture.
          setHTML(els.hmac, data.hmac_enabled === false
            ? badge('Disabled', 'err')
            : badge('Enabled', 'ok'));

          // Workspace + Target. Workspace mirrors the Target cell's badge
          // treatment for visual parity (operators were asking "is this
          // workspace actually attached or just a placeholder?" because the
          // plain-text rendering looked like an unresolved cell vs Target's
          // green pill). 'active' tenant_status -> emerald 'ok' badge;
          // anything else (e.g. 'suspended', 'pending') stays the badge but
          // flips to 'warn' kind AND surfaces the qualifier in parens so the
          // operator sees both the name and the non-active state at once.
          if (data.tenant_name) {
            var tName = String(data.tenant_name);
            var tenantNotActive = data.tenant_status && data.tenant_status !== 'active';
            if (tenantNotActive) {
              tName += ' (' + data.tenant_status + ')';
            }
            setHTML(els.tenant, badge(tName, tenantNotActive ? 'warn' : 'ok'));
          } else {
            setText(els.tenant, '—');
          }

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
            // 'Off' prose has "Patcherly dashboard" wrapped in a real
            // <a target="_blank" rel="noopener noreferrer"> deep-link to
            // /targets so the operator can jump straight to the page that
            // opens the per-target test window.
            //
            // Prefer the server-provided ``dashboard_url`` field from
            // /connector-status (added in v1.49.0 — the same actionable
            // URL the closed-window ``403 test_window_closed`` embeds in
            // its detail). Falls back to ``dashboardUrl`` read once at
            // init() from the panel data attribute (PHP-side
            // derive_dashboard_url() host-rewrite), so older API builds
            // that don't yet ship the field keep working unchanged.
            var off = (typeof data.dashboard_url === 'string' && data.dashboard_url) || dashboardUrl;
            renderTestModeOff(els.testMode, off);
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
