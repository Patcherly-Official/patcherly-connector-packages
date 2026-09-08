(function(){
  var cfg = window.PATCHERLY_SETTINGS || {
    url: '', dashboardUrl: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '',
    ajaxNonce: '', adminNonce: '', clientId: '', siteHost: '',
    stepLabels: {}, stepCopy: {}
  };
  function $(id){ return document.getElementById(id); }

  // Shared response helpers remain here for Settings diagnostics.
  function copy(key, fallback) {
    return (cfg.stepCopy && cfg.stepCopy[key]) || fallback;
  }

  function withAdminNonce(url){
    if (!cfg.adminNonce) return url;
    return url + (url.indexOf('?') === -1 ? '?' : '&') + '_ajax_nonce=' + encodeURIComponent(cfg.adminNonce);
  }

  function initStatus(){
    if (!window.PatcherlyStatus) return;
    if (document.getElementById('patcherly-status-panel')) window.PatcherlyStatus.init('patcherly', cfg.url);
    if (document.getElementById('patcherly-paths-status-panel')) window.PatcherlyStatus.init('patcherly-paths', cfg.url);
  }

  function refreshAllStatus(){
    if (!window.PatcherlyStatus) return;
    if (document.getElementById('patcherly-status-panel')) window.PatcherlyStatus.refresh('patcherly');
    if (document.getElementById('patcherly-paths-status-panel')) window.PatcherlyStatus.refresh('patcherly-paths');
  }

  var FRIENDLY_OAUTH_ERROR = {
    invalid_client: 'Patcherly doesn\'t recognise this site yet. Make sure it\'s added as a Site on your Patcherly dashboard, then try again.',
    invalid_request: 'Patcherly couldn\'t accept the connection request. Refresh the page and try again.',
    invalid_scope: 'The Patcherly API needs an update before this plugin version can connect. Try again in a few minutes - if it keeps failing, contact support.',
    unauthorized_client: 'This site isn\'t authorised to connect to Patcherly. Contact support if this looks wrong.',
    unsupported_grant_type: 'Patcherly couldn\'t process this connection method. Update the plugin and try again.',
    access_denied: 'Connection was declined at the Patcherly dashboard. Click Connect with Patcherly again to retry.',
    expired_token: 'The connection code expired before it was approved. Click Connect with Patcherly again to get a new code.',
    authorization_pending: 'Waiting for you to approve this site at the Patcherly dashboard…',
    slow_down: 'Slowing the connection check - your site will keep trying automatically.',
    target_not_registered: 'This site isn\'t on Patcherly yet. Sign up (or sign in), add it as a Site, then click Connect with Patcherly again.'
  };
  function prettifyErrorCode(code) {
    if (!code || typeof code !== 'string') return '';
    return code.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim().replace(/^./, function(c){ return c.toUpperCase(); });
  }
  function isApiDownFailure(status, payload) {
    if (status >= 500) return true;
    if (payload && typeof payload.http_code === 'number' && payload.http_code >= 500) return true;
    if (payload && typeof payload.error === 'string') {
      var lc = payload.error.toLowerCase();
      return lc.indexOf('upstream http 5') === 0 || lc.indexOf('connection failed') === 0 || lc.indexOf('request failed') === 0 || lc.indexOf('server error ') === 0;
    }
    return false;
  }
  function isFetchTransportError(err) {
    if (!err) return false;
    if (err.name === 'TypeError') return true;
    var msg = (err.message || '').toLowerCase();
    return msg.indexOf('failed to fetch') !== -1 || msg.indexOf('networkerror') !== -1 || msg.indexOf('load failed') !== -1 || msg.indexOf('network request failed') !== -1;
  }
  async function parseFailure(r) {
    var ctype = (r.headers.get('Content-Type') || '').toLowerCase();
    var payload = null;
    var message = '';
    if (ctype.indexOf('application/json') !== -1) {
      try {
        var j = await r.json();
        var data = (j && typeof j === 'object' && 'data' in j) ? j.data : j;
        payload = (data && typeof data === 'object') ? data : null;
        if (payload && typeof payload.message === 'string' && payload.message) message = payload.message;
        else if (payload && typeof payload.error === 'string' && payload.error) message = FRIENDLY_OAUTH_ERROR[payload.error] || prettifyErrorCode(payload.error);
      } catch (_) {}
    }
    var apiDown = isApiDownFailure(r.status, payload);
    if (apiDown) message = copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down - please try again in a few minutes.');
    else if (!message) {
      if (r.status === 0) {
        message = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.').replace('%s', copy('err_network_support', 'Patcherly Support'));
        apiDown = true;
      } else message = 'HTTP ' + r.status;
    }
    return { message: message, payload: payload, isApiDown: apiDown };
  }
  function apiDownError(parsed) {
    var error = new Error(parsed.message);
    error.isApiDown = !!parsed.isApiDown;
    return error;
  }
  // Diagnostics - each row owns a result panel keyed by `data-diag-result="<id>"`.
  // showDiagResult() writes a status line ('info'/'ok'/'fail') or a <pre> code block.
  function diagResultEl(id){
    return document.querySelector('[data-diag-result="' + id + '"]');
  }

  function showDiagResult(id, kind, text, opts){
    var el = diagResultEl(id);
    if (!el) return;
    el.removeAttribute('hidden');
    el.classList.remove('is-info', 'is-ok', 'is-fail');
    el.classList.add('is-' + (kind || 'info'));
    if (opts && opts.code) {
      // Code mode: build a <pre> with the textual payload so JSON dumps
      // retain whitespace + horizontal scrolling. textContent (not
      // innerHTML) keeps the payload safe even if a future server-side
      // hook puts raw HTML in there.
      el.innerHTML = '';
      var pre = document.createElement('pre');
      pre.className = 'patcherly-diagnostic-result__code';
      pre.textContent = text || '';
      el.appendChild(pre);
      return;
    }
    el.innerHTML = '';
    var body = document.createElement('div');
    body.className = 'patcherly-diagnostic-result__body';
    var line = document.createElement('span');
    line.className = 'patcherly-diagnostic-result__line';
    line.textContent = text || '';
    body.appendChild(line);
    if (opts && opts.contact) {
      var a = document.createElement('a');
      a.className = 'patcherly-diagnostic-result__contact';
      a.href = 'https://patcherly.com/contact';
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = copy('err_contact_cta', 'Contact Patcherly if the problem persists →');
      body.appendChild(a);
    }
    // dashboardUrl is rendered as an emerald CTA-style link - used when a
    // diagnostic needs a deep-link back to the dashboard (e.g. Test Mode toggle).
    if (opts && opts.dashboardUrl) {
      var d = document.createElement('a');
      d.className = 'patcherly-diagnostic-result__contact';
      d.href = String(opts.dashboardUrl);
      d.target = '_blank';
      d.rel = 'noopener noreferrer';
      d.textContent = (opts && opts.dashboardLabel) || copy('open_dashboard_cta', 'Open Patcherly dashboard →');
      body.appendChild(d);
    }
    el.appendChild(body);
  }

  async function testConnection(e){
    if(e) e.preventDefault();
    if(!cfg.url){ showDiagResult('test', 'fail', 'Missing Patcherly URL'); return false; }
    showDiagResult('test', 'info', 'Testing…');
    try {
      var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_test_connection'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) {
        var parsed = await parseFailure(r);
        throw apiDownError(parsed);
      }
      var j = await r.json();
      // When the site isn't paired yet the PHP handler falls back to the public
      // /health/summary probe, which only proves the API URL is reachable - not
      // that credentials are accepted. Render that as an info banner so the
      // operator isn't misled into thinking pairing succeeded.
      if (j && j.paired === false) {
        showDiagResult('test', 'info', copy('test_reachable_unpaired',
          'Patcherly API is reachable, but this site isn\'t connected yet. Connect from Home before testing the signed connection.'));
        if (window.PatcherlyStatus) refreshAllStatus();
        return false;
      }
      // Terse summary - full detail lives in the Connector Status table above.
      var bits = [];
      if (j.target_status) bits.push('target=' + j.target_status);
      if (j.oauth_status)  bits.push('oauth=' + j.oauth_status);
      showDiagResult('test', 'ok', 'OK' + (bits.length ? ' (' + bits.join(', ') + ')' : ''));
      if (window.PatcherlyStatus) refreshAllStatus();
    } catch(err){
      var down = (err && err.isApiDown) || isFetchTransportError(err);
      var msg = down
        ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down - please try again in a few minutes.')
        : (err && err.message ? err.message : 'error');
      showDiagResult('test', 'fail', msg, { contact: down });
    }
    return false;
  }

  // Advanced-settings deep-link - pops the <details> open, scrolls a row into view, briefly
  // highlights it. row-key currently supports "context-consent".
  function openAdvancedSetting(rowKey){
    var details = $('patcherly-advanced-details');
    if (!details) {
      var cfgLocal = window.PATCHERLY_SETTINGS || {};
      var settingsUrl = cfgLocal.settingsUrl || '';
      if (settingsUrl) {
        var hash = rowKey === 'rescue-mu' ? '#patcherly-advanced-rescue-mu' : '#patcherly-advanced-context-consent';
        window.location.href = settingsUrl + hash;
      }
      return;
    }
    if (details.tagName === 'DETAILS') {
      details.open = true;
    }
    var target = null;
    if (rowKey === 'context-consent') {
      var anchor = $('patcherly-advanced-context-consent');
      if (anchor) {
        target = anchor.closest('tr') || anchor;
      } else {
        var firstRadio = details.querySelector('input[type="radio"][name="patcherly_context_consent"]');
        if (firstRadio) {
          target = firstRadio.closest('tr') || firstRadio;
        }
      }
    } else if (rowKey === 'rescue-mu') {
      var rescueAnchor = $('patcherly-advanced-rescue-mu');
      if (rescueAnchor) {
        target = rescueAnchor.closest('tr') || rescueAnchor;
      }
    }
    var scrollTarget = target || details;
    try { scrollTarget.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (_) {}
    if (target && target.classList) {
      target.classList.add('patcherly-advanced-highlight');
      window.setTimeout(function(){ target.classList.remove('patcherly-advanced-highlight'); }, 1800);
    }
  }

  var siteContextLoadToken = 0;

  function formatContextSnapshot(data) {
    var lines = [];
    lines.push('Consent tier: ' + (data.consent || 'unknown'));
    if (data.last_upload_at) {
      lines.push('Last successful upload: ' + data.last_upload_at);
    }
    lines.push('');
    if (data.consent === 'off') {
      lines.push('Site context collection is Off - nothing is collected or uploaded.');
      return lines.join('\n');
    }
    if (data.consent === 'pending') {
      lines.push('No consent tier selected yet - choose Full, Minimal, or Off in Advanced settings.');
      return lines.join('\n');
    }
    if (data.site && data.site.context) {
      lines.push('=== ' + (data.site.label || 'On this site') + ' ===');
      lines.push(JSON.stringify(data.site.context, null, 2));
      lines.push('');
    }
    if (data.patcherly) {
      if (data.patcherly.empty) {
        lines.push('=== ' + (data.patcherly.label || 'Stored on Patcherly') + ' ===');
        lines.push(data.patcherly.message || 'No context uploaded yet.');
      } else {
        lines.push('=== ' + (data.patcherly.label || 'Stored on Patcherly') + ' ===');
        if (data.patcherly.updated_at) {
          lines.push('Updated: ' + data.patcherly.updated_at);
        }
        lines.push(JSON.stringify({
          context_type: data.patcherly.context_type,
          context_data: data.patcherly.context_data,
          server_context: data.patcherly.server_context,
          collected_at: data.patcherly.collected_at,
          updated_at: data.patcherly.updated_at
        }, null, 2));
      }
    } else if (data.patcherly_error) {
      lines.push('Could not read stored copy from Patcherly: ' + data.patcherly_error);
    } else if (!patcherly_oauth_is_paired_guess()) {
      lines.push('Pair this site to also see the last copy stored on Patcherly.');
    }
    return lines.join('\n');
  }

  function patcherly_oauth_is_paired_guess() {
    var panel = $('patcherly-status-panel');
    return !!(panel && panel.getAttribute('data-patcherly-paired') === '1');
  }

  async function loadSiteContextSnapshot(opts) {
    var panel = $('patcherly-site-context-panel');
    var statusEl = $('patcherly-site-context-status');
    var bodyEl = $('patcherly-site-context-body');
    if (!panel || !statusEl || !bodyEl) return;
    var token = ++siteContextLoadToken;
    statusEl.textContent = 'Loading…';
    bodyEl.hidden = true;
    bodyEl.textContent = '';
    try {
      var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_get_site_context_snapshot'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' }
      });
      if (!r.ok) throw new Error('HTTP ' + r.status);
      var j = await r.json();
      if (token !== siteContextLoadToken) return;
      if (j.success === false) {
        throw new Error(j.data && (j.data.error || j.data.message) ? (j.data.error || j.data.message) : 'Request failed');
      }
      var data = j.data || j;
      statusEl.textContent = 'Snapshot loaded at ' + (new Date()).toLocaleString() + '.';
      bodyEl.textContent = formatContextSnapshot(data);
      bodyEl.hidden = false;
      if (opts && opts.scroll) {
        try { panel.scrollIntoView({ behavior: 'smooth', block: 'start' }); } catch (_) {}
      }
    } catch (err) {
      if (token !== siteContextLoadToken) return;
      statusEl.textContent = 'Could not load context snapshot: ' + (err && err.message ? err.message : 'error');
      bodyEl.hidden = true;
    }
  }

  function openSiteContextPanel() {
    var panel = $('patcherly-site-context-panel');
    if (!panel) return;
    panel.open = true;
    loadSiteContextSnapshot({ scroll: true });
  }

  function submitWpconfigApply() {
    var applyCfg = cfg.wpconfigApply || {};
    var postUrl = applyCfg.postUrl || '';
    if (!postUrl) return;
    var wrap = document.getElementById('patcherly-advanced-rescue-wpconfig');
    var fieldName = applyCfg.autowriteField || 'patcherly_rescue_wpconfig_autowrite';
    var cb = wrap && wrap.querySelector('input[name="' + fieldName + '"]');
    var form = document.createElement('form');
    form.method = 'post';
    form.action = postUrl;
    form.style.display = 'none';
    function addHidden(name, value) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    addHidden('action', 'patcherly_rescue_apply_wpconfig');
    if (applyCfg.nonce) addHidden('_wpnonce', applyCfg.nonce);
    addHidden(fieldName, (cb && cb.checked) ? '1' : '0');
    document.body.appendChild(form);
    form.submit();
  }

  function submitRootHtaccessApply() {
    var applyCfg = cfg.rootHtaccessApply || {};
    var postUrl = applyCfg.postUrl || '';
    if (!postUrl) return;
    var wrap = document.getElementById('patcherly-advanced-storage-hardening');
    var fieldName = applyCfg.autowriteField || 'patcherly_root_htaccess_autowrite';
    var cb = wrap && wrap.querySelector('input[name="' + fieldName + '"]');
    var form = document.createElement('form');
    form.method = 'post';
    form.action = postUrl;
    form.style.display = 'none';
    function addHidden(name, value) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    addHidden('action', 'patcherly_rescue_apply_root_htaccess');
    if (applyCfg.nonce) addHidden('_wpnonce', applyCfg.nonce);
    addHidden(fieldName, (cb && cb.checked) ? '1' : '0');
    document.body.appendChild(form);
    form.submit();
  }

  function submitBackupPurge() {
    var purgeCfg = cfg.backupPurge || {};
    var postUrl = purgeCfg.postUrl || '';
    if (!postUrl) return;
    var msg = purgeCfg.confirm || 'Delete all file backups? Rollback will no longer be possible.';
    if (!window.confirm(msg)) return;
    var form = document.createElement('form');
    form.method = 'post';
    form.action = postUrl;
    form.style.display = 'none';
    function addHidden(name, value) {
      var input = document.createElement('input');
      input.type = 'hidden';
      input.name = name;
      input.value = value;
      form.appendChild(input);
    }
    addHidden('action', 'patcherly_purge_backups');
    if (purgeCfg.nonce) addHidden('_wpnonce', purgeCfg.nonce);
    document.body.appendChild(form);
    form.submit();
  }

  function bind(){
    var t = $('patcherly-form-test'); if (t) t.addEventListener('submit', testConnection);

    var applyWpconfigBtn = $('patcherly-btn-apply-wpconfig');
    if (applyWpconfigBtn) {
      applyWpconfigBtn.addEventListener('click', function (e) {
        e.preventDefault();
        submitWpconfigApply();
      });
    }

    var applyRootHtaccessBtn = $('patcherly-btn-apply-root-htaccess');
    if (applyRootHtaccessBtn) {
      applyRootHtaccessBtn.addEventListener('click', function (e) {
        e.preventDefault();
        submitRootHtaccessApply();
      });
    }

    var purgeBackupsBtn = $('patcherly-btn-purge-backups');
    if (purgeBackupsBtn) {
      purgeBackupsBtn.addEventListener('click', function (e) {
        e.preventDefault();
        submitBackupPurge();
      });
    }

    var resyncBtn = $('patcherly-btn-force-resync');
    if (resyncBtn) {
      resyncBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        showDiagResult('resync', 'info', 'Resyncing…');
        try {
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_force_resync'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) {
            var parsed = await parseFailure(r);
            throw apiDownError(parsed);
          }
          var j = await r.json();
          if (j.success === false) {
            showDiagResult('resync', 'fail', j.message || 'Unknown error');
          } else {
            showDiagResult('resync', 'ok', 'Resync completed successfully');
            if (window.PatcherlyStatus) refreshAllStatus();
          }
        } catch(err) {
          var down = (err && err.isApiDown) || isFetchTransportError(err);
          var msg = down
            ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down - please try again in a few minutes.')
            : (err && err.message ? err.message : 'error');
          showDiagResult('resync', 'fail', msg, { contact: down });
        }
      });
    }

    var debugBtn = $('patcherly-btn-debug-endpoints');
    if (debugBtn) {
      debugBtn.addEventListener('click', async function(e) {
        e.preventDefault();
        showDiagResult('endpoints', 'info', 'Fetching…');
        try {
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_debug_endpoints'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) {
            var parsed = await parseFailure(r);
            throw apiDownError(parsed);
          }
          var j = await r.json();
          showDiagResult('endpoints', 'ok', JSON.stringify(j, null, 2), { code: true });
        } catch(err) {
          var down = (err && err.isApiDown) || isFetchTransportError(err);
          var msg = down
            ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down - please try again in a few minutes.')
            : (err && err.message ? err.message : 'error');
          showDiagResult('endpoints', 'fail', msg, { contact: down });
        }
      });
    }

    // Anchored deep-link from Connector Status → "Context sharing" row.
    // We intercept the click so the page doesn't jump to a non-existent
    // fragment; openAdvancedSetting() pops <details> open and scrolls.
    document.addEventListener('click', function(e){
      var showCtx = e.target && e.target.closest ? e.target.closest('[data-patcherly-show-context]') : null;
      if (showCtx) {
        e.preventDefault();
        openSiteContextPanel();
        return;
      }
      var link = e.target && e.target.closest ? e.target.closest('[data-patcherly-open-advanced]') : null;
      if (!link) return;
      e.preventDefault();
      openAdvancedSetting(link.getAttribute('data-patcherly-open-advanced') || '');
    });

    var ctxPanel = $('patcherly-site-context-panel');
    if (ctxPanel) {
      ctxPanel.addEventListener('toggle', function(){
        if (ctxPanel.open && !ctxPanel.getAttribute('data-patcherly-loaded')) {
          ctxPanel.setAttribute('data-patcherly-loaded', '1');
          loadSiteContextSnapshot({ scroll: false });
        }
      });
    }

    var hash = window.location.hash ? window.location.hash.replace(/^#/, '') : '';
    if (hash === 'patcherly-advanced-context-consent') {
      openAdvancedSetting('context-consent');
    } else if (hash === 'patcherly-advanced-rescue-mu') {
      openAdvancedSetting('rescue-mu');
    }
  }

  if (document.readyState === 'complete') { initStatus(); bind(); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); }); }
})();
