(function(){
  var cfg = window.PATCHERLY_SETTINGS || {
    url: '', dashboardUrl: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '',
    ajaxNonce: '', adminNonce: '', clientId: '', siteHost: '',
    stepLabels: {}, stepCopy: {}
  };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }

  // v1.49.x — derive the Patcherly Dashboard URL from the configured API
  // URL when the server hasn't already supplied one (e.g. when the error
  // path doesn't promote `targets_url` in the structured detail body).
  // Mirror of `Patcherly_Connector_Plugin::derive_dashboard_url()` in
  // patcherly.php. We always prefer the PHP-localized `cfg.dashboardUrl`,
  // and only fall through to this if cfg is missing (extension blocked
  // the localize_script payload, browser dev-tools clobbered it, …).
  //
  //   apidev.patcherly.com → https://appdev.patcherly.com
  //   api.patcherly.com    → https://app.patcherly.com
  //   anything else        → https://app.patcherly.com (safe default)
  function deriveDashboardUrl(apiUrl) {
    var fallback = 'https://app.patcherly.com';
    if (typeof apiUrl !== 'string' || !apiUrl) return fallback;
    var candidate = apiUrl.indexOf('://') === -1 ? ('https://' + apiUrl) : apiUrl;
    var host = '';
    try { host = (new URL(candidate)).hostname.toLowerCase(); } catch (_) { return fallback; }
    if (!host) return fallback;
    if (host.indexOf('apidev.') === 0) return 'https://appdev.patcherly.com';
    if (host.indexOf('api.') === 0)    return 'https://app.patcherly.com';
    return fallback;
  }

  function patcherlyDashboardUrl() {
    return (typeof cfg.dashboardUrl === 'string' && cfg.dashboardUrl) ? cfg.dashboardUrl : deriveDashboardUrl(cfg.url);
  }
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

  // ── Friendly response parsing ────────────────────────────────────────────
  //
  // v1.49.5 — NEVER dump raw response bodies into the step list. WordPress
  // sometimes proxies upstream HTML 502 pages from Render through admin-ajax,
  // and the old code surfaced "HTTP 502: <!DOCTYPE html><html>…" verbatim
  // into the result span. The helper below:
  //   1. Refuses to read bodies whose Content-Type is `text/html`.
  //   2. Decodes a JSON body when present and pulls a structured message
  //      out (admin-ajax wraps errors in {success:false, data:{...}}).
  //   3. Falls back to friendly bucketed messages by status code.
  // Returns `{ message, payload }` where `payload` is the structured
  // `data.detail` object (if any) so callers can act on it (e.g. show the
  // target_not_registered CTA without parsing free-text).

  // v1.49.5 — friendly mapper for OAuth 2.0 Device Authorization Grant
  // error codes (RFC 8628 §3.5 + the structured Patcherly extensions).
  // Anything not in this table falls back to a generic, capitalised
  // version of the code so the user never sees raw snake_case jargon.
  var FRIENDLY_OAUTH_ERROR = {
    invalid_client: 'Patcherly doesn\'t recognise this site yet. Make sure it\'s added as a Target on your Patcherly dashboard, then try again.',
    invalid_request: 'Patcherly couldn\'t accept the pairing request. Refresh the page and try again.',
    unauthorized_client: 'This site isn\'t authorised to pair with Patcherly. Contact support if this looks wrong.',
    unsupported_grant_type: 'Patcherly couldn\'t process this pairing method. Update the plugin and try again.',
    access_denied: 'Pairing was declined at the Patcherly dashboard. Click Connect with Patcherly again to retry.',
    expired_token: 'The pairing code expired before it was approved. Click Connect with Patcherly again to get a new code.',
    authorization_pending: 'Waiting for you to approve this site at the Patcherly dashboard…',
    slow_down: 'Slowing the pairing check — your site will keep trying automatically.',
    target_not_registered: 'This site isn\'t on Patcherly yet. Sign up (or sign in), add it as a Target, then click Connect with Patcherly again.'
  };
  function prettifyErrorCode(code) {
    if (!code || typeof code !== 'string') return '';
    return code
      .replace(/[_-]+/g, ' ')
      .replace(/\s+/g, ' ')
      .trim()
      .replace(/^./, function(c){ return c.toUpperCase(); });
  }

  async function parseFailure(r) {
    var ctype = (r.headers.get('Content-Type') || '').toLowerCase();
    var payload = null;
    var message = '';
    if (ctype.indexOf('application/json') !== -1) {
      try {
        var j = await r.json();
        // admin-ajax wraps errors as `{ success:false, data:{...} }`.
        var data = (j && typeof j === 'object' && 'data' in j) ? j.data : j;
        payload = (data && typeof data === 'object') ? data : null;
        if (payload) {
          // Order of preference:
          //   1. Server-supplied human message (FastAPI `detail.message`).
          //   2. Friendly mapping of the structured error code.
          //   3. Prettified version of the raw error code.
          if (typeof payload.message === 'string' && payload.message) {
            message = payload.message;
          } else if (typeof payload.error === 'string' && payload.error) {
            message = FRIENDLY_OAUTH_ERROR[payload.error] || prettifyErrorCode(payload.error);
          }
        }
      } catch (_) { /* fall through to bucketed message */ }
    }
    if (!message) {
      if (r.status === 502 || r.status === 503 || r.status === 504) {
        message = copy('err_bad_gateway', 'Your own site briefly couldn\'t talk to Patcherly. Reload and try again.');
      } else if (r.status >= 500) {
        message = copy('err_server', 'Patcherly API is having trouble — try again in a minute.');
      } else if (r.status === 0) {
        message = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection.');
      } else {
        message = 'HTTP ' + r.status;
      }
    }
    return { message: message, payload: payload };
  }

  // v1.49.x — error codes whose root cause is "this site isn't registered
  // as a Patcherly Target". The pairing UI surfaces the inline message in
  // the contact step PLUS an actionable "Open Patcherly Targets →" link
  // directly underneath it, so the operator never has to read the error,
  // hunt for the dashboard URL, and type it into the address bar.
  //   target_not_registered → server fail-fast (we sent target_host but
  //                           no row matched in any workspace)
  //   invalid_client        → upstream OAuth client validation rejected
  //                           the request (typically same root cause)
  //   unauthorized_client   → client isn't authorised to pair at all
  var TARGETS_LINK_ERRORS = {
    target_not_registered: true,
    invalid_client:        true,
    unauthorized_client:   true
  };

  function attachTargetsLinkToStep(stepId, payloadTargetsUrl) {
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="' + stepId + '"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    // Wipe any previous link we may have appended on a prior failed click
    // so a second retry doesn't stack two action links in the same block.
    var prev = detail.querySelector('.patcherly-step__detail-link');
    if (prev) prev.remove();
    var prevBr = detail.querySelector('br.patcherly-step__detail-br');
    if (prevBr) prevBr.remove();
    var url = (typeof payloadTargetsUrl === 'string' && payloadTargetsUrl) ? payloadTargetsUrl : (patcherlyDashboardUrl().replace(/\/+$/, '') + '/targets');
    var br = document.createElement('br');
    br.className = 'patcherly-step__detail-br';
    var a  = document.createElement('a');
    a.className = 'patcherly-step__detail-link';
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = copy('open_targets', 'Open Patcherly Targets →');
    detail.appendChild(br);
    detail.appendChild(a);
  }

  // ── target_not_registered CTA ────────────────────────────────────────────

  function showTargetNotRegistered(payload) {
    var card = $('patcherly-oauth-tnr');
    if (!card) return;
    var titleEl = card.querySelector('.patcherly-oauth-tnr__title');
    var bodyEl  = card.querySelector('.patcherly-oauth-tnr__body');
    var signup  = $('patcherly-oauth-tnr-signup');
    var targets = $('patcherly-oauth-tnr-targets');
    if (titleEl) titleEl.textContent = copy('tnr_title', 'This site isn\'t on Patcherly yet.');
    if (bodyEl)  bodyEl.textContent  = (payload && payload.message) || copy('tnr_body', 'Sign up (or sign in), add this website as a Target, then click Connect with Patcherly again.');
    if (signup) {
      signup.textContent = copy('tnr_signup', 'Sign up to Patcherly');
      if (payload && payload.signup_url) signup.href = payload.signup_url;
    }
    if (targets) {
      targets.textContent = copy('tnr_targets', 'Add a Target');
      if (payload && payload.targets_url) targets.href = payload.targets_url;
    }
    card.hidden = false;
    try { card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}
  }

  function hideTargetNotRegistered() {
    var card = $('patcherly-oauth-tnr');
    if (card) card.hidden = true;
  }

  // ── OAuth device-grant flow ──────────────────────────────────────────────

  var oauthPollTimer = null;

  async function startOAuth(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-connect-oauth');
    if (btn) btn.disabled = true;
    hideTargetNotRegistered();
    renderSteps();
    showSteps();
    setStep('contact', 'running');

    // v1.49.5 — pre-open a blank tab SYNCHRONOUSLY in the click handler
    // so popup blockers don't kill it. We'll either redirect this tab to
    // the Patcherly verification URL once step 1 returns the device-code
    // response, or close it if step 1 fails. Without this synchronous
    // open, Chrome/Safari treat a later `window.open()` (post-await) as
    // a non-gesture popup and silently block it.
    var approveTab = null;
    try { approveTab = window.open('about:blank', 'patcherly_oauth_approve'); } catch (_) {}

    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_start');
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      if (cfg.siteHost) fd.set('target_host', cfg.siteHost);
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) {
        // Close the pre-opened tab if step 1 failed — there's no URL to
        // send the user to.
        if (approveTab) { try { approveTab.close(); } catch (_) {} approveTab = null; }
        var parsed = await parseFailure(r);
        var errCode = (parsed.payload && typeof parsed.payload.error === 'string') ? parsed.payload.error : '';
        // target_not_registered → also show the dedicated CTA card below
        // the Connect button. The contact step still carries the inline
        // error block + Targets link so the operator sees a clear failure
        // even before scrolling to the CTA.
        if (errCode === 'target_not_registered') {
          setStep('contact', 'error', parsed.message || copy('tnr_title', 'This site isn\'t on Patcherly yet.'));
          attachTargetsLinkToStep('contact', parsed.payload && parsed.payload.targets_url);
          showTargetNotRegistered(parsed.payload);
          if (btn) btn.disabled = false;
          return;
        }
        setStep('contact', 'error', parsed.message);
        // Other "this site isn't a registered Target" error codes
        // (invalid_client, unauthorized_client) get the same inline link
        // so the user always has a one-click route to the dashboard's
        // Targets list regardless of which precise code the API returned.
        if (TARGETS_LINK_ERRORS[errCode]) {
          attachTargetsLinkToStep('contact', parsed.payload && parsed.payload.targets_url);
        }
        if (btn) btn.disabled = false;
        return;
      }
      var j = await r.json();
      if (!j.success) {
        if (approveTab) { try { approveTab.close(); } catch (_) {} approveTab = null; }
        var rawCode = (j.data && j.data.error) ? j.data.error : '';
        var msg = (j.data && j.data.message) ? j.data.message
                : (rawCode ? (FRIENDLY_OAUTH_ERROR[rawCode] || prettifyErrorCode(rawCode))
                           : copy('pairing_error', 'Pairing failed'));
        setStep('contact', 'error', msg);
        if (btn) btn.disabled = false;
        return;
      }
      var d = j.data;
      // Step 1 succeeded: we have a server URL pinned + a device code.
      setStep('contact', 'success', (copy('connected_to', 'Connected to') + ' ' + (d.server_url || cfg.url || 'api.patcherly.com')));
      setStep('device', 'success', d.user_code ? (copy('code_label', 'Code') + ': ' + d.user_code) : '');
      setStep('approve', 'running', d.verification_uri ? (copy('open_at', 'Open at') + ' ' + d.verification_uri) : '');

      // v1.49.5 — redirect the pre-opened tab to the verification URL so
      // the user lands on the Patcherly dashboard automatically. Some
      // OAuth providers expose a `verification_uri_complete` that
      // pre-fills the user_code; prefer that when present.
      var verifyUrl = (d.verification_uri_complete || d.verification_uri || '');
      if (approveTab && verifyUrl) {
        try { approveTab.location.href = verifyUrl; } catch (_) {
          // Cross-origin redirect blocked or tab handle invalid —
          // fall back to opening a fresh tab. Still gesture-derived
          // because we're inside the click→await chain.
          try { window.open(verifyUrl, '_blank', 'noopener'); } catch (_) {}
        }
      } else if (!approveTab && verifyUrl) {
        // Popup blocker killed the synchronous open. Try one last time.
        try { window.open(verifyUrl, '_blank', 'noopener'); } catch (_) {}
      }

      // Inject the verify link + user-code right next to the approve step
      // as a visible fallback for the (rare) case the new tab was killed
      // by a strict popup blocker AND the fallback window.open also got
      // blocked. Always present so the user has an explicit click-target.
      var approveLi = document.querySelector('#patcherly-oauth-steps li[data-step="approve"]');
      if (approveLi && d.verification_uri) {
        var existing = approveLi.querySelector('.patcherly-step__cta');
        if (existing) existing.remove();
        var cta = document.createElement('div');
        cta.className = 'patcherly-step__cta';
        var a = document.createElement('a');
        a.href = verifyUrl || d.verification_uri;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.className = 'button button-primary';
        a.textContent = copy('open_at', 'Open at') + ' ' + (d.verification_uri || '');
        cta.appendChild(a);
        if (d.user_code) {
          var codeWrap = document.createElement('span');
          codeWrap.className = 'patcherly-step__code';
          codeWrap.textContent = d.user_code;
          cta.appendChild(codeWrap);
        }
        approveLi.appendChild(cta);
      }
      // Poll for token
      oauthPollTimer = setInterval(function(){ pollOAuth(d.device_code); }, 5000);
    } catch(err) {
      // Transport failure (network down, CSP block, etc.) — never appears
      // as `r.ok=false` because we never got a response object.
      if (approveTab) { try { approveTab.close(); } catch (_) {} }
      setStep('contact', 'error', copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection.'));
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
      if (r.ok) {
        var j = await r.json().catch(function(){ return {}; });
        if (j.success && j.data && j.data.access_token) {
          clearInterval(oauthPollTimer); oauthPollTimer = null;
          setStep('approve', 'success');
          setStep('save', 'success');
          setStep('done', 'success', copy('pairing_done', 'All set — reloading the page.'));
          setTimeout(function(){ location.reload(); }, 1000);
          return;
        }
      } else {
        // Hard error — stop polling and surface a friendly message.
        clearInterval(oauthPollTimer); oauthPollTimer = null;
        var parsed = await parseFailure(r);
        setStep('approve', 'error', parsed.message);
        var btn = $('patcherly-btn-connect-oauth');
        if (btn) btn.disabled = false;
      }
    } catch(_) { /* transient — ignore, next tick will retry */ }
  }

  async function refreshContext(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-refresh-context');
    var statusEl = $('patcherly-refresh-context-status');
    if (btn) btn.disabled = true;
    setText(statusEl, 'Refreshing site context…');
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_refresh_context');
      fd.set('_ajax_nonce', cfg.adminNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) {
        var parsed = await parseFailure(r);
        throw new Error(parsed.message);
      }
      var j = await r.json().catch(function(){ return {}; });
      if (!j.success) throw new Error((j.data && (j.data.message || j.data.error)) || 'Refresh failed');
      setText(statusEl, 'Site context refreshed.');
    } catch(err) {
      setText(statusEl, 'Refresh failed: ' + (err.message || 'Unknown'));
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
      if (!r.ok) {
        var parsed = await parseFailure(r);
        throw new Error(parsed.message);
      }
      hideSteps();
      setTimeout(function(){ location.reload(); }, 600);
    } catch(err) {
      alert('Disconnect failed: ' + (err.message || 'Unknown'));
    }
  }

  // ── Diagnostics ──────────────────────────────────────────────────────────
  //
  // Each diagnostic row in the Settings page exposes a result panel via a
  // `data-diag-result="<id>"` attribute. `showDiagResult()` writes either a
  // status line ('info' / 'ok' / 'fail') or a preformatted code block into
  // that panel, replacing the old approach of scattered <span> sinks. Keeping
  // the visual chrome inline (right below the button that produced it) means
  // a long JSON dump from "Debug Endpoints" never clobbers the one-line "OK"
  // from "Test Connection" the way the previous shared <pre> did.

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
    } else {
      el.innerHTML = '';
      var span = document.createElement('span');
      span.className = 'patcherly-diagnostic-result__line';
      span.textContent = text || '';
      el.appendChild(span);
    }
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
        throw new Error(parsed.message);
      }
      var j = await r.json();
      // v1.49.5 — deployment_type/database_type were dropped from
      // ConnectorStatus. Surface the new minimal payload instead: target
      // posture + plugin version. Keep the message terse — full detail
      // belongs in the Connector Status table above.
      var bits = [];
      if (j.target_status) bits.push('target=' + j.target_status);
      if (j.oauth_status)  bits.push('oauth=' + j.oauth_status);
      showDiagResult('test', 'ok', 'OK' + (bits.length ? ' (' + bits.join(', ') + ')' : ''));
      if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
    } catch(err){ showDiagResult('test', 'fail', 'Failed: '+(err&&err.message?err.message:'error')); }
    return false;
  }

  async function sendSample(e){
    if(e) e.preventDefault();
    if(!cfg.url){ showDiagResult('sample', 'fail', 'Missing Patcherly URL'); return false; }
    if(!cfg.oauthConnected){ showDiagResult('sample', 'fail', 'Not connected — use Connect button first'); return false; }
    showDiagResult('sample', 'info', 'Sending…');
    try{
      var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_send_sample'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      });
      if(!r.ok) {
        var parsed = await parseFailure(r);
        throw new Error(parsed.message);
      }
      var result = await r.json();
      if (result.success) {
        showDiagResult('sample', 'ok', result.data && result.data.message ? result.data.message : 'Ingested successfully');
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
      } else {
        throw new Error(result.data && (result.data.message || result.data.error) ? (result.data.message || result.data.error) : 'Unknown error');
      }
    }catch(err){ showDiagResult('sample', 'fail', 'Failed: '+(err&&err.message?err.message:'error')); }
    return false;
  }

  // ── Context-consent helpers (Settings page) ──────────────────────────────
  //
  // Mirror of `Patcherly_Connector_Plugin::context_consent_status_meta()` in
  // patcherly.php. Used to update the "Context sharing" row in the Connector
  // Status panel after the post-pairing consent banner saves a new tier, so
  // the row reflects the choice immediately without a page reload. The PHP
  // helper is the authoritative source on first render; this is only used
  // for the live-update path.
  var CONTEXT_CONSENT_META = {
    full:    { label: 'Full',    tooltip: 'Active plugins, theme, ACF, WooCommerce, CPTs, taxonomies, server limits and DB engine are shared with Patcherly.', kind: 'full' },
    minimal: { label: 'Minimal', tooltip: 'Only WordPress, PHP and DB engine versions are shared with Patcherly.',                                              kind: 'minimal' },
    off:     { label: 'Off',     tooltip: 'No site context is collected or uploaded. Patcherly sees only the error log line.',                                  kind: 'off' },
    pending: { label: 'Not set', tooltip: 'You haven\'t picked a context-sharing tier yet. Use the banner above or the Advanced setting.',                      kind: 'pending' }
  };

  function updateContextSharingRow(consent){
    var cell = $('patcherly-context-sharing');
    if (!cell) return;
    var key  = (consent === '' || consent === 'pending') ? 'pending' : consent;
    var meta = CONTEXT_CONSENT_META[key] || CONTEXT_CONSENT_META.pending;
    cell.setAttribute('data-consent', key);
    var badge = cell.querySelector('.patcherly-context-badge');
    if (badge) {
      badge.className = 'patcherly-context-badge patcherly-context-badge--' + meta.kind;
      badge.setAttribute('title', meta.tooltip);
      badge.textContent = meta.label;
    }
  }

  // ── Advanced-settings deep-link ──────────────────────────────────────────
  //
  // Anchored links from elsewhere on the page (e.g. the Context Sharing row
  // in Connector Status) use `data-patcherly-open-advanced="<row-key>"` to
  // pop the <details> open, scroll the relevant setting into view, and
  // briefly highlight it so the eye finds it on a long Advanced settings
  // form. row-key currently supports "context-consent".
  function openAdvancedSetting(rowKey){
    var details = $('patcherly-advanced-details');
    if (!details) return;
    details.open = true;
    var target = null;
    if (rowKey === 'context-consent') {
      // The Settings API renders one <tr> per add_settings_field. The radio
      // group lives under the row whose <th><label> mentions OPTION_CONTEXT_CONSENT
      // — but the cleanest selector is the radio inputs' shared name attribute.
      var firstRadio = details.querySelector('input[type="radio"][name="patcherly_context_consent"]');
      if (firstRadio) {
        // Walk up to the <tr> so the highlight covers the label + radios.
        target = firstRadio.closest('tr') || firstRadio;
      }
    }
    var scrollTarget = target || details;
    try { scrollTarget.scrollIntoView({ behavior: 'smooth', block: 'center' }); } catch (_) {}
    if (target && target.classList) {
      target.classList.add('patcherly-advanced-highlight');
      window.setTimeout(function(){ target.classList.remove('patcherly-advanced-highlight'); }, 1800);
    }
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
        showDiagResult('resync', 'info', 'Resyncing…');
        try {
          var r = await fetch(withAdminNonce(ajaxurl + '?action=patcherly_force_resync'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' }
          });
          if (!r.ok) {
            var parsed = await parseFailure(r);
            throw new Error(parsed.message);
          }
          var j = await r.json();
          if (j.success === false) {
            showDiagResult('resync', 'fail', 'Failed: ' + (j.message || 'Unknown error'));
          } else {
            showDiagResult('resync', 'ok', 'Resync completed successfully');
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(err) {
          showDiagResult('resync', 'fail', 'Failed: ' + (err.message || 'error'));
        }
      });
    }

    // v1.49.5 — post-pairing context-consent banner. The banner is
    // rendered by `maybe_render_context_consent_banner()` only when the
    // site is paired AND consent is empty/pending; we wire the three
    // buttons to the dedicated AJAX endpoint and hide the banner on
    // success. The Advanced settings radio is the authoritative UI;
    // this banner is just the friendly first-contact prompt.
    var consentBanner = $('patcherly-consent-banner');
    if (consentBanner) {
      var consentNonce = consentBanner.getAttribute('data-nonce') || cfg.adminNonce || '';
      consentBanner.addEventListener('click', async function(e){
        var btn = e.target && e.target.closest ? e.target.closest('button[data-consent]') : null;
        if (!btn) return;
        e.preventDefault();
        var value = btn.getAttribute('data-consent') || '';
        var msg = consentBanner.querySelector('.patcherly-consent-banner__msg');
        var siblings = consentBanner.querySelectorAll('button[data-consent]');
        siblings.forEach(function(b){ b.disabled = true; });
        if (msg) msg.textContent = '';
        try {
          var fd = new FormData();
          fd.set('action', 'patcherly_save_context_consent');
          fd.set('value', value);
          fd.set('_ajax_nonce', consentNonce);
          var r = await fetch(ajaxurl, { method: 'POST', body: fd });
          if (!r.ok) {
            var parsed = await parseFailure(r);
            throw new Error(parsed.message);
          }
          var j = await r.json();
          if (j && j.success !== false) {
            consentBanner.classList.add('is-saved');
            consentBanner.setAttribute('hidden', 'hidden');
            // Live-update the "Context sharing" row in the Connector Status
            // panel so the operator sees the new tier without reloading.
            // The server-side render is the source of truth on first paint;
            // this mirror keeps the table coherent between paints.
            var saved = (j.data && j.data.consent) || value;
            updateContextSharingRow(saved);
          } else {
            throw new Error((j && j.data && j.data.error) || 'Could not save your choice.');
          }
        } catch (err) {
          if (msg) msg.textContent = err && err.message ? err.message : 'Could not save your choice.';
          siblings.forEach(function(b){ b.disabled = false; });
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
            throw new Error(parsed.message);
          }
          var j = await r.json();
          showDiagResult('endpoints', 'ok', JSON.stringify(j, null, 2), { code: true });
        } catch(err) {
          showDiagResult('endpoints', 'fail', 'Failed: ' + (err.message || 'error'));
        }
      });
    }

    // Anchored deep-link from Connector Status → "Context sharing" row.
    // We intercept the click so the page doesn't jump to a non-existent
    // fragment; openAdvancedSetting() pops <details> open and scrolls.
    document.addEventListener('click', function(e){
      var link = e.target && e.target.closest ? e.target.closest('[data-patcherly-open-advanced]') : null;
      if (!link) return;
      e.preventDefault();
      openAdvancedSetting(link.getAttribute('data-patcherly-open-advanced') || '');
    });
  }

  if (document.readyState === 'complete') { initStatus(); bind(); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); }); }
})();
