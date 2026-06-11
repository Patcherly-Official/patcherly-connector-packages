(function(){
  var cfg = window.PATCHERLY_SETTINGS || {
    url: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '',
    ajaxNonce: '', adminNonce: '', clientId: '', siteHost: '',
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
        // target_not_registered → show the CTA card instead of polluting
        // the step list with the structured detail. The contact step stops
        // with a one-line summary so the user knows where the flow stopped.
        if (parsed.payload && parsed.payload.error === 'target_not_registered') {
          setStep('contact', 'error', parsed.message || copy('tnr_title', 'This site isn\'t on Patcherly yet.'));
          showTargetNotRegistered(parsed.payload);
          if (btn) btn.disabled = false;
          return;
        }
        setStep('contact', 'error', parsed.message);
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
      if(!r.ok) {
        var parsed = await parseFailure(r);
        throw new Error(parsed.message);
      }
      var j = await r.json();
      // v1.49.5 — deployment_type/database_type were dropped from
      // ConnectorStatus. Surface the new minimal payload instead: target
      // posture + plugin version. Keep the message terse — full detail
      // belongs in the Connector Status table below.
      var bits = [];
      if (j.target_status) bits.push('target=' + j.target_status);
      if (j.oauth_status)  bits.push('oauth=' + j.oauth_status);
      setText($('patcherly-test-result'), 'OK' + (bits.length ? ' (' + bits.join(', ') + ')' : ''));
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
        var parsed = await parseFailure(r);
        throw new Error(parsed.message);
      }
      var result = await r.json();
      if (result.success) {
        setText($('patcherly-sample-result'), result.data && result.data.message ? result.data.message : 'Ingested successfully');
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
      } else {
        throw new Error(result.data && (result.data.message || result.data.error) ? (result.data.message || result.data.error) : 'Unknown error');
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
          if (!r.ok) {
            var parsed = await parseFailure(r);
            throw new Error(parsed.message);
          }
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
