(function(){
  var cfg = window.PATCHERLY_SETTINGS || {
    url: '', dashboardUrl: '', oauthConnected: false, oauthExpiresAt: '', oauthScope: '',
    ajaxNonce: '', adminNonce: '', clientId: '', siteHost: '',
    stepLabels: {}, stepCopy: {}
  };
  function $(id){ return document.getElementById(id); }
  function setText(el, t){ if(el) el.textContent = t; }

  // Derive Dashboard URL from the API URL when the server didn't supply one.
  // Mirror of Patcherly_Connector_Plugin::derive_dashboard_url(); cfg.dashboardUrl wins.
  //   apidev.patcherly.com → https://appdev.patcherly.com
  //   api.patcherly.com    → https://app.patcherly.com
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

  // Renders the "Requesting a one-time pairing code" success state as a
  // big, copy-able pill instead of plain "Code: KCGB-6DF4" text. The
  // block is built inside the step's `[data-role="detail"]` so the
  // is-success banner styles (green background, bordered) wrap it
  // naturally -- same visual language as the rest of the pairing flow.
  function renderDeviceCode(userCode) {
    if (!userCode) return;
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="device"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    detail.textContent = '';

    var wrap = document.createElement('div');
    wrap.className = 'patcherly-step__device-code-block';

    var labelEl = document.createElement('span');
    labelEl.className = 'patcherly-step__device-code-label';
    labelEl.textContent = copy('code_label', 'Code') + ':';
    wrap.appendChild(labelEl);

    var codeEl = document.createElement('span');
    codeEl.className = 'patcherly-step__device-code';
    codeEl.textContent = userCode;
    wrap.appendChild(codeEl);

    var btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'patcherly-step__copy-btn';
    btn.setAttribute('aria-label', copy('copy_code', 'Copy code'));
    btn.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
      'stroke-linejoin="round" aria-hidden="true">' +
      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
      '</svg>' +
      '<span data-role="copy-label">' + copy('copy_code', 'Copy code') + '</span>';
    btn.addEventListener('click', function() {
      copyToClipboard(userCode).then(function(ok) {
        if (!ok) return;
        var lbl = btn.querySelector('[data-role="copy-label"]');
        var prev = lbl ? lbl.textContent : '';
        btn.classList.add('is-copied');
        if (lbl) lbl.textContent = copy('copy_code_done', 'Copied');
        setTimeout(function() {
          btn.classList.remove('is-copied');
          if (lbl) lbl.textContent = prev || copy('copy_code', 'Copy code');
        }, 2000);
      });
    });
    wrap.appendChild(btn);

    detail.appendChild(wrap);
  }

  // navigator.clipboard.writeText is async and requires a secure context;
  // fall back to the legacy execCommand path on http:// admin pages so
  // operators on self-signed dev sites still get the click-to-copy UX.
  function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function() { return true; })
        .catch(function() { return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }
  function legacyCopy(text) {
    try {
      var ta = document.createElement('textarea');
      ta.value = text;
      ta.setAttribute('readonly', '');
      ta.style.position = 'absolute';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      return ok;
    } catch (_) { return false; }
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

  // Friendly response parsing. parseFailure() never dumps raw HTML 502 bodies into the step list —
  // it prefers JSON `data.message`, then the FRIENDLY_OAUTH_ERROR map, then bucketed status codes.
  // Returns `{ message, payload }` so callers can act on `payload.error` (e.g. target_not_registered).

  // RFC 8628 §3.5 + Patcherly device-grant error codes → user-facing copy.
  var FRIENDLY_OAUTH_ERROR = {
    invalid_client: 'Patcherly doesn\'t recognise this site yet. Make sure it\'s added as a Target on your Patcherly dashboard, then try again.',
    invalid_request: 'Patcherly couldn\'t accept the pairing request. Refresh the page and try again.',
    invalid_scope: 'The Patcherly API needs an update before this plugin version can pair. Try again in a few minutes — if it keeps failing, contact support.',
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

  // Detects "the Patcherly API is genuinely unreachable" from either the HTTP
  // status code or the server-set `payload.error` string (e.g. "Upstream HTTP 503"
  // / "Connection failed: …" / "Request failed: …"). Callers use this flag to
  // append the "Contact Patcherly" link inside the diagnostic result banner.
  function isApiDownFailure(status, payload) {
    if (status === 502 || status === 503 || status === 504) return true;
    if (status >= 500) return true;
    if (payload && typeof payload.http_code === 'number' && payload.http_code >= 500) return true;
    if (payload && typeof payload.error === 'string') {
      var lc = payload.error.toLowerCase();
      if (lc.indexOf('upstream http 5') === 0) return true;
      if (lc.indexOf('connection failed') === 0) return true;
      if (lc.indexOf('request failed') === 0) return true;
      if (lc.indexOf('server error ') === 0) return true;
    }
    return false;
  }

  // Best-effort detection for browser-side fetch failures (DNS, TLS, refused,
  // offline, mixed-content block). Different browsers throw different shapes,
  // so we sniff the name + message.
  function isFetchTransportError(err) {
    if (!err) return false;
    if (err.name === 'TypeError') return true;
    var msg = (err.message || '').toLowerCase();
    return msg.indexOf('failed to fetch') !== -1
        || msg.indexOf('networkerror') !== -1
        || msg.indexOf('load failed') !== -1
        || msg.indexOf('network request failed') !== -1;
  }

  async function parseFailure(r) {
    var ctype = (r.headers.get('Content-Type') || '').toLowerCase();
    var payload = null;
    var message = '';
    if (ctype.indexOf('application/json') !== -1) {
      try {
        var j = await r.json();
        // admin-ajax wraps errors as { success:false, data:{...} }.
        var data = (j && typeof j === 'object' && 'data' in j) ? j.data : j;
        payload = (data && typeof data === 'object') ? data : null;
        if (payload) {
          // Preference: server message → friendly code map → prettified raw code.
          if (typeof payload.message === 'string' && payload.message) {
            message = payload.message;
          } else if (typeof payload.error === 'string' && payload.error) {
            message = FRIENDLY_OAUTH_ERROR[payload.error] || prettifyErrorCode(payload.error);
          }
        }
      } catch (_) { /* fall through to bucketed message */ }
    }
    var apiDown = isApiDownFailure(r.status, payload);
    // Rewrite "Upstream HTTP 5xx" / "Connection failed: …" style server strings
    // (which are accurate but not human-friendly) into the explicit "API is down"
    // copy so the diagnostic banner reads naturally to a non-technical operator.
    if (apiDown) {
      message = copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.');
    } else if (!message) {
      if (r.status === 0) {
        // String fallback for toast / diagnostic-banner contexts (no DOM
        // element to attach a link to). The diagnostic banner separately
        // renders the err_contact_cta link below this prose when
        // `isApiDown` is true (see showDiagResult), so the operator still
        // gets a one-click support path even though the %s placeholder is
        // collapsed to plain text here. Step banners use setNetworkErrorStep
        // instead which DOES render the inline mailto: anchor.
        message = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.').replace('%s', copy('err_network_support', 'Patcherly Support'));
        apiDown = true;
      } else {
        message = 'HTTP ' + r.status;
      }
    }
    return { message: message, payload: payload, isApiDown: apiDown };
  }

  // Wraps an Error so the catch block downstream can render the contact link.
  function apiDownError(parsed) {
    var e = new Error(parsed.message);
    e.isApiDown = !!parsed.isApiDown;
    return e;
  }

  // Error codes whose root cause is "this site isn't registered as a Patcherly Target" —
  // the pairing UI appends an "Open Patcherly Targets →" link to the contact step.
  var TARGETS_LINK_ERRORS = {
    target_not_registered: true,
    invalid_client:        true,
    unauthorized_client:   true
  };

  // Network-error step renderer with an inline mailto: link to Patcherly
  // Support. Used by the two pairing-flow code paths that can't reach the
  // API at all (the initial /device call in startOAuth and the polling
  // streak guard in pollOAuth). The prose is a translatable PHP string
  // containing exactly one '%s' placeholder; we split on it so the link
  // text and surrounding sentence stay localisable and the mailto:
  // address comes from cfg.stepCopy.support_email (a server constant, not
  // a translated string). On legacy bundles missing the new keys we fall
  // back to the old short prose + an appended link via the
  // attachTargetsLinkToStep-style pattern so the operator can still reach
  // support even if the localisation map is stale.
  function setNetworkErrorStep(stepId) {
    setStep(stepId, 'error', '');
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="' + stepId + '"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    detail.textContent = '';
    var prose       = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.');
    var supportText = copy('err_network_support', 'Patcherly Support');
    var supportAddr = (cfg.stepCopy && cfg.stepCopy.support_email) || 'help@patcherly.com';
    var idx = prose.indexOf('%s');
    if (idx === -1) {
      // Legacy bundle: no placeholder in the prose. Render the prose as-is
      // and tack a "Patcherly Support" anchor after a space so the operator
      // still gets a one-click mailto path. Better than silently dropping
      // the support link entirely.
      detail.appendChild(document.createTextNode(prose + ' '));
      var aLegacy = document.createElement('a');
      aLegacy.className = 'patcherly-step__detail-link';
      aLegacy.href = 'mailto:' + supportAddr;
      aLegacy.textContent = supportText;
      detail.appendChild(aLegacy);
      return;
    }
    var before = prose.substring(0, idx);
    var after  = prose.substring(idx + 2);
    if (before) detail.appendChild(document.createTextNode(before));
    var a = document.createElement('a');
    a.className = 'patcherly-step__detail-link';
    a.href = 'mailto:' + supportAddr;
    a.textContent = supportText;
    detail.appendChild(a);
    if (after) detail.appendChild(document.createTextNode(after));
  }

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
  // Polling is bounded by three guards so the page can NEVER hammer
  // admin-ajax.php in the background (this caused a `429 Too Many
  // Requests` from the host's WAF / CloudFlare when a half-paired
  // settings page was left open overnight):
  //   * `oauthPollDeadline` -- absolute Date.now() limit derived from the
  //     server-supplied `expires_in` plus a 60s grace; once the device
  //     code is expired the server only returns `expired_token` so there
  //     is no value in continuing to poll.
  //   * `oauthPollErrorStreak` -- transport failures (network down, host
  //     timeout, CORS, etc.) hit the empty `catch(_)` below and the loop
  //     would otherwise retry forever; we now stop after 6 consecutive
  //     errors (~30s) and surface "Couldn't reach Patcherly".
  //   * `document.visibilityState === 'hidden'` -- skip the tick when
  //     the tab is in the background. The user will resume on focus and
  //     the deadline / streak guards still apply.
  var oauthPollDeadline = 0;
  var oauthPollErrorStreak = 0;
  var OAUTH_POLL_MAX_ERROR_STREAK = 6;

  function stopOAuthPoll() {
    if (oauthPollTimer) { clearInterval(oauthPollTimer); oauthPollTimer = null; }
    oauthPollDeadline = 0;
    oauthPollErrorStreak = 0;
  }

  async function startOAuth(e){
    if (e) e.preventDefault();
    var btn = $('patcherly-btn-connect-oauth');
    if (btn) btn.disabled = true;
    hideTargetNotRegistered();
    renderSteps();
    showSteps();
    setStep('contact', 'running');

    // No synchronous tab pre-open here. The old flow opened a blank tab
    // inside the click handler (to dodge popup blockers) and either
    // redirected or closed it depending on the AJAX result -- this made
    // an empty tab flash up and disappear on every failure, and felt
    // broken to operators when step 1 failed. The new flow instead
    // renders an explicit "Confirm your code" button on the approve
    // step (see below); the click on THAT button is a fresh user
    // gesture so popup blockers still let the verification tab open,
    // and a step-1 failure simply leaves the steps panel showing the
    // error without ever opening a window.
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_start');
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      if (cfg.siteHost) fd.set('target_host', cfg.siteHost);
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      if (!r.ok) {
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
      // Promote the device step to success first (so the green banner
      // wraps the code), then render the big copyable pill into it.
      setStep('device', 'success', '');
      renderDeviceCode(d.user_code || '');
      // Status line under the approve step is intentionally terse -- the
      // explicit "Confirm your code" CTA built below is the actionable
      // element; repeating the URL here as plain text added visual noise
      // and (in the old flow) competed with the auto-opened tab.
      setStep('approve', 'running', copy('approve_pending', 'Open the Patcherly dashboard to approve this site.'));

      // Explicit gesture-driven approve CTA. We deliberately do NOT
      // window.open() here -- that would either pop a tab the user
      // didn't ask for (annoying) or get blocked silently (broken).
      // The user clicks the button below, which IS a fresh gesture, so
      // popup blockers stay happy and the user is in control of when
      // the new tab appears. `verification_uri_complete` pre-fills the
      // user_code on the dashboard so the operator only has to confirm.
      var verifyUrl = (d.verification_uri_complete || d.verification_uri || '');
      var approveLi = document.querySelector('#patcherly-oauth-steps li[data-step="approve"]');
      if (approveLi && verifyUrl) {
        var existing = approveLi.querySelector('.patcherly-step__cta');
        if (existing) existing.remove();
        var cta = document.createElement('div');
        cta.className = 'patcherly-step__cta';
        var a = document.createElement('a');
        a.href = verifyUrl;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        a.className = 'button button-primary';
        a.textContent = copy('confirm_code', 'Confirm your code');
        cta.appendChild(a);
        if (d.user_code) {
          var codeWrap = document.createElement('span');
          codeWrap.className = 'patcherly-step__code';
          codeWrap.textContent = d.user_code;
          cta.appendChild(codeWrap);
        }
        approveLi.appendChild(cta);
      }
      // Poll for token. The server-provided `expires_in` (default 1800s
      // / 30min) plus a 60s grace caps the loop so it can never run
      // indefinitely if the user walks away or the network degrades --
      // see `stopOAuthPoll` and `oauthPollDeadline` above.
      var ttlSeconds = (typeof d.expires_in === 'number' && d.expires_in > 0) ? d.expires_in : 1800;
      oauthPollDeadline = Date.now() + (ttlSeconds * 1000) + 60000;
      oauthPollErrorStreak = 0;
      oauthPollTimer = setInterval(function(){ pollOAuth(d.device_code); }, 5000);
    } catch(err) {
      // Transport failure (network down, CSP block, etc.) -- never
      // appears as `r.ok=false` because we never got a response object.
      // No tab to clean up because the new UX doesn't pre-open one.
      setNetworkErrorStep('contact');
      if (btn) btn.disabled = false;
    }
  }

  async function pollOAuth(deviceCode){
    // Hard deadline guard -- the server-derived `oauthPollDeadline` (set
    // in startOAuth from `expires_in`) caps how long this loop runs so
    // an unattended settings page can never spam admin-ajax.php
    // indefinitely (host WAFs / CloudFlare respond with `429 Too Many
    // Requests` to sustained 12 req/min polling against the same IP).
    if (oauthPollDeadline && Date.now() > oauthPollDeadline) {
      stopOAuthPoll();
      setStep('approve', 'error', copy('pairing_timeout', 'Pairing code expired before it was approved. Click Connect with Patcherly again to start over.'));
      var btnTo = $('patcherly-btn-connect-oauth');
      if (btnTo) btnTo.disabled = false;
      return;
    }
    // Skip when tab is in the background; deadline + streak guards still
    // apply so the loop self-stops even if it never gets a tick of
    // foreground time.
    if (typeof document !== 'undefined' && document.visibilityState === 'hidden') {
      return;
    }
    try {
      var fd = new FormData();
      fd.set('action', 'patcherly_oauth_poll');
      fd.set('device_code', deviceCode);
      fd.set('_ajax_nonce', cfg.ajaxNonce || '');
      var r = await fetch(ajaxurl, { method: 'POST', body: fd });
      // 202 = authorization_pending / slow_down, keep polling silently
      if (r.status === 202) { oauthPollErrorStreak = 0; return; }
      if (r.ok) {
        var j = await r.json().catch(function(){ return {}; });
        if (j.success && j.data && j.data.access_token) {
          stopOAuthPoll();
          setStep('approve', 'success');
          setStep('save', 'success');
          setStep('done', 'success', copy('pairing_done', 'All set — reloading the page.'));
          setTimeout(function(){ location.reload(); }, 1000);
          return;
        }
        // 200 OK but no access_token and no `success:true` payload --
        // shouldn't happen in practice (the PHP handler maps every
        // non-pending state to a structured error) but if it does, treat
        // it as a transport failure rather than silently looping forever.
        oauthPollErrorStreak++;
      } else if (r.status >= 500) {
        // Transient upstream / host failure (502/503/504 from CloudFlare,
        // a Patcherly API restart, a momentary admin-ajax.php hiccup).
        // KEY: do NOT hard-stop here. After the user clicks Approve on
        // the dashboard the device code is locked-in and the very next
        // poll is supposed to return the bearer token. If a single 5xx
        // tick in that exact window killed the loop, the operator saw
        // "service may be temporarily down" forever even though the
        // token was already minted upstream. Bumping `errorStreak` keeps
        // the loop honest: a sustained outage still bails out after
        // MAX_ERROR_STREAK consecutive misses (~30 s at 5 s cadence),
        // but a one-off blip is recovered on the next tick.
        var bodyParsed = null;
        try { bodyParsed = await parseFailure(r); } catch (_) {}
        try {
          patcherlyDebugLog('pollOAuth transient ' + r.status +
            (bodyParsed && bodyParsed.message ? (': ' + bodyParsed.message) : ''));
        } catch (_) {}
        oauthPollErrorStreak++;
      } else {
        // 4xx (other than 202): definitive error from the server -- the
        // device code expired, was denied, or the request itself is
        // malformed. Stop polling and surface the friendly message.
        stopOAuthPoll();
        var parsed = await parseFailure(r);
        setStep('approve', 'error', parsed.message);
        var btn = $('patcherly-btn-connect-oauth');
        if (btn) btn.disabled = false;
        return;
      }
    } catch(_) {
      // Transport failure (network down, CORS, host timeout). The empty
      // catch used to silently retry forever -- now we count consecutive
      // failures and bail after MAX_ERROR_STREAK to avoid drowning the
      // host's WAF when the network has been out for a while.
      oauthPollErrorStreak++;
    }
    if (oauthPollErrorStreak >= OAUTH_POLL_MAX_ERROR_STREAK) {
      stopOAuthPoll();
      setNetworkErrorStep('approve');
      var btnNet = $('patcherly-btn-connect-oauth');
      if (btnNet) btnNet.disabled = false;
    }
  }

  // Best-effort debug helper -- prints to console only when WP_DEBUG
  // surfaces window.console (which it does by default). Wrapped in
  // try/catch because IE/old-Safari can throw if a CSP forbids the
  // window.console reference.
  function patcherlyDebugLog(msg) {
    try {
      if (typeof console !== 'undefined' && console.warn) {
        console.warn('[patcherly] ' + msg);
      }
    } catch (_) {}
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

  // Diagnostics — each row owns a result panel keyed by `data-diag-result="<id>"`.
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
    // dashboardUrl is rendered as an emerald CTA-style link — used by the
    // Send Sample Error row when the per-target test-ingest window is
    // closed, so the operator can jump straight to the toggle that fixes it.
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
      // /health/summary probe, which only proves the API URL is reachable — not
      // that credentials are accepted. Render that as an info banner so the
      // operator isn't misled into thinking pairing succeeded.
      if (j && j.paired === false) {
        showDiagResult('test', 'info', copy('test_reachable_unpaired',
          'Patcherly API is reachable, but this site isn\'t paired yet. Use the "Connect with Patcherly" button above to pair before testing credentials.'));
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
        return false;
      }
      // Terse summary — full detail lives in the Connector Status table above.
      var bits = [];
      if (j.target_status) bits.push('target=' + j.target_status);
      if (j.oauth_status)  bits.push('oauth=' + j.oauth_status);
      showDiagResult('test', 'ok', 'OK' + (bits.length ? ' (' + bits.join(', ') + ')' : ''));
      if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
    } catch(err){
      var down = (err && err.isApiDown) || isFetchTransportError(err);
      var msg = down
        ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.')
        : (err && err.message ? err.message : 'error');
      showDiagResult('test', 'fail', msg, { contact: down });
    }
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
        // v1.49.0 — diagnostics now POST /errors/ingest-test, which the
        // server gates on the per-target test-ingest window. When the
        // window is off it returns 403 with {code:'test_window_closed',
        // dashboard_url:'…'}; we render a one-click link instead of a
        // generic failure string so the operator can flip the toggle.
        var payload = parsed && parsed.payload;
        var isWindowClosed = !!(payload && (payload.code === 'test_window_closed' || payload.dashboard_url));
        if (r.status === 403 && isWindowClosed) {
          showDiagResult('sample', 'fail', parsed.message || copy('err_test_window_closed',
            'Test ingest window is not open for this target. Enable it from your Patcherly dashboard, then retry.'), {
            dashboardUrl: payload.dashboard_url,
            dashboardLabel: copy('open_test_ingest_cta', 'Enable test ingest in Patcherly →')
          });
          return false;
        }
        throw apiDownError(parsed);
      }
      var result = await r.json();
      if (result.success) {
        showDiagResult('sample', 'ok', result.data && result.data.message ? result.data.message : 'Ingested successfully');
        if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
      } else {
        throw new Error(result.data && (result.data.message || result.data.error) ? (result.data.message || result.data.error) : 'Unknown error');
      }
    }catch(err){
      var down = (err && err.isApiDown) || isFetchTransportError(err);
      var msg = down
        ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.')
        : (err && err.message ? err.message : 'error');
      showDiagResult('sample', 'fail', msg, { contact: down });
    }
    return false;
  }

  // Context-consent helpers — mirror of Patcherly_Connector_Plugin::context_consent_status_meta().
  // Used to live-update the "Context sharing" row after the banner saves a new tier; the PHP
  // helper is authoritative on first render.
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

  // Advanced-settings deep-link — pops the <details> open, scrolls a row into view, briefly
  // highlights it. row-key currently supports "context-consent".
  function openAdvancedSetting(rowKey){
    var details = $('patcherly-advanced-details');
    if (!details) return;
    details.open = true;
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
      lines.push('Site context collection is Off — nothing is collected or uploaded.');
      return lines.join('\n');
    }
    if (data.consent === 'pending') {
      lines.push('No consent tier selected yet — choose Full, Minimal, or Off in Advanced settings.');
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
            throw apiDownError(parsed);
          }
          var j = await r.json();
          if (j.success === false) {
            showDiagResult('resync', 'fail', j.message || 'Unknown error');
          } else {
            showDiagResult('resync', 'ok', 'Resync completed successfully');
            if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
          }
        } catch(err) {
          var down = (err && err.isApiDown) || isFetchTransportError(err);
          var msg = down
            ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.')
            : (err && err.message ? err.message : 'error');
          showDiagResult('resync', 'fail', msg, { contact: down });
        }
      });
    }

    // Post-pairing onboarding — context tier + Emergency Rescue consent.
    var onboardingBanner = $('patcherly-post-pair-setup-banner');
    if (onboardingBanner) {
      var onboardingNonce = onboardingBanner.getAttribute('data-nonce') || cfg.adminNonce || '';
      var selectedTier = 'full';
      var tierButtons = onboardingBanner.querySelectorAll('button[data-consent]');
      tierButtons.forEach(function(btn){
        btn.addEventListener('click', function(e){
          e.preventDefault();
          selectedTier = btn.getAttribute('data-consent') || 'full';
          tierButtons.forEach(function(b){
            b.classList.remove('button-primary');
            if (b === btn) b.classList.add('button-primary');
          });
        });
      });
      if (tierButtons.length) {
        tierButtons[0].classList.add('button-primary');
      }
      var getStarted = $('patcherly-onboarding-get-started');
      if (getStarted) {
        getStarted.addEventListener('click', async function(e){
          e.preventDefault();
          var msg = onboardingBanner.querySelector('.patcherly-consent-banner__msg');
          var rescueBox = $('patcherly-onboarding-rescue-opt-in');
          var rescueMu = rescueBox && rescueBox.checked ? '1' : '0';
          getStarted.disabled = true;
          tierButtons.forEach(function(b){ b.disabled = true; });
          if (msg) msg.textContent = '';
          try {
            var fd = new FormData();
            fd.set('action', 'patcherly_save_post_pair_setup');
            fd.set('value', selectedTier);
            fd.set('rescue_mu', rescueMu);
            fd.set('_ajax_nonce', onboardingNonce);
            var r = await fetch(ajaxurl, { method: 'POST', body: fd });
            if (!r.ok) {
              var parsed = await parseFailure(r);
              throw new Error(parsed.message);
            }
            var j = await r.json();
            if (j && j.success !== false) {
              onboardingBanner.classList.add('is-saved');
              onboardingBanner.setAttribute('hidden', 'hidden');
              var saved = (j.data && j.data.consent) || selectedTier;
              updateContextSharingRow(saved);
              if (window.PatcherlyStatus) window.PatcherlyStatus.refresh('patcherly');
            } else {
              throw new Error((j && j.data && j.data.error) || 'Could not save your choices.');
            }
          } catch (err) {
            if (msg) msg.textContent = err && err.message ? err.message : 'Could not save your choices.';
            getStarted.disabled = false;
            tierButtons.forEach(function(b){ b.disabled = false; });
          }
        });
      }
    }

    // Legacy context-only banner id (kept for cached HTML during upgrades).
    var consentBanner = $('patcherly-consent-banner');
    if (consentBanner && consentBanner.id !== 'patcherly-post-pair-setup-banner') {
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
            // Live-update the "Context sharing" row so the operator sees the new tier without reload.
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
            throw apiDownError(parsed);
          }
          var j = await r.json();
          showDiagResult('endpoints', 'ok', JSON.stringify(j, null, 2), { code: true });
        } catch(err) {
          var down = (err && err.isApiDown) || isFetchTransportError(err);
          var msg = down
            ? copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down — please try again in a few minutes.')
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
  }

  if (document.readyState === 'complete') { initStatus(); bind(); }
  else { window.addEventListener('load', function(){ initStatus(); bind(); }); }
})();
