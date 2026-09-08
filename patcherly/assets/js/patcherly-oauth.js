(function(){
  var cfg = window.PATCHERLY_OAUTH || window.PATCHERLY_SETTINGS || window.PATCHERLY_HOME || {};
  function $(id){ return document.getElementById(id); }
  function setText(el, text){ if (el) el.textContent = text; }
  function copy(key, fallback){ return (cfg.stepCopy && cfg.stepCopy[key]) || fallback; }

  function deriveDashboardUrl(apiUrl) {
    var fallback = 'https://app.patcherly.com';
    if (typeof apiUrl !== 'string' || !apiUrl) return fallback;
    var candidate = apiUrl.indexOf('://') === -1 ? ('https://' + apiUrl) : apiUrl;
    var host = '';
    try { host = (new URL(candidate)).hostname.toLowerCase(); } catch (_) { return fallback; }
    if (host.indexOf('apidev.') === 0) return 'https://appdev.patcherly.com';
    if (host.indexOf('api.') === 0) return 'https://app.patcherly.com';
    return fallback;
  }

  function patcherlyDashboardUrl() {
    return (typeof cfg.dashboardUrl === 'string' && cfg.dashboardUrl)
      ? cfg.dashboardUrl
      : deriveDashboardUrl(cfg.url);
  }

  var STEP_IDS = ['contact', 'device', 'approve', 'save', 'done'];
  function stepLabel(id){ return (cfg.stepLabels && cfg.stepLabels[id]) || id; }

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
      label.textContent = stepLabel(id);
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
      var el = li.querySelector('[data-role="detail"]');
      if (el) el.textContent = detail;
    }
  }

  function legacyCopy(text) {
    try {
      var textarea = document.createElement('textarea');
      textarea.value = text;
      textarea.setAttribute('readonly', '');
      textarea.style.position = 'absolute';
      textarea.style.left = '-9999px';
      document.body.appendChild(textarea);
      textarea.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(textarea);
      return ok;
    } catch (_) { return false; }
  }

  function copyToClipboard(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text)
        .then(function(){ return true; })
        .catch(function(){ return legacyCopy(text); });
    }
    return Promise.resolve(legacyCopy(text));
  }

  function renderDeviceCode(userCode) {
    if (!userCode) return;
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="device"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    detail.textContent = '';
    var wrap = document.createElement('div');
    wrap.className = 'patcherly-step__device-code-block';
    var label = document.createElement('span');
    label.className = 'patcherly-step__device-code-label';
    label.textContent = copy('code_label', 'Code') + ':';
    wrap.appendChild(label);
    var code = document.createElement('span');
    code.className = 'patcherly-step__device-code';
    code.textContent = userCode;
    wrap.appendChild(code);
    var button = document.createElement('button');
    button.type = 'button';
    button.className = 'patcherly-step__copy-btn';
    button.setAttribute('aria-label', copy('copy_code', 'Copy code'));
    button.innerHTML =
      '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" ' +
      'stroke="currentColor" stroke-width="2" stroke-linecap="round" ' +
      'stroke-linejoin="round" aria-hidden="true">' +
      '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>' +
      '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>' +
      '</svg><span data-role="copy-label">' + copy('copy_code', 'Copy code') + '</span>';
    button.addEventListener('click', function() {
      copyToClipboard(userCode).then(function(ok) {
        if (!ok) return;
        var text = button.querySelector('[data-role="copy-label"]');
        var previous = text ? text.textContent : '';
        button.classList.add('is-copied');
        if (text) text.textContent = copy('copy_code_done', 'Copied');
        setTimeout(function() {
          button.classList.remove('is-copied');
          if (text) text.textContent = previous || copy('copy_code', 'Copy code');
        }, 2000);
      });
    });
    wrap.appendChild(button);
    detail.appendChild(wrap);
  }

  function showSteps() {
    var ol = $('patcherly-oauth-steps');
    if (!ol) return;
    ol.hidden = false;
    try { ol.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}
  }

  function hideSteps() {
    var ol = $('patcherly-oauth-steps');
    if (ol) ol.hidden = true;
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
    return code.replace(/[_-]+/g, ' ').replace(/\s+/g, ' ').trim()
      .replace(/^./, function(character){ return character.toUpperCase(); });
  }

  function isApiDownFailure(status, payload) {
    if (status >= 500) return true;
    if (payload && typeof payload.http_code === 'number' && payload.http_code >= 500) return true;
    if (payload && typeof payload.error === 'string') {
      var error = payload.error.toLowerCase();
      return error.indexOf('upstream http 5') === 0
        || error.indexOf('connection failed') === 0
        || error.indexOf('request failed') === 0
        || error.indexOf('server error ') === 0;
    }
    return false;
  }

  async function parseFailure(response) {
    var contentType = (response.headers.get('Content-Type') || '').toLowerCase();
    var payload = null;
    var message = '';
    if (contentType.indexOf('application/json') !== -1) {
      try {
        var json = await response.json();
        var data = (json && typeof json === 'object' && 'data' in json) ? json.data : json;
        payload = (data && typeof data === 'object') ? data : null;
        if (payload && typeof payload.message === 'string' && payload.message) {
          message = payload.message;
        } else if (payload && typeof payload.error === 'string' && payload.error) {
          message = FRIENDLY_OAUTH_ERROR[payload.error] || prettifyErrorCode(payload.error);
        }
      } catch (_) {}
    }
    var apiDown = isApiDownFailure(response.status, payload);
    if (apiDown) {
      message = copy('err_api_down', 'We couldn\'t reach the Patcherly API. The service may be temporarily down - please try again in a few minutes.');
    } else if (!message) {
      if (response.status === 0) {
        message = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.')
          .replace('%s', copy('err_network_support', 'Patcherly Support'));
        apiDown = true;
      } else {
        message = 'HTTP ' + response.status;
      }
    }
    return { message: message, payload: payload, isApiDown: apiDown };
  }

  var TARGETS_LINK_ERRORS = {
    target_not_registered: true,
    invalid_client: true,
    unauthorized_client: true
  };

  function setNetworkErrorStep(stepId) {
    setStep(stepId, 'error', '');
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="' + stepId + '"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    detail.textContent = '';
    var prose = copy('err_network', 'Couldn\'t reach Patcherly. Check your internet connection and try again in a few minutes. If the issue persists contact %s.');
    var supportText = copy('err_network_support', 'Patcherly Support');
    var supportAddress = (cfg.stepCopy && cfg.stepCopy.support_email) || 'help@patcherly.com';
    var index = prose.indexOf('%s');
    if (index === -1) {
      detail.appendChild(document.createTextNode(prose + ' '));
    } else {
      if (index) detail.appendChild(document.createTextNode(prose.substring(0, index)));
    }
    var link = document.createElement('a');
    link.className = 'patcherly-step__detail-link';
    link.href = 'mailto:' + supportAddress;
    link.textContent = supportText;
    detail.appendChild(link);
    if (index !== -1 && prose.substring(index + 2)) {
      detail.appendChild(document.createTextNode(prose.substring(index + 2)));
    }
  }

  function attachTargetsLinkToStep(stepId, payloadTargetsUrl) {
    var li = document.querySelector('#patcherly-oauth-steps li[data-step="' + stepId + '"]');
    if (!li) return;
    var detail = li.querySelector('[data-role="detail"]');
    if (!detail) return;
    var previousLink = detail.querySelector('.patcherly-step__detail-link');
    if (previousLink) previousLink.remove();
    var previousBreak = detail.querySelector('br.patcherly-step__detail-br');
    if (previousBreak) previousBreak.remove();
    var url = (typeof payloadTargetsUrl === 'string' && payloadTargetsUrl)
      ? payloadTargetsUrl
      : patcherlyDashboardUrl().replace(/\/+$/, '') + '/targets';
    var br = document.createElement('br');
    br.className = 'patcherly-step__detail-br';
    var link = document.createElement('a');
    link.className = 'patcherly-step__detail-link';
    link.href = url;
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = copy('open_targets', 'Open Patcherly Sites →');
    detail.appendChild(br);
    detail.appendChild(link);
  }

  function showTargetNotRegistered(payload) {
    var card = $('patcherly-oauth-tnr');
    if (!card) return;
    var title = card.querySelector('.patcherly-oauth-tnr__title');
    var body = card.querySelector('.patcherly-oauth-tnr__body');
    var signup = $('patcherly-oauth-tnr-signup');
    var targets = $('patcherly-oauth-tnr-targets');
    if (title) title.textContent = copy('tnr_title', 'This site isn\'t on Patcherly yet.');
    if (body) body.textContent = (payload && payload.message) || copy('tnr_body', 'Sign up (or sign in), add this website as a Site, then click Connect with Patcherly again.');
    if (signup) {
      signup.textContent = copy('tnr_signup', 'Sign up to Patcherly');
      if (payload && payload.signup_url) signup.href = payload.signup_url;
    }
    if (targets) {
      targets.textContent = copy('tnr_targets', 'Add a Site');
      if (payload && payload.targets_url) targets.href = payload.targets_url;
    }
    card.hidden = false;
    try { card.scrollIntoView({ behavior: 'smooth', block: 'nearest' }); } catch (_) {}
  }

  function hideTargetNotRegistered() {
    var card = $('patcherly-oauth-tnr');
    if (card) card.hidden = true;
  }

  var oauthPollTimer = null;
  var oauthPollDeadline = 0;
  var oauthPollErrorStreak = 0;
  var OAUTH_POLL_MAX_ERROR_STREAK = 6;

  function stopOAuthPoll() {
    if (oauthPollTimer) clearInterval(oauthPollTimer);
    oauthPollTimer = null;
    oauthPollDeadline = 0;
    oauthPollErrorStreak = 0;
  }

  function patcherlyDebugLog(message) {
    try {
      if (typeof console !== 'undefined' && console.warn) {
        console.warn('[patcherly] ' + message);
      }
    } catch (_) {}
  }

  async function startOAuth(event) {
    if (event) event.preventDefault();
    var button = $('patcherly-btn-connect-oauth');
    if (button) button.disabled = true;
    hideTargetNotRegistered();
    renderSteps();
    showSteps();
    setStep('contact', 'running');
    try {
      var form = new FormData();
      form.set('action', 'patcherly_oauth_start');
      form.set('_ajax_nonce', cfg.ajaxNonce || '');
      if (cfg.siteHost) form.set('target_host', cfg.siteHost);
      var response = await fetch(ajaxurl, { method: 'POST', body: form });
      if (!response.ok) {
        var parsed = await parseFailure(response);
        var errorCode = parsed.payload && typeof parsed.payload.error === 'string'
          ? parsed.payload.error
          : '';
        setStep('contact', 'error', parsed.message);
        if (TARGETS_LINK_ERRORS[errorCode]) {
          attachTargetsLinkToStep('contact', parsed.payload && parsed.payload.targets_url);
        }
        if (errorCode === 'target_not_registered') showTargetNotRegistered(parsed.payload);
        if (button) button.disabled = false;
        return;
      }
      var json = await response.json();
      if (!json.success) {
        var rawCode = json.data && json.data.error ? json.data.error : '';
        var message = json.data && json.data.message
          ? json.data.message
          : (rawCode ? (FRIENDLY_OAUTH_ERROR[rawCode] || prettifyErrorCode(rawCode)) : copy('pairing_error', 'Connection failed'));
        setStep('contact', 'error', message);
        if (button) button.disabled = false;
        return;
      }
      var data = json.data;
      setStep('contact', 'success', copy('connected_to', 'Connected to') + ' ' + (data.server_url || cfg.url || 'api.patcherly.com'));
      setStep('device', 'success', '');
      renderDeviceCode(data.user_code || '');
      setStep('approve', 'running', copy('approve_pending', 'Open the Patcherly dashboard to approve this site.'));
      var verifyUrl = data.verification_uri_complete || data.verification_uri || '';
      var approve = document.querySelector('#patcherly-oauth-steps li[data-step="approve"]');
      if (approve && verifyUrl) {
        var oldCta = approve.querySelector('.patcherly-step__cta');
        if (oldCta) oldCta.remove();
        var cta = document.createElement('div');
        cta.className = 'patcherly-step__cta';
        var link = document.createElement('a');
        link.href = verifyUrl;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.className = 'button button-primary';
        link.textContent = copy('confirm_code', 'Confirm your code');
        cta.appendChild(link);
        if (data.user_code) {
          var code = document.createElement('span');
          code.className = 'patcherly-step__code';
          code.textContent = data.user_code;
          cta.appendChild(code);
        }
        approve.appendChild(cta);
      }
      var ttl = typeof data.expires_in === 'number' && data.expires_in > 0 ? data.expires_in : 1800;
      oauthPollDeadline = Date.now() + (ttl * 1000) + 60000;
      oauthPollErrorStreak = 0;
      oauthPollTimer = setInterval(function(){ pollOAuth(data.device_code); }, 5000);
    } catch (_) {
      setNetworkErrorStep('contact');
      if (button) button.disabled = false;
    }
  }

  async function pollOAuth(deviceCode) {
    if (oauthPollDeadline && Date.now() > oauthPollDeadline) {
      stopOAuthPoll();
      setStep('approve', 'error', copy('pairing_timeout', 'Connection code expired before it was approved. Click Connect with Patcherly again to start over.'));
      var timeoutButton = $('patcherly-btn-connect-oauth');
      if (timeoutButton) timeoutButton.disabled = false;
      return;
    }
    if (document.visibilityState === 'hidden') return;
    try {
      var form = new FormData();
      form.set('action', 'patcherly_oauth_poll');
      form.set('device_code', deviceCode);
      form.set('_ajax_nonce', cfg.ajaxNonce || '');
      var response = await fetch(ajaxurl, { method: 'POST', body: form });
      if (response.status === 202) {
        oauthPollErrorStreak = 0;
        return;
      }
      if (response.ok) {
        var json = await response.json().catch(function(){ return {}; });
        if (json.success && json.data && json.data.access_token) {
          stopOAuthPoll();
          setStep('approve', 'success');
          setStep('save', 'success');
          setStep('done', 'success', copy('pairing_done', 'All set - reloading the page.'));
          setTimeout(function(){ location.reload(); }, 1000);
          return;
        }
        oauthPollErrorStreak++;
      } else if (response.status >= 500) {
        var transientFailure = null;
        try { transientFailure = await parseFailure(response); } catch (_) {}
        patcherlyDebugLog(
          'pollOAuth transient ' + response.status +
          (transientFailure && transientFailure.message ? ': ' + transientFailure.message : '')
        );
        oauthPollErrorStreak++;
      } else {
        stopOAuthPoll();
        var parsed = await parseFailure(response);
        setStep('approve', 'error', parsed.message);
        var button = $('patcherly-btn-connect-oauth');
        if (button) button.disabled = false;
        return;
      }
    } catch (_) {
      oauthPollErrorStreak++;
    }
    if (oauthPollErrorStreak >= OAUTH_POLL_MAX_ERROR_STREAK) {
      stopOAuthPoll();
      setNetworkErrorStep('approve');
      var networkButton = $('patcherly-btn-connect-oauth');
      if (networkButton) networkButton.disabled = false;
    }
  }

  function updateLastCollectedLabel(timestamp) {
    var wrap = $('patcherly-site-context-last-collected');
    var value = $('patcherly-site-context-last-collected-value');
    if (!wrap || !value) return;
    var seconds = typeof timestamp === 'number' && timestamp > 0
      ? timestamp
      : Math.floor(Date.now() / 1000);
    wrap.setAttribute('data-ts', String(seconds));
    try { value.textContent = new Date(seconds * 1000).toLocaleString(); }
    catch (_) { value.textContent = String(seconds); }
  }

  function refreshStatusElForButton(button) {
    if (!button || !button.id) return $('patcherly-refresh-context-status');
    var suffix = button.id.replace(/^patcherly-btn-refresh-context-?/, '');
    if (!suffix) return $('patcherly-refresh-context-status');
    return $('patcherly-refresh-context-' + suffix + '-status') || $('patcherly-refresh-context-status');
  }

  async function refreshContext(event) {
    if (event) event.preventDefault();
    var button = event && event.currentTarget ? event.currentTarget : $('patcherly-btn-refresh-context');
    var status = refreshStatusElForButton(button);
    if (button) button.disabled = true;
    setText(status, 'Refreshing site context…');
    try {
      var form = new FormData();
      form.set('action', 'patcherly_refresh_context');
      form.set('_ajax_nonce', cfg.adminNonce || '');
      var response = await fetch(ajaxurl, { method: 'POST', body: form });
      if (!response.ok) {
        var parsed = await parseFailure(response);
        throw new Error(parsed.message);
      }
      var json = await response.json().catch(function(){ return {}; });
      if (!json.success) throw new Error((json.data && (json.data.message || json.data.error)) || 'Refresh failed');
      setText(status, 'Site context refreshed.');
      updateLastCollectedLabel(Math.floor(Date.now() / 1000));
    } catch (error) {
      setText(status, 'Refresh failed: ' + (error.message || 'Unknown'));
    } finally {
      if (button) button.disabled = false;
    }
  }

  async function disconnectOAuth(event) {
    if (event) event.preventDefault();
    var btn = (event && event.currentTarget) ? event.currentTarget : $('patcherly-btn-disconnect-oauth');
    var reconnect = !!(btn && (
      btn.getAttribute('data-patcherly-reconnect') === '1' ||
      /re-?connect/i.test(btn.textContent || '')
    ));
    var confirmMsg = reconnect
      ? (copy('reconnect_confirm', 'Clear this site\'s connection and start Connect with Patcherly again? You will need to approve the site at the Patcherly dashboard.'))
      : 'Disconnect Patcherly? Errors won\'t sync until you connect again.';
    if (!confirm(confirmMsg)) return;
    try {
      var form = new FormData();
      form.set('action', 'patcherly_oauth_disconnect');
      form.set('_ajax_nonce', cfg.ajaxNonce || '');
      var response = await fetch(ajaxurl, { method: 'POST', body: form });
      if (!response.ok) {
        var parsed = await parseFailure(response);
        throw new Error(parsed.message);
      }
      hideSteps();
      if (reconnect) {
        // One-click Re-Connect: wipe local tokens then start device OAuth in-page (no reload).
        await startOAuth();
        return;
      }
      setTimeout(function(){ location.reload(); }, 600);
    } catch (error) {
      alert((reconnect ? 'Re-Connect failed: ' : 'Disconnect failed: ') + (error.message || 'Unknown'));
    }
  }

  var CONTEXT_CONSENT_META = {
    full: { label: 'Full', tooltip: 'Active plugins, theme, ACF, WooCommerce, CPTs, taxonomies, server limits and DB engine are shared with Patcherly.', kind: 'full' },
    minimal: { label: 'Minimal', tooltip: 'Only WordPress, PHP and DB engine versions are shared with Patcherly.', kind: 'minimal' },
    off: { label: 'Off', tooltip: 'No site context is collected or uploaded. Patcherly sees only the error log line.', kind: 'off' },
    pending: { label: 'Not set', tooltip: 'You haven\'t picked a context-sharing tier yet. Use the banner above or the Advanced setting.', kind: 'pending' }
  };

  function updateContextSharingRow(consent) {
    var cell = $('patcherly-context-sharing');
    if (!cell) return;
    var key = consent === '' || consent === 'pending' ? 'pending' : consent;
    var meta = CONTEXT_CONSENT_META[key] || CONTEXT_CONSENT_META.pending;
    cell.setAttribute('data-consent', key);
    var badge = cell.querySelector('.patcherly-context-badge');
    if (!badge) return;
    badge.className = 'patcherly-context-badge patcherly-context-badge--' + meta.kind;
    badge.setAttribute('title', meta.tooltip);
    badge.textContent = meta.label;
  }

  function refreshAllStatus() {
    if (!window.PatcherlyStatus) return;
    if ($('patcherly-status-panel')) window.PatcherlyStatus.refresh('patcherly');
    if ($('patcherly-paths-status-panel')) window.PatcherlyStatus.refresh('patcherly-paths');
  }

  function bindPostPairOnboarding() {
    var banner = $('patcherly-post-pair-setup-banner');
    if (!banner) return;
    var nonce = banner.getAttribute('data-nonce') || cfg.adminNonce || '';
    var selectedTier = 'full';
    var tierButtons = banner.querySelectorAll('button[data-consent]');
    tierButtons.forEach(function(button) {
      button.addEventListener('click', function(event) {
        event.preventDefault();
        selectedTier = button.getAttribute('data-consent') || 'full';
        tierButtons.forEach(function(item) {
          item.classList.toggle('button-primary', item === button);
        });
      });
    });
    if (tierButtons.length) tierButtons[0].classList.add('button-primary');
    var getStarted = $('patcherly-onboarding-get-started');
    if (!getStarted) return;
    getStarted.addEventListener('click', async function(event) {
      event.preventDefault();
      var message = banner.querySelector('.patcherly-consent-banner__msg');
      var rescueBox = $('patcherly-onboarding-rescue-opt-in');
      var wpconfigBox = $('patcherly-onboarding-wpconfig-opt-in');
      getStarted.disabled = true;
      tierButtons.forEach(function(button){ button.disabled = true; });
      if (message) message.textContent = '';
      try {
        var form = new FormData();
        form.set('action', 'patcherly_save_post_pair_setup');
        form.set('value', selectedTier);
        form.set('rescue_mu', rescueBox && rescueBox.checked ? '1' : '0');
        form.set('rescue_wpconfig', wpconfigBox && !wpconfigBox.disabled && wpconfigBox.checked ? '1' : '0');
        form.set('_ajax_nonce', nonce);
        var response = await fetch(ajaxurl, { method: 'POST', body: form });
        if (!response.ok) {
          var parsed = await parseFailure(response);
          throw new Error(parsed.message);
        }
        var json = await response.json();
        if (!json || json.success === false) {
          throw new Error((json && json.data && json.data.error) || 'Could not save your choices.');
        }
        updateContextSharingRow((json.data && json.data.consent) || selectedTier);
        var warnings = json.data && Array.isArray(json.data.warnings)
          ? json.data.warnings.filter(Boolean)
          : [];
        banner.classList.add('is-saved');
        if (warnings.length) {
          if (message) message.textContent = warnings.join(' ');
          if (window.console && console.warn) console.warn('Patcherly Get started warnings:', warnings.join('; '));
          window.setTimeout(function(){ banner.setAttribute('hidden', 'hidden'); }, 8000);
        } else {
          banner.setAttribute('hidden', 'hidden');
        }
        refreshAllStatus();
      } catch (error) {
        if (message) message.textContent = error && error.message ? error.message : 'Could not save your choices.';
        getStarted.disabled = false;
        tierButtons.forEach(function(button){ button.disabled = false; });
      }
    });
  }

  function bindCustomLogDismiss() {
    document.querySelectorAll('.patcherly-dismiss-custom-log-notice').forEach(function(button) {
      button.addEventListener('click', async function(event) {
        event.preventDefault();
        var box = button.closest('.patcherly-wp-custom-log-notice');
        var nonce = (box && box.getAttribute('data-nonce')) || cfg.adminNonce || '';
        try {
          var form = new FormData();
          form.set('action', 'patcherly_dismiss_custom_log_notice');
          form.set('_ajax_nonce', nonce);
          var response = await fetch(ajaxurl, { method: 'POST', body: form });
          if (!response.ok) return;
          var json = await response.json().catch(function(){ return null; });
          if (json && json.success === false) return;
          if (box) box.setAttribute('hidden', 'hidden');
        } catch (_) {}
      });
    });
  }

  function bind() {
    var connect = $('patcherly-btn-connect-oauth');
    if (connect) connect.addEventListener('click', startOAuth);
    var disconnect = $('patcherly-btn-disconnect-oauth');
    if (disconnect) disconnect.addEventListener('click', disconnectOAuth);
    document.querySelectorAll('.patcherly-refresh-context-btn').forEach(function(button) {
      button.addEventListener('click', refreshContext);
    });
    bindPostPairOnboarding();
    bindCustomLogDismiss();
  }

  if (document.readyState === 'complete') bind();
  else window.addEventListener('load', bind);
})();
