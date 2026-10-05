/**
 * Patcherly Home page - metrics cards, usage bar, audit table, account status bar.
 * Populated from smart_connect / connector-status via PatcherlyStatus.refresh().
 */
(function () {
  if (window.PatcherlyHome) return;

  var cfg = window.PATCHERLY_HOME || {};
  var DEMO = cfg.demoMetrics || {};

  // Digit separators follow number_format (same as dashboard formatCurrency);
  // currency code is independent. Null metrics_format keeps EUR + comma defaults.
  // Date/time prefer Patcherly profile prefs from metrics_format; fall back to WP site cfg.
  var metricsFormat = {
    display_currency: 'EUR',
    number_format: 'comma',
    timezone: null,
    date_format: null,
    time_format: null
  };

  function applyMetricsFormat(data) {
    var mf = data && data.metrics_format;
    if (!mf) return;
    if (mf.display_currency) {
      metricsFormat.display_currency = String(mf.display_currency).toUpperCase();
    }
    metricsFormat.number_format = mf.number_format === 'dot' ? 'dot' : 'comma';
    if (mf.timezone) metricsFormat.timezone = String(mf.timezone);
    if (mf.date_format) metricsFormat.date_format = String(mf.date_format);
    if (mf.time_format === '12h' || mf.time_format === '24h') {
      metricsFormat.time_format = mf.time_format;
    }
  }

  function numberLocale() {
    return metricsFormat.number_format === 'comma' ? 'de-DE' : 'en-US';
  }

  /** Map dashboard date_format prefs to PHP tokens for formatDateTimeIso. */
  function mapPatcherlyDateFormat(df) {
    switch (String(df || '')) {
      case 'mm/dd/yyyy': return 'm/d/Y';
      case 'yyyy-mm-dd': return 'Y-m-d';
      case 'dd-mm-yyyy': return 'd-m-Y';
      case 'mm-dd-yyyy': return 'm-d-Y';
      case 'dd/mm/yyyy':
      default: return 'd/m/Y';
    }
  }

  function mapPatcherlyTimeFormat(tf) {
    return tf === '12h' ? 'g:i A' : 'H:i';
  }

  function $(id) { return document.getElementById(id); }

  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatNum(n) {
    if (n === null || n === undefined || isNaN(n)) return ' - ';
    return Number(n).toLocaleString(numberLocale(), { maximumFractionDigits: 0 });
  }

  function formatMoney(n) {
    if (n === null || n === undefined || isNaN(n)) return ' - ';
    var currency = metricsFormat.display_currency || 'EUR';
    try {
      return new Intl.NumberFormat(numberLocale(), {
        style: 'currency',
        currency: currency,
        maximumFractionDigits: 0
      }).format(Number(n));
    } catch (_) {
      return String(n);
    }
  }

  function formatHours(n) {
    if (n === null || n === undefined || isNaN(n)) return ' - ';
    return Number(n).toLocaleString(numberLocale(), { maximumFractionDigits: 1 }) + ' h';
  }

  function formatDateTime(iso) {
    if (!iso) return ' - ';
    var F = window.PatcherlyFormat;
    if (F && F.formatDateTimeIso) {
      var tz = metricsFormat.timezone || cfg.timezone;
      var dateFmt = metricsFormat.date_format
        ? mapPatcherlyDateFormat(metricsFormat.date_format)
        : cfg.date_format;
      var timeFmt = metricsFormat.time_format
        ? mapPatcherlyTimeFormat(metricsFormat.time_format)
        : cfg.time_format;
      var hour12 = metricsFormat.time_format
        ? metricsFormat.time_format === '12h'
        : cfg.hour12;
      // Prefer Patcherly profile prefs from metrics_format; fall back to WP site cfg.timezone etc.
      return F.formatDateTimeIso(iso, {
        timezone: tz,
        locale: cfg.locale,
        hour12: hour12,
        date_format: dateFmt,
        time_format: timeFmt
      });
    }
    try { return new Date(iso).toLocaleString(); }
    catch (_) { return iso; }
  }

  function billingUrlFromData(data) {
    return (data && data.billing_upgrade_url) || cfg.billingUpgradeUrl || '';
  }

  function hasAdvancedAnalytics(data) {
    if (!data) return false;
    var v = data.entitlement_advanced_analytics;
    return v === true || v === 'true';
  }

  function planCanUpgradeFromName(planName, apiFlag) {
    if (typeof apiFlag === 'boolean') return apiFlag;
    if (!planName) return true;
    var ranks = { Personal: 1, Core: 2, Pro: 3, 'Pro Plus': 4 };
    var normalized = String(planName).trim().toLowerCase();
    var rank = 0;
    Object.keys(ranks).forEach(function (label) {
      if (label.toLowerCase() === normalized) rank = ranks[label];
    });
    if (!rank) return true;
    var maxRank = 0;
    Object.keys(ranks).forEach(function (label) {
      if (ranks[label] > maxRank) maxRank = ranks[label];
    });
    return rank < maxRank;
  }

  function setCard(id, value) {
    var el = $(id);
    if (!el) return;
    var valEl = el.querySelector('.patcherly-metric-card__value');
    if (valEl) valEl.textContent = value;
  }

  function setOverviewPeriod(label) {
    var el = $('patcherly-metrics-period');
    if (!el) return;
    el.textContent = String(label || defaultMetricsPeriod());
    el.hidden = false;
  }

  function showMetricsDashboardLink(url) {
    var link = $('patcherly-metrics-dashboard-link');
    if (!link) return;
    var href = url || cfg.metricsDashboardUrl || '';
    if (href) {
      link.href = href;
      link.hidden = false;
    } else {
      link.hidden = true;
    }
  }

  function defaultMetricsPeriod() {
    return (cfg.i18n && cfg.i18n.metricsPeriod) ? cfg.i18n.metricsPeriod : 'Last 30 days';
  }

  function showUpgradeBar(show, url) {
    var bar = $('patcherly-metrics-upgrade');
    if (!bar) return;
    if (!show) {
      bar.hidden = true;
      return;
    }
    bar.hidden = false;
    var link = bar.querySelector('a');
    if (link && url) link.href = url;
  }

  function setAccountLoading(visible) {
    var loadEl = $('patcherly-account-loading');
    if (!loadEl) return;
    if (visible) {
      var label = (cfg.i18n && cfg.i18n.accountLoadingWorkspace)
        ? cfg.i18n.accountLoadingWorkspace
        : 'Loading Workspace info';
      loadEl.textContent = label;
    }
    loadEl.hidden = !visible;
  }

  function renderAccountBar(data) {
    var planEl = $('patcherly-account-plan');
    if (!planEl) return;
    var paired = !!(cfg.oauthConnected || (data && data.target_id));
    var incomplete = paired && (!data || data.tenant_id == null || String(data.tenant_id).trim() === '');
    if (!paired || incomplete) {
      planEl.hidden = true;
      planEl.textContent = '';
      setAccountLoading(false);
      return;
    }
    var planName = data && data.tenant_plan_name;
    if (!planName) {
      planEl.hidden = true;
      planEl.textContent = '';
      setAccountLoading(true);
      return;
    }
    setAccountLoading(false);
    var billingUrl = billingUrlFromData(data);
    var planLabel = (cfg.i18n && cfg.i18n.planLabel) ? cfg.i18n.planLabel : 'Plan';
    var workspaceLabel = (cfg.i18n && cfg.i18n.workspaceLabel) ? cfg.i18n.workspaceLabel : 'Workspace';
    var tenantName = data && data.tenant_name ? String(data.tenant_name).trim() : '';
    planEl.hidden = false;
    planEl.textContent = '';
    planEl.appendChild(document.createTextNode(planLabel + ': '));
    if (billingUrl) {
      var a = document.createElement('a');
      a.href = billingUrl;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = String(planName);
      a.title = planCanUpgradeFromName(planName, data && data.tenant_plan_can_upgrade)
        ? 'View billing and upgrade your plan'
        : 'View billing and manage your subscription';
      planEl.appendChild(a);
    } else {
      planEl.appendChild(document.createTextNode(String(planName)));
    }
    if (tenantName) {
      planEl.appendChild(document.createTextNode(' · ' + workspaceLabel + ': ' + tenantName));
    }
  }

  function usageCapLabel(used, cap, unlimited) {
    if (unlimited) {
      return formatNum(used) + ' / ∞';
    }
    return formatNum(used) + ' / ' + formatNum(cap);
  }

  function usagePct(used, cap) {
    if (cap == null || cap < 0) return 0;
    if (!cap) return used > 0 ? 100 : 0;
    return Math.min(100, Math.round((used / Math.max(cap, 1)) * 100));
  }

  function setUsageMeter(id, used, cap, unlimited) {
    var el = $(id);
    if (!el) return;
    var valEl = el.querySelector('.patcherly-usage-meter__value');
    var barEl = el.querySelector('.patcherly-usage-meter__bar span');
    if (valEl) valEl.textContent = usageCapLabel(used, cap, unlimited);
    if (barEl) {
      if (unlimited) {
        barEl.style.width = '0%';
        el.querySelector('.patcherly-usage-meter__bar').hidden = true;
      } else {
        el.querySelector('.patcherly-usage-meter__bar').hidden = false;
        barEl.style.width = usagePct(used, cap) + '%';
      }
    }
  }

  function renderUsageBar(data) {
    applyMetricsFormat(data);
    var bar = $('patcherly-usage-bar');
    if (!bar) return;
    var paired = cfg.oauthConnected || (data && data.target_id);
    var usage = data && data.tenant_usage;
    if (!paired || !usage) {
      bar.hidden = true;
      return;
    }
    bar.hidden = false;
    var billingUrl = billingUrlFromData(data);
    var upgrade = $('patcherly-usage-upgrade');
    if (upgrade && billingUrl) upgrade.href = billingUrl;

    var fixesUnlimited = !!usage.fixes_quota_unlimited_byok;
    setUsageMeter(
      'patcherly-usage-fixes',
      Number(usage.fixes_used || 0),
      Number(usage.fixes_monthly_limit || 0),
      fixesUnlimited
    );
    setUsageMeter(
      'patcherly-usage-targets',
      Number(usage.targets_count || 0),
      Number(usage.max_targets || 0),
      false
    );
    setUsageMeter(
      'patcherly-usage-users',
      Number(usage.users_count || 0),
      Number(usage.max_users || 0),
      false
    );

    var resetEl = $('patcherly-usage-reset');
    if (resetEl) {
      var resetPrefix = (cfg.i18n && cfg.i18n.usageResets) || 'Usage resets on';
      if (usage.period_reset && !fixesUnlimited) {
        resetEl.textContent = resetPrefix + ' ' + formatDateTime(usage.period_reset);
      } else if (fixesUnlimited) {
        resetEl.textContent = (cfg.i18n && cfg.i18n.usageFixesUnlimited) || 'Fixes used: unlimited on your plan';
      } else {
        resetEl.textContent = '';
      }
    }
  }

  function t(key, fallback) {
    return (cfg.i18n && cfg.i18n[key]) ? cfg.i18n[key] : fallback;
  }

  function settingsAction() {
    var href = cfg.settingsUrl || '';
    if (!href) return null;
    return {
      href: href,
      label: t('liveOpenSettings', 'Open Settings →')
    };
  }

  /**
   * Append i18n copy that may include <strong>…</strong> (trusted localize strings only).
   * Everything else is text - no innerHTML of arbitrary markup.
   */
  function appendInlineMarkup(parent, text) {
    var src = String(text || '');
    if (!src) return;
    var re = /<strong>([\s\S]*?)<\/strong>/gi;
    var last = 0;
    var m;
    while ((m = re.exec(src)) !== null) {
      if (m.index > last) {
        parent.appendChild(document.createTextNode(src.slice(last, m.index)));
      }
      var strong = document.createElement('strong');
      strong.textContent = m[1];
      parent.appendChild(strong);
      last = m.index + m[0].length;
    }
    if (last < src.length) {
      parent.appendChild(document.createTextNode(src.slice(last)));
    }
  }

  function setMonitoringLiveText(title, msg, eyebrow, action) {
    var titleEl = $('patcherly-monitoring-live-title');
    var msgEl = $('patcherly-monitoring-live-msg');
    var eyeEl = $('patcherly-monitoring-live-eyebrow');
    if (titleEl) titleEl.textContent = title;
    if (eyeEl) eyeEl.textContent = eyebrow;
    if (!msgEl) return;
    msgEl.textContent = '';
    if (msg) {
      appendInlineMarkup(msgEl, msg);
    }
    if (action && action.href) {
      if (msg) {
        msgEl.appendChild(document.createTextNode(' '));
      }
      var a = document.createElement('a');
      a.href = action.href;
      a.textContent = action.label || t('liveOpenSettings', 'Open Settings →');
      msgEl.appendChild(a);
    }
  }

  function renderMonitoringChecks(items) {
    var list = $('patcherly-monitoring-live-checks');
    if (!list) return;
    if (!items || !items.length) {
      list.hidden = true;
      list.innerHTML = '';
      return;
    }
    var html = '';
    for (var i = 0; i < items.length; i++) {
      var item = items[i] || {};
      html += '<li class="patcherly-monitoring-live__check patcherly-monitoring-live__check--' +
        escHtml(item.kind || 'neutral') + '">' + escHtml(item.label || '') + '</li>';
    }
    list.innerHTML = html;
    list.hidden = false;
  }

  function pathCount(data) {
    if (!data) return 0;
    var preset = Array.isArray(data.preset_log_paths) ? data.preset_log_paths.length : 0;
    var custom = Array.isArray(data.custom_log_paths) ? data.custom_log_paths.length : 0;
    return preset + custom;
  }

  function renderMonitoringLive(data) {
    var root = $('patcherly-monitoring-live');
    if (!root) return;
    var paired = !!(cfg.oauthConnected || (data && data.target_id));
    var incomplete = paired && (!data || data.tenant_id == null || String(data.tenant_id).trim() === '');
    var apiOk = !data || data.api_ok !== false;
    var rescue = (data && data.rescue) || {};
    var rescueInstalled = !!rescue.mu_installed;
    var rescueOptIn = rescue.mu_opt_in !== false;
    var rescuePending = rescueOptIn && !rescueInstalled;
    // Do not treat target_id alone as logs-ok — paired sites always have one after connect.
    var logsOk = paired && !incomplete && pathCount(data) > 0;
    var pending = (data && typeof data.bugs_pending === 'number') ? data.bugs_pending : 0;
    var quiet = pending <= 0;
    var eyebrowLive = t('liveEyebrow', 'Monitoring live for bugs');
    var eyebrowPaused = t('liveEyebrowPaused', 'Monitoring paused');

    if (!paired) {
      root.setAttribute('data-state', 'unpaired');
      setMonitoringLiveText(
        t('liveTitleUnpaired', 'Not monitoring yet'),
        t('liveMsgUnpaired', 'Use Connect above so Patcherly can watch for bugs around the clock. Keep the plugin active even when you see no errors - quiet means it is working.'),
        eyebrowPaused
      );
      renderMonitoringChecks([
        { kind: 'err', label: t('liveCheckNeedsConnect', 'Connect required') },
        { kind: 'neutral', label: t('liveCheckLogs', 'Logs watched') },
        { kind: 'neutral', label: t('liveCheckRescue', 'Emergency Rescue') }
      ]);
      return;
    }

    if (incomplete) {
      root.setAttribute('data-state', 'warn');
      setMonitoringLiveText(
        t('liveTitleIncomplete', 'Connection unverified'),
        t('liveMsgIncomplete', 'Use Re-Connect Account above so monitoring can continue.'),
        eyebrowPaused
      );
      renderMonitoringChecks([
        { kind: 'warn', label: t('liveCheckNeedsConnect', 'Connect required') }
      ]);
      return;
    }

    if (!apiOk) {
      root.setAttribute('data-state', 'warn');
      setMonitoringLiveText(
        t('liveTitleApi', 'Cannot reach Patcherly'),
        t('liveMsgApi', 'The Patcherly API is unreachable right now. Check the server URL in Settings, or wait while the plugin keeps trying.'),
        eyebrowLive,
        settingsAction()
      );
      renderMonitoringChecks([
        { kind: 'ok', label: t('liveCheckConnected', 'Connected') },
        { kind: 'warn', label: t('liveCheckLogs', 'Logs watched') },
        {
          kind: rescueInstalled ? 'ok' : (rescuePending ? 'warn' : 'neutral'),
          label: rescueInstalled
            ? t('liveCheckRescue', 'Emergency Rescue')
            : (rescuePending
              ? t('liveCheckRescuePending', 'Rescue pending')
              : t('liveCheckRescueOff', 'Rescue off'))
        }
      ]);
      return;
    }

    var checks = [
      { kind: 'ok', label: t('liveCheckConnected', 'Connected') },
      { kind: logsOk ? 'ok' : 'warn', label: t('liveCheckLogs', 'Logs watched') },
      {
        kind: rescueInstalled ? 'ok' : (rescuePending ? 'warn' : 'neutral'),
        label: rescueInstalled
          ? t('liveCheckRescue', 'Emergency Rescue')
          : (rescuePending
            ? t('liveCheckRescuePending', 'Rescue pending')
            : t('liveCheckRescueOff', 'Rescue off'))
      },
      {
        kind: quiet ? 'ok' : 'warn',
        label: quiet
          ? t('liveCheckQuiet', 'No open bugs')
          : (t('liveCheckPending', 'Open bugs') + ' (' + formatNum(pending) + ')')
      }
    ];

    if (!logsOk) {
      root.setAttribute('data-state', 'warn');
      setMonitoringLiveText(
        t('liveTitleLogs', 'Log monitoring needs attention'),
        t('liveMsgLogs', 'No log paths are active for this site. Review log monitoring paths in Settings.'),
        eyebrowLive,
        settingsAction()
      );
      renderMonitoringChecks(checks);
      return;
    }

    if (rescuePending) {
      root.setAttribute('data-state', 'warn');
      setMonitoringLiveText(
        t('liveTitleSetup', 'Finish setup to stay protected'),
        t('liveMsgRescue', 'Connected and watching logs. Enable Emergency Rescue in Settings so Patcherly can still help after a white screen.'),
        eyebrowLive,
        settingsAction()
      );
      renderMonitoringChecks(checks);
      return;
    }

    root.setAttribute('data-state', 'ok');
    setMonitoringLiveText(
      quiet
        ? t('liveTitleOk', 'All systems OK')
        : t('liveTitleWatching', 'Patcherly is monitoring this site'),
      quiet
        ? t('liveMsgQuiet', 'No errors detected yet. Quiet is normal. <strong>Keep this plugin active</strong> so Patcherly can catch the next bug.')
        : t('liveMsgPending', 'Open bugs are waiting for review. Patcherly is still watching this site for new issues.'),
      eyebrowLive
    );
    renderMonitoringChecks(checks);
  }

  function renderMetricsUnpaired() {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'unpaired');
    setOverviewPeriod(defaultMetricsPeriod());
    setCard('patcherly-metric-pending', cfg.i18n && cfg.i18n.pairToStart ? cfg.i18n.pairToStart : 'Connect to see metrics');
    setCard('patcherly-metric-found', '');
    setCard('patcherly-metric-analyzed', '');
    setCard('patcherly-metric-fixed', '');
    setCard('patcherly-metric-time', '');
    setCard('patcherly-metric-money', '');
    showUpgradeBar(false);
    showMetricsDashboardLink();
    renderAccountBar(null);
    renderMonitoringLive(null);
  }

  function renderMetricsStatusIncomplete() {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'incomplete');
    setOverviewPeriod(defaultMetricsPeriod());
    var msg = cfg.i18n && cfg.i18n.metricsStatusIncomplete
      ? cfg.i18n.metricsStatusIncomplete
      : 'Refresh status on Home to load metrics.';
    setCard('patcherly-metric-pending', msg);
    setCard('patcherly-metric-found', '');
    setCard('patcherly-metric-analyzed', '');
    setCard('patcherly-metric-fixed', '');
    setCard('patcherly-metric-time', '');
    setCard('patcherly-metric-money', '');
    showUpgradeBar(false);
    showMetricsDashboardLink();
    renderAccountBar({ tenant_id: null, target_id: cfg.oauthConnected ? '1' : null });
    renderMonitoringLive({ tenant_id: null, target_id: cfg.oauthConnected ? '1' : null });
  }

  function renderMetricsFromSummary(summary, data) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'live');
    setOverviewPeriod(defaultMetricsPeriod());
    var pending = (data && typeof data.bugs_pending === 'number') ? data.bugs_pending : 0;
    setCard('patcherly-metric-pending', formatNum(pending));
    setCard('patcherly-metric-found', formatNum(summary.errors_found));
    setCard('patcherly-metric-analyzed', formatNum(summary.errors_analyzed));
    setCard('patcherly-metric-fixed', formatNum(summary.errors_fixed));
    setCard('patcherly-metric-time', formatHours(summary.time_saved_hours));
    setCard('patcherly-metric-money', formatMoney(summary.money_saved));
    showUpgradeBar(false);
  }

  function renderMetricsDemo(billingUrl, data) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'demo');
    setOverviewPeriod(DEMO.period_label || defaultMetricsPeriod());
    var pending = (data && typeof data.bugs_pending === 'number') ? data.bugs_pending : 0;
    setCard('patcherly-metric-pending', formatNum(pending));
    setCard('patcherly-metric-found', formatNum(DEMO.errors_found || 84));
    setCard('patcherly-metric-analyzed', formatNum(DEMO.errors_analyzed || 76));
    setCard('patcherly-metric-fixed', formatNum(DEMO.errors_fixed || 71));
    setCard('patcherly-metric-time', formatHours(DEMO.time_saved_hours || 38.5));
    setCard('patcherly-metric-money', formatMoney(DEMO.money_saved || 3080));
    showUpgradeBar(true, billingUrl || cfg.billingUpgradeUrl || '');
  }

  function renderMetrics(data) {
    applyMetricsFormat(data);
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (!paired) {
      renderMetricsUnpaired();
      return;
    }
    if (!data || data.tenant_id == null || String(data.tenant_id).trim() === '') {
      renderMetricsStatusIncomplete();
      return;
    }
    showMetricsDashboardLink((data && data.metrics_dashboard_url) || '');
    if (data && data.metrics_summary) {
      renderMetricsFromSummary(data.metrics_summary, data);
      renderMonitoringLive(data);
      return;
    }
    if (data && data.metrics_demo === true) {
      renderMetricsDemo(billingUrlFromData(data), data);
      renderMonitoringLive(data);
      return;
    }
    if (!hasAdvancedAnalytics(data)) {
      renderMetricsDemo(billingUrlFromData(data), data);
      renderMonitoringLive(data);
      return;
    }
    if (data && data.metrics_error) {
      var grid = $('patcherly-metrics-grid');
      if (grid) grid.setAttribute('data-state', 'error');
      setOverviewPeriod(defaultMetricsPeriod());
      setCard('patcherly-metric-pending', cfg.i18n && cfg.i18n.metricsUnavailable ? cfg.i18n.metricsUnavailable : 'Unavailable');
    }
    renderMonitoringLive(data);
  }

  // Collapse long Home recent-error messages; click/Enter toggles full text.
  var RECENT_MSG_COLLAPSE_AT = 96;

  function recentErrorMessageHtml(msg) {
    var text = String(msg || '').trim() || ' - ';
    if (text === ' - ' || text.length <= RECENT_MSG_COLLAPSE_AT) {
      return escHtml(text);
    }
    var hintExpand = t('msgExpandHint', 'Click to expand');
    var preview = text.slice(0, RECENT_MSG_COLLAPSE_AT).replace(/\s+\S*$/, '');
    if (!preview || preview.length < 40) preview = text.slice(0, RECENT_MSG_COLLAPSE_AT);
    preview += '…';
    return '<div class="patcherly-msg patcherly-msg--recent" role="button" tabindex="0" aria-expanded="false"' +
      ' data-full-msg="' + escHtml(text) + '"' +
      ' data-preview-msg="' + escHtml(preview) + '"' +
      ' title="' + escHtml(hintExpand) + '">' +
      '<span class="patcherly-msg__text">' + escHtml(preview) + '</span>' +
      '<span class="patcherly-msg__hint">' + escHtml(hintExpand) + '</span>' +
      '</div>';
  }

  function setRecentMsgExpanded(msgEl, expanded) {
    if (!msgEl) return;
    msgEl.classList.toggle('is-expanded', expanded);
    msgEl.setAttribute('aria-expanded', expanded ? 'true' : 'false');
    var textEl = msgEl.querySelector('.patcherly-msg__text');
    var hintEl = msgEl.querySelector('.patcherly-msg__hint');
    if (textEl) {
      textEl.textContent = expanded
        ? (msgEl.getAttribute('data-full-msg') || textEl.textContent)
        : (msgEl.getAttribute('data-preview-msg') || textEl.textContent);
    }
    if (hintEl) {
      hintEl.textContent = expanded
        ? t('msgCollapseHint', 'Click to collapse')
        : t('msgExpandHint', 'Click to expand');
    }
    msgEl.setAttribute(
      'title',
      expanded ? t('msgCollapseHint', 'Click to collapse') : t('msgExpandHint', 'Click to expand')
    );
  }

  function bindRecentErrorsMsgToggle() {
    var tbody = $('patcherly-recent-errors-tbody');
    if (!tbody || tbody._patcherlyMsgBound) return;
    tbody._patcherlyMsgBound = true;
    tbody.addEventListener('click', function (e) {
      var msgEl = e.target && e.target.closest ? e.target.closest('.patcherly-msg--recent') : null;
      if (!msgEl || !tbody.contains(msgEl)) return;
      e.preventDefault();
      setRecentMsgExpanded(msgEl, !msgEl.classList.contains('is-expanded'));
    });
    tbody.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      var msgEl = e.target && e.target.closest ? e.target.closest('.patcherly-msg--recent') : null;
      if (!msgEl || !tbody.contains(msgEl)) return;
      e.preventDefault();
      setRecentMsgExpanded(msgEl, !msgEl.classList.contains('is-expanded'));
    });
  }

  function renderRecentErrors(data) {
    var tbody = $('patcherly-recent-errors-tbody');
    var footerLink = $('patcherly-recent-errors-plugin-link');
    var colSpan = 4;
    if (!tbody) return;
    var rows = (data && data.recent_errors) || [];
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (footerLink) {
      footerLink.hidden = !paired;
      if (cfg.i18n && cfg.i18n.viewErrorsPlugin) {
        footerLink.textContent = cfg.i18n.viewErrorsPlugin;
      }
    }
    if (!paired) {
      tbody.innerHTML = '<tr><td colspan="' + colSpan + '" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.pairToStartErrors ? cfg.i18n.pairToStartErrors : 'Connect to see recent errors') +
        '</td></tr>';
      return;
    }
    if (!rows.length) {
      tbody.innerHTML = '<tr><td colspan="' + colSpan + '" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.noRecentErrors ? cfg.i18n.noRecentErrors : 'No recent errors for this site') +
        '</td></tr>';
      return;
    }
    var fmt = window.PatcherlyFormat;
    var html = '';
    var limit = Math.min(rows.length, 3);
    for (var i = 0; i < limit; i++) {
      var row = rows[i] || {};
      var statusCell = (fmt && fmt.statusBadgeHtml)
        ? fmt.statusBadgeHtml(row.status, row)
        : escHtml(row.status || ' - ');
      var severityCell = (fmt && fmt.severityBadgeHtml)
        ? fmt.severityBadgeHtml(row.severity)
        : escHtml(row.severity || ' - ');
      var msg = String(row.message || '').trim() || ' - ';
      html += '<tr>' +
        '<td>' + formatDateTime(row.created_at) + '</td>' +
        '<td>' + statusCell + '</td>' +
        '<td>' + severityCell + '</td>' +
        '<td class="patcherly-msg-cell">' + recentErrorMessageHtml(msg) + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = html;
  }

  function renderAudit(data) {
    var tbody = $('patcherly-audit-tbody');
    var panel = $('patcherly-audit-panel');
    var auditLink = $('patcherly-audit-dashboard-link');
    var auditFmt = window.PatcherlyAuditFormat;
    var colSpan = 5;
    if (!tbody) return;
    var events = (data && data.recent_audit_events) || [];
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (auditLink) {
      var auditUrl = (data && data.audit_dashboard_url) || cfg.auditDashboardUrl || '';
      if (paired && auditUrl) {
        auditLink.href = auditUrl;
        auditLink.hidden = false;
      } else {
        auditLink.hidden = true;
      }
    }
    if (!paired) {
      tbody.innerHTML = '<tr><td colspan="' + colSpan + '" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.pairToStartAudit ? cfg.i18n.pairToStartAudit : 'Connect to see audit events') +
        '</td></tr>';
      return;
    }
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="' + colSpan + '" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.noAudit ? cfg.i18n.noAudit : 'No audit events yet for this site') +
        '</td></tr>';
      return;
    }
    var linkCtx = {
      metrics_dashboard_url: data && data.metrics_dashboard_url,
      dashboardUrl: cfg.dashboardUrl || '',
      audit_dashboard_url: (data && data.audit_dashboard_url) || cfg.auditDashboardUrl || '',
      auditDashboardUrl: (data && data.audit_dashboard_url) || cfg.auditDashboardUrl || '',
      targets_focus_url: data && data.targets_focus_url,
      target_id: data && data.target_id
    };
    var html = '';
    var limit = Math.min(events.length, 3);
    for (var i = 0; i < limit; i++) {
      var ev = events[i];
      var eventCell = auditFmt ? auditFmt.eventBadgeHtml(ev) : (ev.event_type || ' - ');
      var catCell = auditFmt ? auditFmt.categoryBadgeHtml(ev.event_category) : (ev.event_category || ' - ');
      var actorCell = auditFmt ? auditFmt.formatActor(ev, cfg.i18n) : (ev.actor_display || ev.actor || ' - ');
      var actionCell = auditFmt ? auditFmt.actionCellHtml(ev, linkCtx, cfg.i18n) : ' - ';
      html += '<tr>' +
        '<td>' + formatDateTime(ev.timestamp) + '</td>' +
        '<td>' + eventCell + '</td>' +
        '<td>' + catCell + '</td>' +
        '<td>' + actorCell + '</td>' +
        '<td class="patcherly-audit-table__actions">' + actionCell + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = html;
    if (panel) panel.removeAttribute('hidden');
  }

  function scrollToPair() {
    var block = $('patcherly-hero') || $('patcherly-pair-block');
    if (block) block.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function focusUrlFromData(data) {
    if (data && typeof data.targets_focus_url === 'string' && data.targets_focus_url) {
      return data.targets_focus_url;
    }
    if (data && data.target_id != null && cfg.dashboardUrl) {
      return String(cfg.dashboardUrl).replace(/\/+$/, '') + '/targets?focus=' + encodeURIComponent(String(data.target_id));
    }
    return '';
  }

  function paintDryRunNotice(on, focusUrl) {
    var el = $('patcherly-dry-run-notice');
    if (!el) return;
    el.style.display = on ? '' : 'none';
    var link = $('patcherly-dry-run-notice-link');
    if (link) {
      if (on && focusUrl) {
        link.href = focusUrl;
        link.style.display = '';
      } else {
        link.style.display = 'none';
      }
    }
  }

  function isDashboardModeOn(value) {
    // Strict boolean preferred; coerce common API/string shapes without treating
    // unrelated truthy junk (objects, non-empty strings) as ON.
    return value === true || value === 1 || value === '1' || value === 'true';
  }

  function paintModeToggles(data) {
    var wrap = $('patcherly-mode-toggles');
    var dryBtn = $('patcherly-btn-dry-run-off');
    var testBtn = $('patcherly-btn-test-mode-off');
    if (!wrap || !dryBtn || !testBtn) return;
    // Independently: show each OFF button only when that mode is ON from the dashboard.
    var dryOn = isDashboardModeOn(data && data.dry_run);
    var testOn = isDashboardModeOn(data && data.ingest_test_enabled);
    dryBtn.hidden = !dryOn;
    testBtn.hidden = !testOn;
    wrap.hidden = !(dryOn || testOn);
    dryBtn.disabled = !dryOn;
    testBtn.disabled = !testOn;
    if (dryOn) dryBtn.textContent = 'Turn Dry-run off';
    if (testOn) testBtn.textContent = 'Turn Test Mode off';
  }

  function applyStatusModes(data) {
    paintDryRunNotice(isDashboardModeOn(data && data.dry_run), focusUrlFromData(data));
    paintModeToggles(data || {});
  }

  function postConnectorModes(payload) {
    var fd = new FormData();
    fd.set('action', 'patcherly_connector_modes');
    fd.set('_ajax_nonce', cfg.adminNonce || '');
    Object.keys(payload).forEach(function (k) {
      fd.set(k, payload[k]);
    });
    return fetch((typeof ajaxurl !== 'undefined' ? ajaxurl : ''), { method: 'POST', body: fd })
      .then(function (r) { return r.json().then(function (j) { return { ok: r.ok, j: j }; }); });
  }

  function bindAccountBar() {
    var pairBtn = $('patcherly-account-bar-pair');
    if (pairBtn) {
      pairBtn.addEventListener('click', function (e) {
        e.preventDefault();
        scrollToPair();
        var connect = $('patcherly-btn-connect-oauth');
        if (connect) connect.focus();
      });
    }
    var dryBtn = $('patcherly-btn-dry-run-off');
    if (dryBtn && !dryBtn._patcherlyBound) {
      dryBtn._patcherlyBound = true;
      dryBtn.addEventListener('click', function () {
        dryBtn.disabled = true;
        postConnectorModes({ dry_run: '0' }).then(function (res) {
          var data = (res.j && (res.j.data || res.j)) || {};
          if (!res.ok || (res.j && res.j.success === false)) {
            dryBtn.disabled = false;
            window.alert((data && data.error) || 'Could not turn Dry-run off');
            return;
          }
          applyStatusModes({
            dry_run: data.dry_run === true,
            ingest_test_enabled: data.ingest_test_enabled === true,
            targets_focus_url: focusUrlFromData(data),
            target_id: data.target_id
          });
          if (window.PatcherlyStatus && typeof window.PatcherlyStatus.refresh === 'function') {
            try { window.PatcherlyStatus.refresh(); } catch (_) { /* ignore */ }
          }
        }).catch(function () {
          dryBtn.disabled = false;
        });
      });
    }
    var testBtn = $('patcherly-btn-test-mode-off');
    if (testBtn && !testBtn._patcherlyBound) {
      testBtn._patcherlyBound = true;
      testBtn.addEventListener('click', function () {
        testBtn.disabled = true;
        postConnectorModes({ ingest_test_enabled: '0' }).then(function (res) {
          var data = (res.j && (res.j.data || res.j)) || {};
          if (!res.ok || (res.j && res.j.success === false)) {
            testBtn.disabled = false;
            window.alert((data && data.error) || 'Could not turn Test Mode off');
            return;
          }
          applyStatusModes({
            dry_run: data.dry_run === true,
            ingest_test_enabled: data.ingest_test_enabled === true,
            targets_focus_url: focusUrlFromData(data),
            target_id: data.target_id
          });
          if (window.PatcherlyStatus && typeof window.PatcherlyStatus.refresh === 'function') {
            try { window.PatcherlyStatus.refresh(); } catch (_) { /* ignore */ }
          }
        }).catch(function () {
          testBtn.disabled = false;
        });
      });
    }
  }

  function init() {
    bindAccountBar();
    bindRecentErrorsMsgToggle();
    if (!cfg.oauthConnected) {
      renderMetricsUnpaired();
      renderRecentErrors(null);
      renderAudit(null);
    }
  }

  window.PatcherlyHome = {
    renderAccountBar: renderAccountBar,
    renderUsageBar: renderUsageBar,
    renderMetrics: renderMetrics,
    renderMetricsUnpaired: renderMetricsUnpaired,
    renderMetricsStatusIncomplete: renderMetricsStatusIncomplete,
    renderMonitoringLive: renderMonitoringLive,
    renderRecentErrors: renderRecentErrors,
    renderAudit: renderAudit,
    applyStatusModes: applyStatusModes,
    scrollToPair: scrollToPair,
    init: init
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
