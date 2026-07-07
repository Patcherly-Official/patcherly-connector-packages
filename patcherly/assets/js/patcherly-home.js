/**
 * Patcherly Home page — metrics cards, usage bar, audit table, account status bar.
 * Populated from smart_connect / connector-status via PatcherlyStatus.refresh().
 */
(function () {
  if (window.PatcherlyHome) return;

  var cfg = window.PATCHERLY_HOME || {};
  var DEMO = cfg.demoMetrics || {};

  function $(id) { return document.getElementById(id); }

  function formatNum(n) {
    if (n === null || n === undefined || isNaN(n)) return '—';
    return Number(n).toLocaleString();
  }

  function formatMoney(n) {
    if (n === null || n === undefined || isNaN(n)) return '—';
    return '$' + Number(n).toLocaleString(undefined, { maximumFractionDigits: 0 });
  }

  function formatHours(n) {
    if (n === null || n === undefined || isNaN(n)) return '—';
    return Number(n).toLocaleString(undefined, { maximumFractionDigits: 1 }) + ' h';
  }

  function formatDate(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleDateString(); }
    catch (_) { return iso; }
  }

  function formatDateTime(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleString(); }
    catch (_) { return iso; }
  }

  function billingUrlFromData(data) {
    return (data && data.billing_upgrade_url) || cfg.billingUpgradeUrl || '';
  }

  function hasAdvancedAnalytics(data) {
    return !!(data && data.entitlement_advanced_analytics === true);
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
    if (!label) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.textContent = String(label);
    el.hidden = false;
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

  function renderAccountBar(data) {
    var planEl = $('patcherly-account-plan');
    if (!planEl) return;
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (!paired) {
      planEl.hidden = true;
      planEl.textContent = '';
      return;
    }
    var planName = data && data.tenant_plan_name;
    if (!planName) {
      planEl.hidden = true;
      planEl.textContent = '';
      return;
    }
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
      var periodPrefix = usage.period === 'stripe_billing'
        ? ((cfg.i18n && cfg.i18n.usageThisPeriod) || 'This billing period')
        : ((cfg.i18n && cfg.i18n.usageThisMonth) || 'This month');
      var resetPrefix = (cfg.i18n && cfg.i18n.usageResets) || 'Resets on';
      if (usage.period_reset && !fixesUnlimited) {
        resetEl.textContent = periodPrefix + ' · ' + resetPrefix + ' ' + formatDate(usage.period_reset);
      } else if (fixesUnlimited) {
        resetEl.textContent = periodPrefix + ' · Bugs fixed: unlimited on your plan';
      } else {
        resetEl.textContent = periodPrefix;
      }
    }
  }

  function renderMetricsUnpaired() {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'unpaired');
    setOverviewPeriod('');
    setCard('patcherly-metric-found', cfg.i18n && cfg.i18n.pairToStart ? cfg.i18n.pairToStart : 'Connect to see metrics');
    setCard('patcherly-metric-analyzed', '');
    setCard('patcherly-metric-fixed', '');
    setCard('patcherly-metric-time', '');
    setCard('patcherly-metric-money', '');
    showUpgradeBar(false);
    var link = $('patcherly-metrics-dashboard-link');
    if (link) link.hidden = true;
  }

  function renderMetricsFromSummary(summary, periodLabel) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'live');
    setOverviewPeriod(defaultMetricsPeriod());
    setCard('patcherly-metric-found', formatNum(summary.errors_found));
    setCard('patcherly-metric-analyzed', formatNum(summary.errors_analyzed));
    setCard('patcherly-metric-fixed', formatNum(summary.errors_fixed));
    setCard('patcherly-metric-time', formatHours(summary.time_saved_hours));
    setCard('patcherly-metric-money', formatMoney(summary.money_saved));
    showUpgradeBar(false);
  }

  function renderMetricsDemo(billingUrl) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'demo');
    setOverviewPeriod(DEMO.period_label || defaultMetricsPeriod());
    setCard('patcherly-metric-found', formatNum(DEMO.errors_found || 84));
    setCard('patcherly-metric-analyzed', formatNum(DEMO.errors_analyzed || 76));
    setCard('patcherly-metric-fixed', formatNum(DEMO.errors_fixed || 71));
    setCard('patcherly-metric-time', formatHours(DEMO.time_saved_hours || 38.5));
    setCard('patcherly-metric-money', formatMoney(DEMO.money_saved || 3080));
    showUpgradeBar(true, billingUrl || cfg.billingUpgradeUrl || '');
  }

  function renderMetrics(data) {
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (!paired) {
      renderMetricsUnpaired();
      return;
    }
    var link = $('patcherly-metrics-dashboard-link');
    if (link) {
      var metricsUrl = (data && data.metrics_dashboard_url) || cfg.metricsDashboardUrl || '';
      if (metricsUrl && hasAdvancedAnalytics(data)) {
        link.href = metricsUrl;
        link.hidden = false;
      } else {
        link.hidden = true;
      }
    }
    if (!hasAdvancedAnalytics(data)) {
      renderMetricsDemo(billingUrlFromData(data));
      return;
    }
    if (data && data.metrics_summary) {
      renderMetricsFromSummary(data.metrics_summary, data.metrics_summary.period_label);
      return;
    }
    if (data && data.metrics_demo) {
      renderMetricsDemo(billingUrlFromData(data));
      return;
    }
    if (data && data.metrics_error) {
      var grid = $('patcherly-metrics-grid');
      if (grid) grid.setAttribute('data-state', 'error');
      setOverviewPeriod('');
      setCard('patcherly-metric-found', cfg.i18n && cfg.i18n.metricsUnavailable ? cfg.i18n.metricsUnavailable : 'Unavailable');
    }
  }

  function renderAudit(data) {
    var tbody = $('patcherly-audit-tbody');
    var panel = $('patcherly-audit-panel');
    var auditLink = $('patcherly-audit-dashboard-link');
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
      tbody.innerHTML = '<tr><td colspan="4" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.pairToStartAudit ? cfg.i18n.pairToStartAudit : 'Connect to see audit events') +
        '</td></tr>';
      return;
    }
    if (!events.length) {
      tbody.innerHTML = '<tr><td colspan="4" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.noAudit ? cfg.i18n.noAudit : 'No audit events yet for this site') +
        '</td></tr>';
      return;
    }
    var dash = (data && data.metrics_dashboard_url) ? String(data.metrics_dashboard_url).replace(/\/metrics.*$/, '') : (cfg.dashboardUrl || '');
    var html = '';
    var limit = Math.min(events.length, 5);
    for (var i = 0; i < limit; i++) {
      var ev = events[i];
      var errCell = ev.error_id
        ? (dash ? '<a href="' + dash + '/errors?error_id=' + encodeURIComponent(ev.error_id) + '" target="_blank" rel="noopener">' + ev.error_id + '</a>' : ev.error_id)
        : '—';
      html += '<tr>' +
        '<td>' + formatDateTime(ev.timestamp) + '</td>' +
        '<td>' + (ev.event_type || '—') + '</td>' +
        '<td>' + (ev.event_category || '—') + '</td>' +
        '<td>' + errCell + '</td>' +
        '</tr>';
    }
    tbody.innerHTML = html;
    if (panel) panel.removeAttribute('hidden');
  }

  function scrollToPair() {
    var block = $('patcherly-pair-block');
    if (block) block.scrollIntoView({ behavior: 'smooth', block: 'start' });
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
  }

  function init() {
    bindAccountBar();
    if (!cfg.oauthConnected) {
      renderMetricsUnpaired();
      renderAudit(null);
    }
  }

  window.PatcherlyHome = {
    renderAccountBar: renderAccountBar,
    renderUsageBar: renderUsageBar,
    renderMetrics: renderMetrics,
    renderAudit: renderAudit,
    scrollToPair: scrollToPair,
    init: init
  };

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
