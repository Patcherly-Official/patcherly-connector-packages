/**
 * Patcherly Home page — metrics cards, audit table, account status bar.
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
    try { return new Date(iso).toLocaleString(); }
    catch (_) { return iso; }
  }

  function setCard(id, value, sub) {
    var el = $(id);
    if (!el) return;
    var valEl = el.querySelector('.patcherly-metric-card__value');
    var subEl = el.querySelector('.patcherly-metric-card__sub');
    if (valEl) valEl.textContent = value;
    if (subEl && sub) subEl.textContent = sub;
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

  function renderMetricsUnpaired() {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'unpaired');
    setCard('patcherly-metric-found', cfg.i18n && cfg.i18n.pairToStart ? cfg.i18n.pairToStart : 'Pair to start metrics', '');
    setCard('patcherly-metric-analyzed', '', '');
    setCard('patcherly-metric-fixed', '', '');
    setCard('patcherly-metric-time', '', '');
    setCard('patcherly-metric-money', '', '');
    showUpgradeBar(false);
    var link = $('patcherly-metrics-dashboard-link');
    if (link) link.hidden = true;
  }

  function renderMetricsFromSummary(summary, periodLabel) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'live');
    setCard('patcherly-metric-found', formatNum(summary.errors_found), periodLabel || '');
    setCard('patcherly-metric-analyzed', formatNum(summary.errors_analyzed), '');
    setCard('patcherly-metric-fixed', formatNum(summary.errors_fixed), '');
    setCard('patcherly-metric-time', formatHours(summary.time_saved_hours), '');
    setCard('patcherly-metric-money', formatMoney(summary.money_saved), '');
    showUpgradeBar(false);
  }

  function renderMetricsDemo(billingUrl) {
    var grid = $('patcherly-metrics-grid');
    if (grid) grid.setAttribute('data-state', 'demo');
    setCard('patcherly-metric-found', formatNum(DEMO.errors_found || 147), DEMO.period_label || '');
    setCard('patcherly-metric-analyzed', formatNum(DEMO.errors_analyzed || 132), '');
    setCard('patcherly-metric-fixed', formatNum(DEMO.errors_fixed || 128), '');
    setCard('patcherly-metric-time', formatHours(DEMO.time_saved_hours || 42.5), '');
    setCard('patcherly-metric-money', formatMoney(DEMO.money_saved || 3400), '');
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
      if (metricsUrl) {
        link.href = metricsUrl;
        link.hidden = false;
      } else {
        link.hidden = true;
      }
    }
    if (data && data.metrics_summary) {
      renderMetricsFromSummary(data.metrics_summary, data.metrics_summary.period_label);
      return;
    }
    if (data && data.metrics_demo) {
      renderMetricsDemo((data && data.billing_upgrade_url) || cfg.billingUpgradeUrl);
      return;
    }
    if (data && data.metrics_error) {
      var grid = $('patcherly-metrics-grid');
      if (grid) grid.setAttribute('data-state', 'error');
      setCard('patcherly-metric-found', cfg.i18n && cfg.i18n.metricsUnavailable ? cfg.i18n.metricsUnavailable : 'Unavailable', '');
    }
  }

  function renderAudit(data) {
    var tbody = $('patcherly-audit-tbody');
    var panel = $('patcherly-audit-panel');
    if (!tbody) return;
    var events = (data && data.recent_audit_events) || [];
    var paired = cfg.oauthConnected || (data && data.target_id);
    if (!paired) {
      tbody.innerHTML = '<tr><td colspan="4" class="patcherly-muted" style="text-align:center">' +
        (cfg.i18n && cfg.i18n.pairToStartAudit ? cfg.i18n.pairToStartAudit : 'Pair to see audit events') +
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
    for (var i = 0; i < events.length; i++) {
      var ev = events[i];
      var errCell = ev.error_id
        ? (dash ? '<a href="' + dash + '/errors?error_id=' + encodeURIComponent(ev.error_id) + '" target="_blank" rel="noopener">' + ev.error_id + '</a>' : ev.error_id)
        : '—';
      html += '<tr>' +
        '<td>' + formatDate(ev.timestamp) + '</td>' +
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
