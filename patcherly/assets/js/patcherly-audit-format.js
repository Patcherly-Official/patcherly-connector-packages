/*!
 * Audit event labels, badge tones, and dashboard deep-links for the WP Home
 * "Recent audit events" table. Keep in sync with dashboard-next audit/page.tsx
 * (EVENT_LABELS, CATEGORY_LABELS, EVENT_VARIANT, category badge variants).
 * Event outline + category light tones: `patcherly-connector.css` `.patcherly-audit-panel`
 * tokens mirror dashboard-next `globals.scss` / `Badge.tsx`.
 */
(function (global) {
  if (global.PatcherlyAuditFormat) return;

  var EVENT_LABELS = {
    error_ingested: 'Error Detected',
    error_deduplicated: 'Deduplicated',
    analysis_started: 'Analysis Started',
    analysis_completed: 'Analysis Complete',
    analysis_failed: 'Analysis Failed',
    fix_approved: 'Fix Approved',
    fix_rejected_patch: 'Patch Rejected',
    fix_dismissed: 'Patch Rejected',
    low_confidence_approve_acknowledged: 'Low Confidence Approve Acknowledged',
    manual_review_required: 'Manual Review',
    fix_applied: 'Fix Applied',
    fix_apply_dispatched: 'Apply Dispatched',
    fix_apply_dispatch_retried: 'Apply Dispatch Retried',
    fix_apply_redispatched: 'Apply Re-dispatched',
    fix_apply_step: 'Patching Step',
    fix_failed: 'Fix Failed',
    backup_created: 'Backup Created',
    rollback_initiated: 'Rollback Started',
    rollback_completed: 'Rollback Done',
    rollback_failed: 'Rollback Failed',
    oauth_device_pair_started: 'Pairing Started',
    oauth_device_pair_approved: 'Pairing Approved',
    oauth_token_issued: 'Token Issued',
    oauth_token_refreshed: 'Token Refreshed',
    oauth_token_revoked: 'Token Revoked',
    privilege_escalation: 'Privilege Escalation',
    unauthorized_access: 'Unauthorized Access',
    login_failed: 'Failed Login',
    login_success: 'Successful Login',
    successful_login: 'Successful Login',
    failed_login: 'Failed Login',
    target_created: 'Target Created',
    target_updated: 'Target Updated',
    target_deleted: 'Target Deleted',
    target_activated: 'Target Activated',
    target_deactivated: 'Target Deactivated',
    context_upload_rejected: 'Context upload rejected',
    tenant_created: 'Tenant Created',
    tenant_updated: 'Tenant Updated',
    tenant_deleted: 'Tenant Deleted',
    tenant_suspended: 'Tenant Suspended',
    tenant_activated: 'Tenant Activated',
    user_created: 'User Created',
    user_updated: 'User Updated',
    user_deleted: 'User Deleted',
    password_changed: 'Password Changed',
    email_verified: 'Email Verified',
    settings_updated: 'Settings Updated',
    security_settings_updated: 'Security Settings',
    create: 'Create',
    update: 'Update',
    activate_cascade: 'Activate Cascade',
    ip_auto_banned: 'IP Auto-Banned',
    rate_limit_exceeded: 'Rate Limit Exceeded',
    connector_initiated: 'Connector Initiated',
    context_refresh: 'Context Refresh',
    list_backups: 'List Backups',
    get_backup_info: 'Backup Info',
    bulk_email_test: 'Bulk Email Test',
    bulk_email_send: 'Bulk Email Send',
    broadcast_updated: 'Broadcast Updated',
    email_sent: 'Email Sent',
    email_failed: 'Email Failed',
    ai_template_created: 'AI Template Created',
    ai_template_updated: 'AI Template Updated',
    ai_template_deleted: 'AI Template Deleted',
    ai_template_set_default: 'AI Template Set as Default',
    ai_template_reset: 'AI Template Reset to Default',
    ai_template_downloaded: 'AI Template Downloaded',
    notification_preferences_updated: 'Notification Preferences Updated',
    chat_integration_connected: 'Chat Integration Connected',
    chat_integration_disconnected: 'Chat Integration Disconnected',
    chat_integration_channel_updated: 'Chat Integration Channel Updated',
    chat_integration_test_sent: 'Chat Integration Test Sent',
    chat_integration_delivery_failed: 'Chat Integration Delivery Failed',
    token_refresh: 'Token Refresh',
    target_flagged: 'Target Flagged',
    target_unflagged: 'Target Unflagged',
    error_ingest_rejected: 'Error Detection Rejected',
    error_ignored: 'Error Ignored',
    error_deleted: 'Error Deleted',
    errors_deleted_bulk: 'Errors Deleted (Bulk)',
    mfa_reset_by_admin_denied: 'MFA Reset Denied',
    fix_rollback: 'Fix Rollback',
    generate_tests: 'Generate Tests',
    report_test_results: 'Test Results Reported',
    bulk_action: 'Bulk Action',
    approve: 'Approve',
    reject_patch: 'Reject Patch',
    dismiss: 'Reject Patch',
    deactivate_cascade: 'Deactivate Cascade',
    soft_delete_cascade: 'Soft Delete Cascade',
    hard_delete_cascade: 'Hard Delete Cascade',
    soft_delete: 'Soft Delete',
    hard_delete: 'Hard Delete'
  };

  var CATEGORY_LABELS = {
    error_workflow: 'Error Workflow',
    security: 'Security',
    user_action: 'User Action',
    system: 'System',
    email: 'Emails',
    unknown: 'Unknown'
  };

  var EVENT_VARIANT = {
    error_ingested: 'blue',
    error_deduplicated: 'yellow',
    analysis_started: 'accent',
    analysis_completed: 'success',
    analysis_failed: 'error',
    fix_approved: 'success',
    fix_rejected_patch: 'warning',
    fix_dismissed: 'warning',
    manual_review_required: 'warning',
    fix_applied: 'success',
    fix_failed: 'error',
    backup_created: 'teal',
    rollback_initiated: 'warning',
    rollback_completed: 'success',
    rollback_failed: 'error',
    oauth_device_pair_started: 'teal',
    oauth_device_pair_approved: 'success',
    oauth_token_issued: 'teal',
    oauth_token_refreshed: 'teal',
    oauth_token_revoked: 'warning',
    privilege_escalation: 'error',
    unauthorized_access: 'error',
    login_failed: 'error',
    login_success: 'success',
    successful_login: 'success',
    failed_login: 'error',
    target_created: 'success',
    target_updated: 'info',
    target_deleted: 'error',
    target_activated: 'green',
    target_deactivated: 'yellow',
    tenant_created: 'success',
    tenant_updated: 'blue',
    tenant_deleted: 'error',
    tenant_suspended: 'warning',
    tenant_activated: 'green',
    user_created: 'success',
    user_updated: 'info',
    user_deleted: 'error',
    password_changed: 'purple',
    email_verified: 'teal',
    create: 'success',
    update: 'info',
    activate_cascade: 'accent',
    auto_rotate: 'teal',
    settings_updated: 'info',
    security_settings_updated: 'purple',
    ip_auto_banned: 'error',
    rate_limit_exceeded: 'warning',
    connector_initiated: 'info',
    context_refresh: 'accent',
    list_backups: 'teal',
    get_backup_info: 'blue',
    bulk_email_test: 'accent',
    bulk_email_send: 'purple',
    broadcast_updated: 'accent',
    email_sent: 'info',
    email_failed: 'error',
    ai_template_created: 'success',
    ai_template_updated: 'info',
    ai_template_deleted: 'error',
    ai_template_set_default: 'warning',
    ai_template_reset: 'info',
    ai_template_downloaded: 'default',
    notification_preferences_updated: 'info',
    token_refresh: 'teal',
    target_flagged: 'warning',
    target_unflagged: 'info',
    error_ingest_rejected: 'error',
    error_ignored: 'warning',
    error_deleted: 'error',
    errors_deleted_bulk: 'error',
    disable: 'warning',
    enable: 'success',
    mfa_reset_by_admin_denied: 'error',
    fix_rollback: 'warning',
    generate_tests: 'accent',
    report_test_results: 'success',
    bulk_action: 'info',
    approve: 'success',
    reject_patch: 'warning',
    dismiss: 'warning',
    deactivate_cascade: 'warning',
    soft_delete_cascade: 'error',
    hard_delete_cascade: 'error',
    soft_delete: 'warning',
    hard_delete: 'error'
  };

  function escHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  function titleCase(slug) {
    return String(slug || '')
      .split('_')
      .filter(Boolean)
      .map(function (w) { return w.charAt(0).toUpperCase() + w.slice(1).toLowerCase(); })
      .join(' ');
  }

  function metaBool(val) {
    if (val === true || val === 'true') return true;
    if (val === false || val === 'false') return false;
    return null;
  }

  function mergeAuditMeta(ev) {
    var out = {};
    var md = ev && ev.metadata;
    var m = ev && ev.meta;
    if (md && typeof md === 'object' && !Array.isArray(md)) {
      Object.keys(md).forEach(function (k) { out[k] = md[k]; });
    }
    if (m && typeof m === 'object' && !Array.isArray(m)) {
      Object.keys(m).forEach(function (k) { out[k] = m[k]; });
    }
    return out;
  }

  var APPLY_DISPATCH_EVENTS = {
    fix_apply_dispatched: true,
    fix_apply_dispatch_retried: true,
    fix_apply_redispatched: true
  };

  function isApplyDispatchFailed(ev) {
    if (!ev || typeof ev !== 'object') return false;
    var eventType = String(ev.event_type || ev.action || '');
    var meta = mergeAuditMeta(ev);
    if (eventType === 'fix_apply_redispatched' && metaBool(meta.ping_ok) === false) {
      return true;
    }
    if (!APPLY_DISPATCH_EVENTS[eventType]) return false;
    return metaBool(meta.apply_dispatch_ok) === false;
  }

  function getApplyDispatchFailedLabel(eventType) {
    if (eventType === 'fix_apply_dispatch_retried') return 'Apply dispatch retry failed';
    if (eventType === 'fix_apply_redispatched') return 'Apply re-dispatch failed';
    return 'Apply dispatch failed';
  }

  function getAuditEventLabel(ev) {
    var eventType = '';
    if (ev && typeof ev === 'object') {
      eventType = String(ev.event_type || ev.action || '');
      if (isApplyDispatchFailed(ev)) return getApplyDispatchFailedLabel(eventType);
      return getEventLabel(eventType);
    }
    return getEventLabel(ev);
  }

  function getEventVariantForEvent(ev) {
    var eventType = '';
    if (ev && typeof ev === 'object') {
      eventType = String(ev.event_type || ev.action || '');
      if (isApplyDispatchFailed(ev)) return 'error';
      return getEventVariant(eventType);
    }
    return getEventVariant(ev);
  }

  function getEventLabel(eventType) {
    if (!eventType) return 'Unknown';
    return EVENT_LABELS[eventType] || titleCase(eventType);
  }

  function getCategoryLabel(category) {
    if (category === 'user') return CATEGORY_LABELS.user_action;
    if (!category) return 'Unknown';
    return CATEGORY_LABELS[category] || titleCase(category);
  }

  function getEventVariant(eventType) {
    return EVENT_VARIANT[eventType] || 'default';
  }

  function getCategoryVariant(category) {
    if (category === 'security') return 'warning';
    if (category === 'user_action' || category === 'user') return 'info';
    if (category === 'email') return 'info';
    if (category === 'error_workflow') return 'accent';
    return 'default';
  }

  function eventBadgeHtml(evOrType) {
    var eventType = '';
    if (evOrType && typeof evOrType === 'object') {
      eventType = String(evOrType.event_type || evOrType.action || '');
    } else {
      eventType = String(evOrType || '');
    }
    if (!eventType) return '<span class="patcherly-muted">—</span>';
    var label = getAuditEventLabel(evOrType);
    var variant = getEventVariantForEvent(evOrType);
    return '<span class="patcherly-audit-badge patcherly-audit-event-badge patcherly-audit-tone-' + escHtml(variant) + '">'
      + escHtml(label)
      + '</span>';
  }

  function categoryBadgeHtml(category) {
    if (!category) return '<span class="patcherly-muted">—</span>';
    var variant = getCategoryVariant(category);
    return '<span class="patcherly-audit-badge patcherly-audit-cat-badge patcherly-audit-cat-' + escHtml(variant) + '">'
      + escHtml(getCategoryLabel(category))
      + '</span>';
  }

  // Accepts either an audit event object (with server-resolved actor_display /
  // actor_type) or a bare actor string (backward compatible).
  function formatActor(evOrActor, i18n) {
    i18n = i18n || {};
    var display = '', type = '', actor = '';
    if (evOrActor && typeof evOrActor === 'object') {
      display = evOrActor.actor_display != null ? String(evOrActor.actor_display).trim() : '';
      type = evOrActor.actor_type != null ? String(evOrActor.actor_type).trim() : '';
      actor = evOrActor.actor != null ? String(evOrActor.actor).trim() : '';
    } else {
      actor = evOrActor != null ? String(evOrActor).trim() : '';
    }
    if (type === 'system' || (!type && (!actor || actor === 'system' || actor === 'api'))) {
      return '<span class="patcherly-audit-actor patcherly-audit-actor--system">'
        + escHtml(i18n.auditActorSystem || 'System')
        + '</span>';
    }
    if (type === 'connector' || (!type && actor === 'connector')) {
      return '<span class="patcherly-audit-actor patcherly-audit-actor--connector">'
        + escHtml(i18n.auditActorConnector || 'Connector')
        + '</span>';
    }
    if (type === 'support') {
      return '<span class="patcherly-audit-actor patcherly-audit-actor--system">'
        + escHtml(display || i18n.auditActorSupport || 'Patcherly Support')
        + '</span>';
    }
    var text = display || actor;
    if (!text) {
      return '<span class="patcherly-audit-actor patcherly-audit-actor--system">'
        + escHtml(i18n.auditActorSystem || 'System')
        + '</span>';
    }
    return '<span class="patcherly-audit-actor" title="' + escHtml(text) + '">' + escHtml(text) + '</span>';
  }

  function resolveDashboardBase(ctx) {
    ctx = ctx || {};
    if (ctx.metrics_dashboard_url) {
      return String(ctx.metrics_dashboard_url).replace(/\/metrics.*$/, '').replace(/\/+$/, '');
    }
    if (ctx.dashboardUrl) {
      return String(ctx.dashboardUrl).replace(/\/+$/, '');
    }
    return '';
  }

  function buildActionUrl(ev, ctx) {
    ev = ev || {};
    ctx = ctx || {};
    var dash = resolveDashboardBase(ctx);
    if (!dash) return '';

    var et = String(ev.event_type || '');
    var errorId = ev.error_id || (ev.object_type === 'error' && ev.object_id ? ev.object_id : '');
    if (errorId) {
      return dash + '/errors?error_id=' + encodeURIComponent(String(errorId));
    }

    if (/^target_/.test(et) || et === 'context_refresh' || et === 'connector_initiated') {
      var tid = ev.target_id != null && String(ev.target_id) !== '' ? ev.target_id : ctx.target_id;
      if (tid != null && String(tid) !== '') {
        if (ctx.targets_focus_url) return String(ctx.targets_focus_url);
        return dash + '/targets?focus=' + encodeURIComponent(String(tid));
      }
    }

    if (/^oauth_/.test(et) || et === 'token_refresh') {
      if (ctx.audit_dashboard_url) return String(ctx.audit_dashboard_url);
      if (ctx.auditDashboardUrl) return String(ctx.auditDashboardUrl);
    }

    if (ev.audit_id) {
      if (ctx.audit_dashboard_url) return String(ctx.audit_dashboard_url);
      if (ctx.auditDashboardUrl) return String(ctx.auditDashboardUrl);
    }

    return '';
  }

  function eyeIconSvg() {
    return '<svg class="patcherly-audit-action__icon" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
  }

  function actionCellHtml(ev, ctx, i18n) {
    var url = buildActionUrl(ev, ctx);
    if (!url) {
      return '<span class="patcherly-muted">—</span>';
    }
    var title = (i18n && i18n.auditViewInDashboard) ? i18n.auditViewInDashboard : 'View in dashboard';
    return '<a class="patcherly-audit-action" href="' + escHtml(url) + '" target="_blank" rel="noopener noreferrer" title="'
      + escHtml(title) + '" aria-label="' + escHtml(title) + '">' + eyeIconSvg() + '</a>';
  }

  global.PatcherlyAuditFormat = {
    getEventLabel: getEventLabel,
    getAuditEventLabel: getAuditEventLabel,
    isApplyDispatchFailed: isApplyDispatchFailed,
    getCategoryLabel: getCategoryLabel,
    eventBadgeHtml: eventBadgeHtml,
    categoryBadgeHtml: categoryBadgeHtml,
    formatActor: formatActor,
    buildActionUrl: buildActionUrl,
    actionCellHtml: actionCellHtml
  };
})(typeof window !== 'undefined' ? window : this);
