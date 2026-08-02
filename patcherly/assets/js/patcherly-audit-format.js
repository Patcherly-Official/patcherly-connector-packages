/*!
 * Audit event labels, badge tones, and dashboard deep-links for the WP Home
 * "Recent audit events" table. EVENT_LABELS, CATEGORY_LABELS, EVENT_VARIANT, and
 * ACTOR_VARIANT are generated from config/audit_display.yaml (see
 * config/generate_audit_display.py). Event outline + category light tones:
 * `patcherly-connector.css` `.patcherly-audit-panel` tokens mirror dashboard-next.
 */
(function (global) {
  if (global.PatcherlyAuditFormat) return;

/* BEGIN GENERATED_AUDIT_DISPLAY */
  var EVENT_LABELS = {
    "activate_cascade": "Activate Cascade",
    "ai_template_created": "AI Template Created",
    "ai_template_deleted": "AI Template Deleted",
    "ai_template_downloaded": "AI Template Downloaded",
    "ai_template_reset": "AI Template Reset to Default",
    "ai_template_set_default": "AI Template Set as Default",
    "ai_template_updated": "AI Template Updated",
    "analysis_completed": "Analysis Complete",
    "analysis_failed": "Analysis Failed",
    "analysis_started": "Analysis Started",
    "approve": "Approve",
    "auto_analysis_toggled": "Auto Analysis Toggled",
    "auto_apply_blocked_connector_approve": "Auto Apply Blocked",
    "auto_apply_toggled": "Auto Apply Toggled",
    "backup_created": "Backup Created",
    "broadcast_updated": "Broadcast Updated",
    "bulk_action": "Bulk Action",
    "bulk_email_send": "Bulk Email Send",
    "bulk_email_test": "Bulk Email Test",
    "chat_integration_channel_updated": "Chat Integration Channel Updated",
    "chat_integration_connected": "Chat Integration Connected",
    "chat_integration_delivery_failed": "Chat Integration Delivery Failed",
    "chat_integration_disconnected": "Chat Integration Disconnected",
    "chat_integration_test_sent": "Chat Integration Test Sent",
    "connector_initiated": "Connector Initiated",
    "context_refresh": "Context Refresh",
    "context_upload_rejected": "Context upload rejected",
    "create": "Create",
    "deactivate_cascade": "Deactivate Cascade",
    "dismiss": "Reject patch",
    "email_failed": "Email Failed",
    "email_sent": "Email Sent",
    "email_verified": "Email Verified",
    "error_deduplicated": "Deduplicated",
    "error_deleted": "Error Deleted",
    "error_ignored": "Error Ignored",
    "error_ingest_rejected": "Error Detection Rejected",
    "error_ingested": "Error Detected",
    "error_unignored": "Error Unignored",
    "errors_deleted_bulk": "Errors Deleted (Bulk)",
    "failed_login": "Failed Login",
    "fix_applied": "Fix Applied",
    "fix_apply_dispatch_retried": "Apply Dispatch Retried",
    "fix_apply_dispatched": "Apply Dispatched",
    "fix_apply_redispatched": "Apply Re-dispatched",
    "fix_apply_step": "Patching Step",
    "fix_approved": "Fix Approved",
    "fix_dismissed": "Patch Rejected",
    "fix_failed": "Fix Failed",
    "fix_marked_fixed": "Marked Fixed",
    "fix_rejected_patch": "Patch Rejected",
    "fix_rollback": "Fix Rollback",
    "generate_tests": "Generate Tests",
    "get_backup_info": "Backup Info",
    "hard_delete": "Hard Delete",
    "hard_delete_cascade": "Hard Delete Cascade",
    "ip_auto_banned": "IP Auto-Banned",
    "list_backups": "List Backups",
    "login_failed": "Failed Login",
    "login_success": "Successful Login",
    "low_confidence_approve_acknowledged": "Low Confidence Approve Acknowledged",
    "manual_review_required": "Manual Review",
    "mark_fixed": "Mark Fixed",
    "mfa_reset_by_admin_denied": "MFA Reset Denied",
    "notification_preferences_updated": "Notification Preferences Updated",
    "oauth_device_pair_approved": "Pairing Approved",
    "oauth_device_pair_started": "Pairing Started",
    "oauth_token_issued": "Token Issued",
    "oauth_token_refreshed": "Token Refreshed",
    "oauth_token_revoked": "Token Revoked",
    "password_changed": "Password Changed",
    "post_apply_config_updated": "App Restart Config Updated",
    "post_apply_force_disabled": "App Restart Force Disabled",
    "post_apply_review_cleared": "App Restart Review Cleared",
    "post_apply_toggled": "App Restart Toggled",
    "privilege_escalation": "Privilege Escalation",
    "rate_limit_exceeded": "Rate Limit Exceeded",
    "reject_patch": "Reject patch",
    "report_test_results": "Test Results Reported",
    "rollback_completed": "Rollback Done",
    "rollback_failed": "Rollback Failed",
    "rollback_initiated": "Rollback Started",
    "security_settings_updated": "Security Settings",
    "settings_updated": "Settings Updated",
    "soft_delete": "Soft Delete",
    "soft_delete_cascade": "Soft Delete Cascade",
    "successful_login": "Successful Login",
    "target_activated": "Target Activated",
    "target_created": "Target Created",
    "target_deactivated": "Target Deactivated",
    "target_deleted": "Target Deleted",
    "target_entered_protection_mode_auto": "Protection Mode Entered (Auto)",
    "target_entered_protection_mode_manual": "Protection Mode Entered",
    "target_flagged": "Target Flagged",
    "target_released_from_protection_mode_auto": "Protection Mode Released (Auto)",
    "target_released_from_protection_mode_manual": "Protection Mode Released",
    "target_unflagged": "Target Unflagged",
    "target_updated": "Target Updated",
    "tenant_activated": "Tenant Activated",
    "tenant_created": "Tenant Created",
    "tenant_deleted": "Tenant Deleted",
    "tenant_suspended": "Tenant Suspended",
    "tenant_updated": "Tenant Updated",
    "token_refresh": "Token Refresh",
    "unauthorized_access": "Unauthorized Access",
    "unignore": "Error Unignored",
    "update": "Update",
    "user_created": "User Created",
    "user_deleted": "User Deleted",
    "user_updated": "User Updated",
    "workspace_member_permissions_updated": "Member Permissions Updated",
  };

  var CATEGORY_LABELS = {
    "email": "Emails",
    "error_workflow": "Error Workflow",
    "security": "Security",
    "system": "System",
    "unknown": "Unknown",
    "user_action": "User Action",
  };

  var STEP_LABELS = {
    "app_restart_failed": "App Restart Failed",
    "app_restart_ran": "App Restart Completed",
    "app_restart_skipped": "App Restart Skipped",
  };

  var EVENT_VARIANT = {
    "activate_cascade": "accent",
    "ai_template_created": "success",
    "ai_template_deleted": "error",
    "ai_template_downloaded": "default",
    "ai_template_reset": "info",
    "ai_template_set_default": "warning",
    "ai_template_updated": "info",
    "analysis_completed": "success",
    "analysis_failed": "error",
    "analysis_started": "accent",
    "approve": "success",
    "auto_analysis_toggled": "info",
    "auto_apply_blocked_connector_approve": "warning",
    "auto_apply_toggled": "info",
    "auto_rotate": "teal",
    "backup_created": "teal",
    "broadcast_updated": "accent",
    "bulk_action": "info",
    "bulk_email_send": "purple",
    "bulk_email_test": "accent",
    "chat_integration_channel_updated": "info",
    "chat_integration_connected": "success",
    "chat_integration_delivery_failed": "error",
    "chat_integration_disconnected": "warning",
    "chat_integration_test_sent": "accent",
    "connector_initiated": "info",
    "context_refresh": "accent",
    "context_upload_rejected": "error",
    "create": "success",
    "deactivate_cascade": "warning",
    "disable": "warning",
    "dismiss": "warning",
    "email_failed": "error",
    "email_sent": "info",
    "email_verified": "teal",
    "enable": "success",
    "error_deduplicated": "yellow",
    "error_deleted": "error",
    "error_ignored": "warning",
    "error_ingest_rejected": "error",
    "error_ingested": "blue",
    "error_unignored": "info",
    "errors_deleted_bulk": "error",
    "failed_login": "error",
    "fix_applied": "success",
    "fix_apply_dispatch_retried": "warning",
    "fix_apply_dispatched": "info",
    "fix_apply_redispatched": "accent",
    "fix_apply_step": "info",
    "fix_approved": "success",
    "fix_dismissed": "warning",
    "fix_failed": "error",
    "fix_marked_fixed": "success",
    "fix_rejected_patch": "warning",
    "fix_rollback": "warning",
    "generate_tests": "accent",
    "get_backup_info": "blue",
    "hard_delete": "error",
    "hard_delete_cascade": "error",
    "ip_auto_banned": "error",
    "list_backups": "teal",
    "login_failed": "error",
    "login_success": "success",
    "low_confidence_approve_acknowledged": "warning",
    "manual_review_required": "warning",
    "mark_fixed": "success",
    "mfa_reset_by_admin_denied": "error",
    "notification_preferences_updated": "info",
    "oauth_device_pair_approved": "success",
    "oauth_device_pair_started": "teal",
    "oauth_token_issued": "teal",
    "oauth_token_refreshed": "teal",
    "oauth_token_revoked": "warning",
    "password_changed": "purple",
    "post_apply_config_updated": "info",
    "post_apply_force_disabled": "warning",
    "post_apply_review_cleared": "success",
    "post_apply_toggled": "info",
    "privilege_escalation": "error",
    "rate_limit_exceeded": "warning",
    "reject_patch": "warning",
    "report_test_results": "success",
    "rollback_completed": "success",
    "rollback_failed": "error",
    "rollback_initiated": "warning",
    "security_settings_updated": "purple",
    "settings_updated": "info",
    "soft_delete": "warning",
    "soft_delete_cascade": "error",
    "successful_login": "success",
    "target_activated": "green",
    "target_created": "success",
    "target_deactivated": "yellow",
    "target_deleted": "error",
    "target_entered_protection_mode_auto": "warning",
    "target_entered_protection_mode_manual": "warning",
    "target_flagged": "warning",
    "target_released_from_protection_mode_auto": "success",
    "target_released_from_protection_mode_manual": "success",
    "target_unflagged": "info",
    "target_updated": "info",
    "tenant_activated": "green",
    "tenant_created": "success",
    "tenant_deleted": "error",
    "tenant_suspended": "warning",
    "tenant_updated": "blue",
    "token_refresh": "teal",
    "unauthorized_access": "error",
    "unignore": "info",
    "update": "info",
    "user_created": "success",
    "user_deleted": "error",
    "user_updated": "info",
    "workspace_member_permissions_updated": "info",
  };

  var ACTOR_VARIANT = {
    "agent": "teal",
    "connector": "default",
    "superadmin": "warning",
    "system": "default",
    "tenant_admin": "info",
    "unknown": "default",
    "user": "info",
  };
/* END GENERATED_AUDIT_DISPLAY */

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
  function isSuperadminRole(role) {
    return role === 'superadmin';
  }

  function isTenantAdminRole(role) {
    return role === 'tenant_admin' || role === 'admin';
  }

  function actorWithPrefix(label, text) {
    return text && text !== label ? label + ' · ' + text : label;
  }

  function resolveActorKind(evOrActor) {
    var display = '', type = '', actor = '', role = '';
    if (evOrActor && typeof evOrActor === 'object') {
      display = evOrActor.actor_display != null ? String(evOrActor.actor_display).trim() : '';
      type = evOrActor.actor_type != null ? String(evOrActor.actor_type).trim() : '';
      actor = evOrActor.actor != null ? String(evOrActor.actor).trim() : '';
      role = evOrActor.actor_role != null ? String(evOrActor.actor_role).trim() : '';
    } else {
      actor = evOrActor != null ? String(evOrActor).trim() : '';
    }

    if (type) {
      if (type === 'system') return { kind: 'system', text: display || 'System' };
      if (type === 'connector') return { kind: 'connector', text: display || 'Connector' };
      if (type === 'agent') return { kind: 'agent', text: display || 'Agent' };
      if (type === 'support') return { kind: 'system', text: display || 'Patcherly Support' };
      if (type === 'unknown') return { kind: 'unknown', text: '' };
      if (type === 'user') {
        var userText = display || actor || 'User';
        if (isSuperadminRole(role)) return { kind: 'superadmin', text: userText };
        if (isTenantAdminRole(role)) return { kind: 'tenant_admin', text: userText };
        return { kind: 'user', text: userText };
      }
    }

    if (!actor || actor === 'system' || actor === 'api') return { kind: 'system', text: 'System' };
    if (actor === 'connector') return { kind: 'connector', text: 'Connector' };
    return { kind: 'user', text: display || actor };
  }

  function actorBadgeHtml(kind, text, i18n) {
    var variant = ACTOR_VARIANT[kind] || ACTOR_VARIANT.unknown || 'default';
    var badgeText = text;
    if (kind === 'system') {
      badgeText = i18n.auditActorSystem || 'System';
    } else if (kind === 'connector') {
      badgeText = i18n.auditActorConnector || 'Connector';
    } else if (kind === 'superadmin') {
      badgeText = actorWithPrefix(i18n.auditActorSuperadmin || 'Superadmin', text);
    } else if (kind === 'tenant_admin') {
      badgeText = actorWithPrefix(i18n.auditActorTenantAdmin || 'Tenant admin', text);
    } else if (kind === 'agent') {
      badgeText = text || 'Agent';
    }
    if (!badgeText) return '<span class="patcherly-muted">—</span>';
    return '<span class="patcherly-audit-badge patcherly-audit-cat-badge patcherly-audit-cat-' + escHtml(variant) + '" title="'
      + escHtml(text || badgeText) + '">' + escHtml(badgeText) + '</span>';
  }

  function formatActor(evOrActor, i18n) {
    i18n = i18n || {};
    var resolved = resolveActorKind(evOrActor);
    if (resolved.kind === 'unknown') {
      return '<span class="patcherly-muted">—</span>';
    }
    return actorBadgeHtml(resolved.kind, resolved.text, i18n);
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
