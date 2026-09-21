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
    "acknowledge": "Alert Acknowledged",
    "activate_cascade": "Activate Cascade",
    "add_language_framework": "Language/Framework Added",
    "ai_language_frameworks_update": "Language/Framework Catalog Updated",
    "ai_template_created": "AI Template Created",
    "ai_template_deleted": "AI Template Deleted",
    "ai_template_downloaded": "AI Template Downloaded",
    "ai_template_reset": "AI Template Reset to Default",
    "ai_template_set_default": "AI Template Set as Default",
    "ai_template_updated": "AI Template Updated",
    "analysis_completed": "Analysis Complete",
    "analysis_failed": "Analysis Failed",
    "analysis_rejected_no_file_path": "Analysis Rejected (No File Path)",
    "analysis_started": "Analysis Started",
    "analyze_async": "Analysis Queued",
    "anonymized_outcomes_purge": "Anonymized Outcomes Purge",
    "anonymized_outcomes_purge_dry_run": "Anonymized Outcomes Purge (Dry Run)",
    "approve": "Approve",
    "archive_price": "Price Archived",
    "archive_product": "Product Archived",
    "auth_email_delivery_failed": "Auth Email Delivery Failed",
    "auto_analysis_toggled": "Auto Analysis Toggled",
    "auto_apply_blocked_connector_approve": "Auto Apply Blocked",
    "auto_apply_toggled": "Auto Apply Toggled",
    "auto_rotate": "Auto Rotate",
    "backup_created": "Backup Created",
    "batch_ingest_rejected": "Batch Ingest Rejected",
    "billing_misconfigured": "Billing Misconfigured",
    "billing_webhook_received": "Billing Webhook Received",
    "broadcast_updated": "Broadcast Updated",
    "bulk_action": "Bulk Action",
    "bulk_email_send": "Bulk Email Send",
    "bulk_email_test": "Bulk Email Test",
    "chat_integration_channel_updated": "Chat Integration Channel Updated",
    "chat_integration_connected": "Chat Integration Connected",
    "chat_integration_delivery_failed": "Chat Integration Delivery Failed",
    "chat_integration_disconnected": "Chat Integration Disconnected",
    "chat_integration_test_sent": "Chat Integration Test Sent",
    "chat_webhook_settings_updated": "Chat Webhook Settings Updated",
    "checkout_session_verified": "Checkout Session Verified",
    "cleanup_mongodb_backups": "MongoDB Backups Cleaned Up",
    "connector_initiated": "Connector Initiated",
    "connector_refused_suspicious_patch": "Connector Refused Suspicious Patch",
    "context_refresh": "Context Refresh",
    "context_upload_rejected": "Context upload rejected",
    "context_uploaded": "Context Uploaded",
    "create": "Create",
    "create_entitlement_type": "Entitlement Type Created",
    "create_mongodb_backup": "MongoDB Backup Created",
    "create_price": "Price Created",
    "create_product": "Product Created",
    "deactivate_cascade": "Deactivate Cascade",
    "delete_entitlement_type": "Entitlement Type Deleted",
    "delete_mongodb_backup": "MongoDB Backup Deleted",
    "delete_price": "Price Deleted",
    "deletion_mark_reconciled": "Deletion Mark Reconciled",
    "deletion_scheduled": "Deletion Scheduled",
    "disable": "Disable",
    "dismiss": "Reject patch",
    "email_failed": "Email Failed",
    "email_sent": "Email Sent",
    "email_unsubscribed": "Email Unsubscribed",
    "email_verified": "Email Verified",
    "email_verify_failed": "Email Verify Failed",
    "enable": "Enable",
    "error_deduplicated": "Deduplicated",
    "error_deleted": "Error Deleted",
    "error_ignored": "Error Ignored",
    "error_ingest_rejected": "Error Detection Rejected",
    "error_ingested": "Error Detected",
    "error_suspicious_verdict_overridden": "Suspicious Verdict Overridden",
    "error_unignored": "Error Unignored",
    "errors_deleted_bulk": "Errors Deleted (Bulk)",
    "execute_tests": "Execute Tests",
    "failed_login": "Failed Login",
    "finalize_registration": "Registration Finalized",
    "fix_applied": "Fix Applied",
    "fix_apply_dispatch_retried": "Apply Dispatch Retried",
    "fix_apply_dispatched": "Apply Dispatched",
    "fix_apply_redispatched": "Apply Re-dispatched",
    "fix_apply_step": "Patching Step",
    "fix_approved": "Fix Approved",
    "fix_blocked": "Fix Blocked",
    "fix_dismissed": "Patch Rejected",
    "fix_failed": "Fix Failed",
    "fix_marked_fixed": "Marked Fixed",
    "fix_rejected_patch": "Patch Rejected",
    "fix_rollback": "Fix Rollback",
    "full_database_reset": "Full Database Reset",
    "generate_tests": "Generate Tests",
    "get_backup_info": "Backup Info",
    "hard_delete": "Hard Delete",
    "hard_delete_cascade": "Hard Delete Cascade",
    "health_check": "Health Check",
    "ignore": "Error Ignored",
    "import_stripe_price": "Stripe Price Imported",
    "import_stripe_product": "Stripe Product Imported",
    "ingest_contract_violation": "Ingest Contract Violation",
    "ip_auto_banned": "IP Auto-Banned",
    "ip_unblocked": "IP Unblocked",
    "lift_post_restore_maintenance": "Post-Restore Maintenance Lifted",
    "link_replaces": "Product Replacement Linked",
    "link_stripe_price": "Stripe Price Linked",
    "link_stripe_product": "Stripe Product Linked",
    "list_backups": "List Backups",
    "log_path_policy_violation": "Log Path Policy Violation",
    "login_critical_error": "Login Critical Error",
    "login_failed": "Failed Login",
    "login_locked_out": "Login Locked Out",
    "login_success": "Successful Login",
    "logout": "Logout",
    "low_confidence_approve_acknowledged": "Low Confidence Approve Acknowledged",
    "manual_review_required": "Manual Review",
    "mark_fixed": "Mark Fixed",
    "mcp_oauth_authorized": "MCP Connected",
    "mcp_policy_updated": "MCP Policy Updated",
    "mcp_tool_denied": "MCP Tool Denied",
    "mcp_tool_failed": "MCP Tool Failed",
    "mcp_tool_invoked": "MCP Tool Invoked",
    "metrics_rollup_recompute": "Metrics Rollup Recompute",
    "mfa_enroll": "MFA Enroll",
    "mfa_recovery_code_failed": "MFA Recovery Code Failed",
    "mfa_recovery_code_login": "MFA Recovery Code Login",
    "mfa_recovery_codes_regenerate_failed": "MFA Recovery Codes Regenerate Failed",
    "mfa_recovery_codes_regenerated": "MFA Recovery Codes Regenerated",
    "mfa_reset_by_admin": "MFA Reset By Admin",
    "mfa_reset_by_admin_denied": "MFA Reset Denied",
    "mfa_setup": "MFA Setup",
    "mfa_verify": "MFA Verify",
    "mfa_verify_failed": "MFA Verify Failed",
    "mfa_verify_success": "MFA Verify Success",
    "mint_ingest_test_link": "Ingest Test Link Minted",
    "notification_deleted": "Notification Deleted",
    "notification_preferences_updated": "Notification Preferences Updated",
    "notification_read": "Notification Read",
    "notifications_bulk_deleted": "Notifications Bulk Deleted",
    "notifications_read_all": "Notifications Marked Read",
    "oauth_device_approved": "OAuth Device Approved",
    "oauth_linked": "Social Account Linked",
    "oauth_refresh_reuse_detected": "OAuth Refresh Reuse Detected",
    "oauth_token_issued": "Token Issued",
    "oauth_token_refreshed": "Token Refreshed",
    "oauth_token_revoked": "Token Revoked",
    "oauth_tokens_revoked": "OAuth Tokens Revoked",
    "oauth_unlinked": "Social Account Unlinked",
    "output_scan_fp_dismissed": "Output Scan FP Dismissed",
    "owner_workspace_deleted": "Owner Workspace Deleted",
    "password_changed": "Password Changed",
    "password_reset": "Password Reset",
    "password_reset_failed": "Password Reset Failed",
    "patch_quarantined_suspicious": "Patch Quarantined (Suspicious)",
    "patch_quarantined_suspicious_refused": "Patch Quarantine Refused",
    "plan_downgrade_applied": "Plan Downgrade Applied",
    "plan_limits_applied": "Plan Limits Applied",
    "plan_migration_confirmed": "Plan Migration Confirmed",
    "plan_migration_declined": "Plan Migration Declined",
    "post_apply_config_updated": "App Restart Config Updated",
    "post_apply_force_disabled": "App Restart Force Disabled",
    "post_apply_review_cleared": "App Restart Review Cleared",
    "post_apply_toggled": "App Restart Toggled",
    "post_restore_enable_maintenance": "Post-Restore Maintenance Enabled",
    "post_restore_reset_superadmin_mfa": "Post-Restore SA MFA Reset",
    "post_restore_run_checks": "Post-Restore Checks Run",
    "post_restore_sync_billing": "Post-Restore Billing Synced",
    "privilege_escalation": "Privilege Escalation",
    "prompt_injection_output_scan_shadow": "Prompt Injection Scan (Shadow)",
    "push_pending_price_to_stripe": "Pending Price Pushed To Stripe",
    "rate_limit_exceeded": "Rate Limit Exceeded",
    "registration_critical_error": "Registration Critical Error",
    "registration_field_created": "Registration Field Created",
    "registration_field_deleted": "Registration Field Deleted",
    "registration_field_updated": "Registration Field Updated",
    "registration_fields_reordered": "Registration Fields Reordered",
    "reject_patch": "Reject patch",
    "reorder_product_plans": "Product Plans Reordered",
    "report_test_results": "Test Results Reported",
    "reseed_entitlement_types_from_schema": "Entitlement Types Reseeded",
    "reset": "Error Reset",
    "restore_database": "Database Restored",
    "retry_apply": "Retry Patch",
    "rollback_completed": "Rollback Done",
    "rollback_failed": "Rollback Failed",
    "rollback_initiated": "Rollback Started",
    "sa_drift_detected": "SA Drift Detected",
    "sa_recovery": "SA Recovery",
    "sa_role_change": "SA Role Changed",
    "sa_status_change": "SA Status Changed",
    "security_settings_updated": "Security Settings",
    "settings_updated": "Settings Updated",
    "soft_delete": "Soft Delete",
    "soft_delete_cascade": "Soft Delete Cascade",
    "subscription_canceled": "Subscription Canceled",
    "subscription_checkout_started": "Checkout Started",
    "subscription_price_changed": "Subscription Price Changed",
    "successful_login": "Successful Login",
    "superadmin_soft_disabled": "Superadmin Soft-Disabled",
    "support_portal_sso_mint": "Support Portal SSO Mint",
    "suspicious_denorm_drift": "Suspicious Denorm Drift",
    "sync_from_stripe_price": "Price Synced From Stripe",
    "sync_from_stripe_product": "Product Synced From Stripe",
    "target_activated": "Site Activated",
    "target_created": "Site Created",
    "target_deactivated": "Site Deactivated",
    "target_deleted": "Site Deleted",
    "target_entered_protection_mode_auto": "Protection Mode Entered (Auto)",
    "target_entered_protection_mode_manual": "Protection Mode Entered",
    "target_exclude_from_metrics": "Site Excluded From Metrics",
    "target_flagged": "Site Flagged",
    "target_lang_fw_auto_set": "Site Language/Framework Auto-Set",
    "target_language_framework_review": "Language/Framework Review",
    "target_released_from_protection_mode_auto": "Protection Mode Released (Auto)",
    "target_released_from_protection_mode_manual": "Protection Mode Released",
    "target_unflagged": "Site Unflagged",
    "target_updated": "Site Updated",
    "tenant_activated": "Workspace Activated",
    "tenant_created": "Workspace Created",
    "tenant_deleted": "Workspace Deleted",
    "tenant_physical_purge": "Workspace Physically Purged",
    "tenant_suspended": "Workspace Suspended",
    "tenant_totp_optional_updated": "Workspace MFA Optional Updated",
    "tenant_updated": "Workspace Updated",
    "token_refresh": "Token Refresh",
    "totp_confirm_failed": "TOTP Confirm Failed",
    "totp_disable_failed": "TOTP Disable Failed",
    "totp_disabled": "TOTP Disabled",
    "totp_enabled": "TOTP Enabled",
    "totp_setup_failed": "TOTP Setup Failed",
    "totp_setup_started": "TOTP Setup Started",
    "trigger_rollback": "Rollback Triggered",
    "unauthorized_access": "Unauthorized Access",
    "unignore": "Error Unignored",
    "update": "Update",
    "update_entitlement_type": "Entitlement Type Updated",
    "update_price": "Price Updated",
    "update_product": "Product Updated",
    "update_product_entitlements": "Product Entitlements Updated",
    "upload_mongodb_backup_sftp": "MongoDB Backup Uploaded (SFTP)",
    "user_created": "User Created",
    "user_deleted": "User Deleted",
    "user_soft_delete_restored": "User Soft-Delete Restored",
    "user_updated": "User Updated",
    "webhook_url_blocked_ssrf": "Webhook URL Blocked (SSRF)",
    "workspace_invite_accepted": "Workspace Invite Accepted",
    "workspace_invite_created": "Workspace Invite Created",
    "workspace_invite_declined": "Workspace Invite Declined",
    "workspace_invite_revoked": "Workspace Invite Revoked",
    "workspace_left": "Left Workspace",
    "workspace_member_permissions_updated": "Member Permissions Updated",
    "workspace_member_removed": "Workspace Member Removed",
    "workspace_switched": "Workspace Switched",
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
    "app_restart_failed": "Failed",
    "app_restart_ran": "Completed",
    "app_restart_skipped": "Skipped",
    "apply_result_failed": "Apply result failed",
    "apply_result_success": "Apply result success",
    "apply_stalled": "Apply stalled",
    "connector_apply_lock_busy": "Connector apply lock busy",
    "connector_apply_started": "Connector apply started",
    "connector_bootstrap_failed": "Connector bootstrap failed",
    "connector_fix_empty": "Connector fix empty",
    "connector_fix_fetch_failed": "Connector fix fetch failed",
    "connector_fix_hmac_failed": "Connector fix HMAC failed",
    "connector_oauth_missing": "Connector OAuth missing",
    "connector_protection_standby": "Connector protection standby",
    "connector_suspicious_refused": "Connector refused suspicious patch",
    "dispatch_completed": "Dispatch completed",
    "dispatch_deduped": "Dispatch deduped",
    "dispatch_failed": "Dispatch failed",
    "dispatch_skipped_patch_applied": "Dispatch skipped (already applied)",
    "fix_payload_denied": "Fix payload denied",
    "fix_payload_served": "Fix payload served",
  };

  var EVENT_VARIANT = {
    "acknowledge": "success",
    "activate_cascade": "accent",
    "add_language_framework": "success",
    "ai_language_frameworks_update": "info",
    "ai_template_created": "success",
    "ai_template_deleted": "error",
    "ai_template_downloaded": "default",
    "ai_template_reset": "info",
    "ai_template_set_default": "warning",
    "ai_template_updated": "info",
    "analysis_completed": "success",
    "analysis_failed": "error",
    "analysis_rejected_no_file_path": "warning",
    "analysis_started": "accent",
    "analyze_async": "info",
    "anonymized_outcomes_purge": "warning",
    "anonymized_outcomes_purge_dry_run": "info",
    "approve": "success",
    "archive_price": "warning",
    "archive_product": "warning",
    "auth_email_delivery_failed": "error",
    "auto_analysis_toggled": "info",
    "auto_apply_blocked_connector_approve": "warning",
    "auto_apply_toggled": "info",
    "auto_rotate": "teal",
    "backup_created": "teal",
    "batch_ingest_rejected": "error",
    "billing_misconfigured": "error",
    "billing_webhook_received": "teal",
    "broadcast_updated": "accent",
    "bulk_action": "info",
    "bulk_email_send": "purple",
    "bulk_email_test": "accent",
    "chat_integration_channel_updated": "info",
    "chat_integration_connected": "success",
    "chat_integration_delivery_failed": "error",
    "chat_integration_disconnected": "warning",
    "chat_integration_test_sent": "accent",
    "chat_webhook_settings_updated": "info",
    "checkout_session_verified": "success",
    "cleanup_mongodb_backups": "warning",
    "connector_initiated": "info",
    "connector_refused_suspicious_patch": "error",
    "context_refresh": "accent",
    "context_upload_rejected": "error",
    "context_uploaded": "success",
    "create": "success",
    "create_entitlement_type": "success",
    "create_mongodb_backup": "success",
    "create_price": "success",
    "create_product": "success",
    "deactivate_cascade": "warning",
    "delete_entitlement_type": "error",
    "delete_mongodb_backup": "error",
    "delete_price": "error",
    "deletion_mark_reconciled": "info",
    "deletion_scheduled": "warning",
    "disable": "warning",
    "dismiss": "warning",
    "email_failed": "error",
    "email_sent": "info",
    "email_unsubscribed": "info",
    "email_verified": "teal",
    "email_verify_failed": "error",
    "enable": "success",
    "error_deduplicated": "yellow",
    "error_deleted": "error",
    "error_ignored": "warning",
    "error_ingest_rejected": "error",
    "error_ingested": "blue",
    "error_suspicious_verdict_overridden": "warning",
    "error_unignored": "info",
    "errors_deleted_bulk": "error",
    "execute_tests": "accent",
    "failed_login": "error",
    "finalize_registration": "success",
    "fix_applied": "success",
    "fix_apply_dispatch_retried": "warning",
    "fix_apply_dispatched": "info",
    "fix_apply_redispatched": "accent",
    "fix_apply_step": "info",
    "fix_approved": "success",
    "fix_blocked": "warning",
    "fix_dismissed": "warning",
    "fix_failed": "error",
    "fix_marked_fixed": "success",
    "fix_rejected_patch": "warning",
    "fix_rollback": "warning",
    "full_database_reset": "error",
    "generate_tests": "accent",
    "get_backup_info": "blue",
    "hard_delete": "error",
    "hard_delete_cascade": "error",
    "health_check": "info",
    "ignore": "warning",
    "import_stripe_price": "info",
    "import_stripe_product": "info",
    "ingest_contract_violation": "error",
    "ip_auto_banned": "error",
    "ip_unblocked": "success",
    "lift_post_restore_maintenance": "success",
    "link_replaces": "info",
    "link_stripe_price": "info",
    "link_stripe_product": "info",
    "list_backups": "teal",
    "log_path_policy_violation": "warning",
    "login_critical_error": "error",
    "login_failed": "error",
    "login_locked_out": "error",
    "login_success": "success",
    "logout": "info",
    "low_confidence_approve_acknowledged": "warning",
    "manual_review_required": "warning",
    "mark_fixed": "success",
    "mcp_oauth_authorized": "teal",
    "mcp_policy_updated": "purple",
    "mcp_tool_denied": "warning",
    "mcp_tool_failed": "red",
    "mcp_tool_invoked": "blue",
    "metrics_rollup_recompute": "info",
    "mfa_enroll": "success",
    "mfa_recovery_code_failed": "error",
    "mfa_recovery_code_login": "warning",
    "mfa_recovery_codes_regenerate_failed": "error",
    "mfa_recovery_codes_regenerated": "success",
    "mfa_reset_by_admin": "warning",
    "mfa_reset_by_admin_denied": "error",
    "mfa_setup": "info",
    "mfa_verify": "info",
    "mfa_verify_failed": "error",
    "mfa_verify_success": "success",
    "mint_ingest_test_link": "accent",
    "notification_deleted": "warning",
    "notification_preferences_updated": "info",
    "notification_read": "info",
    "notifications_bulk_deleted": "warning",
    "notifications_read_all": "info",
    "oauth_device_approved": "success",
    "oauth_linked": "success",
    "oauth_refresh_reuse_detected": "error",
    "oauth_token_issued": "teal",
    "oauth_token_refreshed": "teal",
    "oauth_token_revoked": "warning",
    "oauth_tokens_revoked": "warning",
    "oauth_unlinked": "warning",
    "output_scan_fp_dismissed": "info",
    "owner_workspace_deleted": "error",
    "password_changed": "purple",
    "password_reset": "warning",
    "password_reset_failed": "error",
    "patch_quarantined_suspicious": "warning",
    "patch_quarantined_suspicious_refused": "error",
    "plan_downgrade_applied": "warning",
    "plan_limits_applied": "warning",
    "plan_migration_confirmed": "success",
    "plan_migration_declined": "warning",
    "post_apply_config_updated": "info",
    "post_apply_force_disabled": "warning",
    "post_apply_review_cleared": "success",
    "post_apply_toggled": "info",
    "post_restore_enable_maintenance": "warning",
    "post_restore_reset_superadmin_mfa": "warning",
    "post_restore_run_checks": "info",
    "post_restore_sync_billing": "info",
    "privilege_escalation": "error",
    "prompt_injection_output_scan_shadow": "warning",
    "push_pending_price_to_stripe": "info",
    "rate_limit_exceeded": "warning",
    "registration_critical_error": "error",
    "registration_field_created": "success",
    "registration_field_deleted": "error",
    "registration_field_updated": "info",
    "registration_fields_reordered": "info",
    "reject_patch": "warning",
    "reorder_product_plans": "info",
    "report_test_results": "success",
    "reseed_entitlement_types_from_schema": "warning",
    "reset": "warning",
    "restore_database": "warning",
    "retry_apply": "success",
    "rollback_completed": "success",
    "rollback_failed": "error",
    "rollback_initiated": "warning",
    "sa_drift_detected": "warning",
    "sa_recovery": "warning",
    "sa_role_change": "warning",
    "sa_status_change": "warning",
    "security_settings_updated": "purple",
    "settings_updated": "info",
    "soft_delete": "warning",
    "soft_delete_cascade": "error",
    "subscription_canceled": "warning",
    "subscription_checkout_started": "info",
    "subscription_price_changed": "info",
    "successful_login": "success",
    "superadmin_soft_disabled": "error",
    "support_portal_sso_mint": "info",
    "suspicious_denorm_drift": "warning",
    "sync_from_stripe_price": "info",
    "sync_from_stripe_product": "info",
    "target_activated": "green",
    "target_created": "success",
    "target_deactivated": "yellow",
    "target_deleted": "error",
    "target_entered_protection_mode_auto": "warning",
    "target_entered_protection_mode_manual": "warning",
    "target_exclude_from_metrics": "info",
    "target_flagged": "warning",
    "target_lang_fw_auto_set": "info",
    "target_language_framework_review": "warning",
    "target_released_from_protection_mode_auto": "success",
    "target_released_from_protection_mode_manual": "success",
    "target_unflagged": "info",
    "target_updated": "info",
    "tenant_activated": "green",
    "tenant_created": "success",
    "tenant_deleted": "error",
    "tenant_physical_purge": "error",
    "tenant_suspended": "warning",
    "tenant_totp_optional_updated": "info",
    "tenant_updated": "blue",
    "token_refresh": "teal",
    "totp_confirm_failed": "error",
    "totp_disable_failed": "error",
    "totp_disabled": "warning",
    "totp_enabled": "success",
    "totp_setup_failed": "error",
    "totp_setup_started": "info",
    "trigger_rollback": "warning",
    "unauthorized_access": "error",
    "unignore": "info",
    "update": "info",
    "update_entitlement_type": "info",
    "update_price": "info",
    "update_product": "info",
    "update_product_entitlements": "info",
    "upload_mongodb_backup_sftp": "success",
    "user_created": "success",
    "user_deleted": "error",
    "user_soft_delete_restored": "success",
    "user_updated": "info",
    "webhook_url_blocked_ssrf": "error",
    "workspace_invite_accepted": "success",
    "workspace_invite_created": "info",
    "workspace_invite_declined": "warning",
    "workspace_invite_revoked": "warning",
    "workspace_left": "info",
    "workspace_member_permissions_updated": "info",
    "workspace_member_removed": "warning",
    "workspace_switched": "info",
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
    if (!eventType) return '<span class="patcherly-muted"> - </span>';
    var label = getAuditEventLabel(evOrType);
    var variant = getEventVariantForEvent(evOrType);
    return '<span class="patcherly-audit-badge patcherly-audit-event-badge patcherly-audit-tone-' + escHtml(variant) + '">'
      + escHtml(label)
      + '</span>';
  }

  function categoryBadgeHtml(category) {
    if (!category) return '<span class="patcherly-muted"> - </span>';
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
      badgeText = actorWithPrefix(i18n.auditActorTenantAdmin || 'Workspace admin', text);
    } else if (kind === 'agent') {
      badgeText = text || 'Agent';
    }
    if (!badgeText) return '<span class="patcherly-muted"> - </span>';
    return '<span class="patcherly-audit-badge patcherly-audit-cat-badge patcherly-audit-cat-' + escHtml(variant) + '" title="'
      + escHtml(text || badgeText) + '">' + escHtml(badgeText) + '</span>';
  }

  function formatActor(evOrActor, i18n) {
    i18n = i18n || {};
    var resolved = resolveActorKind(evOrActor);
    if (resolved.kind === 'unknown') {
      return '<span class="patcherly-muted"> - </span>';
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
      return dash + '/errors?error=' + encodeURIComponent(String(errorId)) + '&view=history';
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
      return '<span class="patcherly-muted"> - </span>';
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
