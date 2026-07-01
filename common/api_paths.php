<?php
/** AUTO-GENERATED from config/api_paths.yaml — do not edit by hand. */
declare(strict_types=1);

final class PatcherlyApiPaths
{
    public const VERSION_PREFIX = "";
    public const APP_PREFIX = "/api";
    public const AUTH_PREFIX = "/auth";

    public const ROUTER_AGENTS = "/api/agents";
    public const ROUTER_AI_LANGUAGE_FRAMEWORKS = "/api/ai/language-frameworks";
    public const ROUTER_AI_MODEL_CATALOG = "/api/ai/model-catalog";
    public const ROUTER_AI_TEMPLATES = "/api/ai/templates";
    public const ROUTER_AUDIT = "/api";
    public const ROUTER_AUTH = "/auth";
    public const ROUTER_BACKUPS = "/api/backups";
    public const ROUTER_BACKUPS_MONGODB = "/api/backups/mongodb";
    public const ROUTER_BILLING = "/api/billing";
    public const ROUTER_BROADCAST = "/api/broadcast";
    public const ROUTER_BULK_EMAIL = "/api/bulk-email";
    public const ROUTER_CONNECTORS = "/api/connectors";
    public const ROUTER_CONTEXT = "/api/context";
    public const ROUTER_ENTITLEMENTS = "/api/entitlements";
    public const ROUTER_ERRORS = "/api/errors";
    public const ROUTER_INTEGRATIONS = "/api/integrations";
    public const ROUTER_LOG_PATHS = "/api/targets/{target_id}/log-paths";
    public const ROUTER_LOGS = "/api/logs";
    public const ROUTER_MAINTENANCE = "/api/superadmin";
    public const ROUTER_METRICS = "/api/metrics";
    public const ROUTER_NOTIFICATIONS = "/api/notifications";
    public const ROUTER_OAUTH = "/api/oauth";
    public const ROUTER_OBSERVE = "/api/observe";
    public const ROUTER_POST_RESTORE = "/api/admin/post-restore";
    public const ROUTER_PRODUCTS = "/api/products";
    public const ROUTER_PUBLIC = "/api/public";
    public const ROUTER_REGISTRATION_FIELDS = "/api/settings/registration-fields";
    public const ROUTER_SEARCH = "/api/search";
    public const ROUTER_SECURITY = "/api/security";
    public const ROUTER_SETTINGS = "/api/settings";
    public const ROUTER_SETUP = "/api/setup";
    public const ROUTER_SUPPORT = "/api/support";
    public const ROUTER_TARGETS = "/api/targets";
    public const ROUTER_TENANTS = "/api/tenants";
    public const ROUTER_TESTS = "/api/tests";
    public const ROUTER_USERS = "/api/users";
    public const NAMED_AUTH_FORGOT = "/auth/forgot";
    public const NAMED_AUTH_LOGIN = "/auth/login";
    public const NAMED_AUTH_LOGOUT = "/auth/logout";
    public const NAMED_AUTH_MFA_RECOVERY = "/auth/mfa/recovery";
    public const NAMED_AUTH_MFA_VERIFY = "/auth/mfa/verify";
    public const NAMED_AUTH_REFRESH = "/auth/refresh";
    public const NAMED_AUTH_REGISTER = "/auth/register";
    public const NAMED_AUTH_RESET = "/auth/reset";
    public const NAMED_AUTH_TOTP_CONFIRM = "/auth/totp/confirm";
    public const NAMED_AUTH_TOTP_SETUP = "/auth/totp/setup";
    public const NAMED_AUTH_TOTP_STATUS = "/auth/totp/status";
    public const NAMED_BILLING_STRIPE_WEBHOOK = "/api/billing/stripe/webhook";
    public const NAMED_CONTEXT_UPLOAD = "/api/context/upload";
    public const NAMED_ERRORS_INGEST = "/api/errors/ingest";
    public const NAMED_ERRORS_INGEST_TEST = "/api/errors/ingest-test";
    public const NAMED_ERRORS_LIST = "/api/errors";
    public const NAMED_ERRORS_STATUSES = "/api/errors/statuses";
    public const NAMED_OAUTH_DEVICE = "/api/oauth/device";
    public const NAMED_OAUTH_DEVICE_APPROVE = "/api/oauth/device/approve";
    public const NAMED_OAUTH_DEVICE_VERIFY = "/api/oauth/device/verify";
    public const NAMED_OAUTH_REVOKE = "/api/oauth/revoke";
    public const NAMED_OAUTH_TOKEN = "/api/oauth/token";
    public const NAMED_OAUTH_TOKEN_STATUS = "/api/oauth/token/status";
    public const NAMED_OBSERVE_METRICS = "/api/observe/metrics";
    public const NAMED_PRODUCTS_RESOLVE_SYNC = "/api/products/resolve-sync";
    public const NAMED_PRODUCTS_SYNC_STATUS = "/api/products/sync-status";
    public const NAMED_PUBLIC_CONFIG = "/api/public/config";
    public const NAMED_PUBLIC_INSTALL_PS1 = "/api/public/install.ps1";
    public const NAMED_PUBLIC_INSTALL_SH = "/api/public/install.sh";
    public const NAMED_PUBLIC_POST_RESTORE_MAINTENANCE = "/api/public/post-restore/maintenance";
    public const NAMED_PUBLIC_REGISTRATION_FIELDS = "/api/public/registration-fields";
    public const NAMED_PUBLIC_REGISTRATION_TRIAL_INFO = "/api/public/registration-trial-info";
    public const NAMED_SETTINGS_TASK_BROKER_REDETECT = "/api/settings/task-broker/redetect";
    public const NAMED_SETUP_APPLY = "/api/setup/apply";
    public const NAMED_SETUP_AUTO_DISCOVER = "/api/setup/auto-discover";
    public const NAMED_SETUP_STATUS = "/api/setup/status";
    public const NAMED_SUPPORT_PORTAL = "/api/support/portal";
    public const NAMED_TARGETS_CONNECTOR_DISCONNECT = "/api/targets/connector-disconnect";
    public const NAMED_TARGETS_CONNECTOR_STATUS = "/api/targets/connector-status";
    public const NAMED_USERS_ME = "/api/users/me";
    public const ALIAS_CONNECTOR_STATUS = "/api/targets/connector-status";
    public const ALIAS_CONNECTOR_STATUS_LEGACY = "/api/connector-status";
    public const CONNECTOR_CONTRACT_FILE_CONTENT = "/api/file-content";
    public const CONNECTOR_CONTRACT_RESCUE_POLL = "/api/rescue/poll";

    public static function appPath(string ...$segments): string
    {
        $base = rtrim(self::VERSION_PREFIX . self::APP_PREFIX, '/');
        $parts = array_values(array_filter(array_map(static fn ($s) => trim($s, '/'), $segments)));
        if ($parts === []) {
            return $base;
        }
        return $base . '/' . implode('/', $parts);
    }
}
