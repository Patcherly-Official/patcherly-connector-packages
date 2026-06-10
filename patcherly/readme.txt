=== Patcherly ===
Contributors: patcherly, shambix
Tags: bug-fixing, error-monitoring, ai, automation, patch-management
Requires at least: 5.3
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.49.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Donate Link: https://github.com/sponsors/Patcherly-Official

Monitor and fix bugs & errors on your WordPress / WooCommerce website, safely, automatically & in real time.

== Description ==

Patcherly monitors bugs & errors on your WordPress / WooCommerce website in real time, so you can get notified as they happen, review a custom AI-generated patch, and approve the fix to be applied directly to your site — with a backup and auto-rollback if a patch is faulty, in seconds. 

Your site stays up and running, without your users or customers ever noticing.

** Patcherly is currently in a free Public Beta: [sign up at Patcherly.com](https://patcherly.com) and enjoy the Pro Plan (all features included) for FREE for the duration of the Beta. A free Personal plan is available afterwards. Every Beta user is personally onboarded in minutes by the founder. **

This plugin is a "connector" between your WordPress site and the Patcherly service (api.patcherly.com). It does **not** upload your full site, database, media library, or user data. What it does send to Patcherly, on a per-error basis, is described in the **External services & privacy** section below.

Key capabilities:

* Error list and status tools directly in wp-admin.
* Every patch creates a snapshot of the affected files; rollback in seconds.
* Log paths customization for error monitoring.
* Path exclusion support for safe filtering (exclude folders and files from being patched).
* Backups of the modified files are kept on **your** server (the connector's local backup folder); Patcherly never receives or stores them.

The Pro Plan (free for everyone during the Beta) includes up to 10 websites monitored from a single account, 100 AI-powered bug fixes per month, patch auto-apply, advanced live patch testing, custom AI-confidence thresholds for auto-apply, and custom log paths. Auto-rollback is included in all plans.

Beta users will get a generous discount on paid plans once the Beta ends, or can switch to the free Personal plan forever. The plugin itself is fully functional in all tiers; paid tiers only change quotas and capabilities of the Patcherly service backend.

[Patcherly.com](https://patcherly.com) | [Help Center](https://help.patcherly.com) | [Privacy Policy](https://patcherly.com/legal/privacy-policy) | [Terms of Service](https://patcherly.com/legal/terms-of-service) | [Security](https://patcherly.com/security) | [Get in touch](https://patcherly.com/contact) | [Discord community](https://discord.gg/7yZkD9KNsS) | [Patcherly on GitHub](https://github.com/Patcherly-Official)

Notes:

* For low-confidence patches (< 90% by default), dashboard manual confirmation may be required even when auto-apply is on.

== External services & privacy ==

This plugin connects your WordPress site to **api.patcherly.com**, an external SaaS operated by [Patcherly](https://patcherly.com) (a product of [Shambix](https://patcherly.com)). Connecting to the service is required for the error monitoring and patching workflow; without it the plugin only displays local diagnostics.

**Website Pairing.** Pairing uses a simple and intuitive flow, through secure OAuth 2.0 Device Authorization Grant (RFC 8628). The plugin contacts `api.patcherly.com` **only** when you click "Connect with Patcherly" — it never reaches out to any external host before that click. After requesting a device code, your browser is redirected to the [Patcherly dashboard](https://app.patcherly.com) to confirm the pairing with your account. No API keys are required.

**No phone-home before pairing.** As of v1.49.0 the plugin makes zero outbound HTTP requests on `init`, plugin activation, deactivation, or theme switch. All API traffic — including the site-context upload — is gated on the OAuth bundle being present, and the context upload itself is a manual "Refresh site context" button on the settings page.

**Data sent to api.patcherly.com.** For every error or bug in your website, and on every patch request, the connector sends:

* the error message, stack trace, file path, and line number captured from PHP error logs you have opted into monitoring;
* a small snippet of the file around the error (the lines needed for the AI to generate an accurate patch) — never the full site files, the database (e.g. user or content data) or media;
* basic site metadata (site URL, WordPress version, PHP version, plugin version, connector ID);
* the active OAuth token associated with your website.

Sensitive-looking values (potential secrets, keys, tokens) are sanitized before any snippet leaves your server.

**AI processing.** Patcherly's backend forwards the sanitized snippet to large language models for analysis and patch generation. The specific LLM provider may change over time as Patcherly evaluates models for quality, latency, and cost; in every case the provider is contractually prohibited from using customer code for model training, and outputs are returned only to your Patcherly account.

**Data stored on YOUR server.** Pre-apply backups of files patched by Patcherly stay in a local backup folder on your server only. Patcherly never receives them. Retention of those backups is up to you (we never delete them) as well as deletion, but doing so will impede manual rollback, shall it be needed for a rollback (we advise to keep them for at least 30 days).

**Account required.** At minimum, a free Patcherly account is required to use the plugin services. Sign-up: [https://patcherly.com](https://patcherly.com). Terms of Service: [https://patcherly.com/legal/terms-of-service](https://patcherly.com/legal/terms-of-service). Privacy Policy: [https://patcherly.com/legal/privacy-policy](https://patcherly.com/legal/privacy-policy).

**Source code.** The plugin is open source under GPLv2-or-later. Development happens at [github.com/Patcherly-Official](https://github.com/Patcherly-Official).

If you would like to support us, and help us keeping a free Personal plan available to all forever, you can head over to our [GitHub Sponsors page](https://github.com/sponsors/Patcherly-Official) and make a donation.

== Installation ==

1. Upload the `patcherly` folder to `/wp-content/plugins/` 
2. Activate **Patcherly Connector** from **Plugins** in wp-admin.
3. Open **Patcherly Connector** in the admin menu.
4. Click **Connect with Patcherly** to pair the site via OAuth Device Authorization.

== Screenshots ==

1. Patcherly Connector settings page in wp-admin — server URL, OAuth pairing status, log-path monitoring, and debug toggles.
2. Errors list in wp-admin — live error stream with severity, occurrence count, and the "Generate fix" action.
3. Patch review and apply — AI-generated patch preview, confidence score, and apply / rollback controls.

== Frequently Asked Questions ==

= Does this plugin replace the Patcherly dashboard? =

No. It provides the site-side connector flow and a simplified UI of the official dashboard. Human review and policy confirmations are still managed in the Patcherly dashboard at [app.patcherly.com](https://app.patcherly.com).

= Do I need a Patcherly account? =

Yes. At minimum, a free Patcherly account is required because the AI patching and multi-site monitoring run as a Software-as-a-Service at api.patcherly.com. You can sign up at [patcherly.com](https://patcherly.com). The plugin can be installed and the settings page explored without an account; pairing your website, monitoring it for bugs and patching require sign-in.

= What data does this plugin send off-site, and where? =

The plugin only ever talks to one external host: **api.patcherly.com**. It sends error details, a small file snippet around the error line, and basic site metadata (URL, WP / PHP / plugin versions). It does **not** send your database, media library, user data, or full site files. Pre-apply backups stay on your own server. See the **External services & privacy** section above for the full list, plus the [Privacy Policy](https://patcherly.com/legal/privacy-policy) and [Terms of Service](https://patcherly.com/legal/terms-of-service).

= Is anything sent without my consent? =

No. The plugin only talks to api.patcherly.com after you actively pair the site via the OAuth flow. Before pairing, no error data or site metadata is transmitted. After pairing, the connector will start monitoring your website for errors and once they happen, it will send the to the Patcherly API to provide you with an error analysis and bug fix; if you approve the fix then it will be sent back to your website connector for processing. Disconnecting the site in the Patcherly dashboard or deleting the plugin stops all outbound/inbound traffic.

= Can I roll back a failed fix? =

Yes. Before applying any patch, the connector saves a backup of the affected file(s) into its local backup folder on YOUR server. If the post-apply health check fails, an auto-rollback restores the originals from the backup immediately. You can also trigger a manual rollback from wp-admin or the dashboard at any time, as long as the backup folder and file backup(s) still exists on your server.

= Is the plugin "trialware"? =

No. The plugin is fully functional in all plans, including the free Personal plan. Paid tiers only change quotas and capabilities on the Patcherly service backend (number of monitored sites, AI patches per month, auto-apply confidence, etc.), not the plugin code on your server.

= Where can I find the source code? =

The plugin is GPLv2-or-later. Source is mirrored at [github.com/Patcherly-Official](https://github.com/Patcherly-Official).

== Changelog ==

= 1.49.3 =

* **Hotfix — admin_init fatal.** `oauth_client.php` is now required at plugin boot. The previous lazy-load pattern crashed every wp-admin pageview with `Call to undefined function patcherly_oauth_is_paired()` because the new pre-pairing gates fired on `admin_init` before any code path had pulled the helper in. Test `test-no-phone-home-before-pairing.php` now asserts the top-level require so the regression cannot reappear.

= 1.49.2 =

* **No phone-home before pairing.** Removed the four `init` hooks (and their helpers `maybe_discover_api_url`, `maybe_discover_ids`, `maybe_fetch_log_paths`, `maybe_collect_context`) plus the `activated_plugin` / `deactivated_plugin` / `switch_theme` triggers that uploaded site context. Nothing outbound now happens until the admin clicks **Connect with Patcherly**. WordPress.org guideline 7/9 compliance.
* **Privacy & Terms URLs.** Updated readme.txt links to the canonical `/legal/privacy-policy` and `/legal/terms-of-service` (the previous short `/privacy` and `/terms` paths 404'd).
* **No hardcoded `wp-content` literals.** Patch-target resolution now uses `WP_CONTENT_DIR`, `WP_PLUGIN_DIR`, and `get_theme_roots()`; sites that relocate wp-content via the Make WordPress "abstracted index" pattern are no longer silently broken.
* **Lock files moved out of the plugin folder.** `Patcherly_FileLock` now writes to `wp-content/uploads/patcherly_locks/sha1.lock` (protected by `.htaccess` + `web.config` + `index.php`) instead of dropping `*.lock` files next to patched targets in `wp-content/plugins/` or `wp-content/themes/`.
* **OAuth secret encryption at rest.** `access_token`, `refresh_token`, and `hmac_secret` are now AEAD-encrypted with libsodium (`pcx1:` envelope, key derived from `wp_salt('secure_auth')` + a per-install nonce). Legacy plaintext values load transparently and are re-encrypted in place on first read. Falls back to plaintext storage on hosts that disable libsodium.
* **Context cache hardening.** `wp-content/uploads/patcherly_cache/` JSON files are now written via `WP_Filesystem` with restrictive permissions, encoded with `wp_json_encode`, and protected by a `web.config` (IIS) sibling alongside the existing `.htaccess` + `index.php`. Context upload is now strictly opt-in (button on the settings page); the pre-pairing init trigger was removed.
* **AJAX nonce enforcement.** The OAuth AJAX handlers (`ajax_oauth_start`, `ajax_oauth_poll`, `ajax_oauth_disconnect`) now route through a shared `_authorize_oauth_ajax()` helper that enforces the return value of `check_ajax_referer` and responds with HTTP 403 on a missing or stale nonce. The previous `$die = false` ignored-return pattern is gone.
* **Server URL UX.** Pre-filled with `https://api.patcherly.com` on activation and tucked into a collapsed "Advanced — change API endpoint" section. Sanitizer falls back to the default if an operator saves an empty value. During pairing the connector tries the configured host first, then `https://apidev.patcherly.com` as a one-shot fallback (only when the configured host is the production default).
* **New CLI tests.** Five regression tests under `connectors/patcherly/tests/`: `test-no-phone-home-before-pairing.php`, `test-ajax-oauth-nonce-enforcement.php`, `test-lock-file-in-uploads.php`, `test-patch-target-path-resolution.php`, `test-oauth-secret-encryption.php`.

= 1.47.0 =

* Launch-blocker hardening: OAuth token revocation when targets/tenants/users are soft-deleted; refresh-token reuse detection revokes the full token family.
* Log-path policy lockdown: connector-side validation mirrors the server allow-list; unsafe paths are dropped before any I/O is attempted.
* Plugin-check cleanup: standardized text domain to `patcherly`, escaped admin output, sanitized `register_setting()` callbacks, switched `parse_url` to `wp_parse_url`, replaced `unlink` with `wp_delete_file`, gated diagnostic `error_log()` behind `WP_DEBUG`, annotated nonce-verification on AJAX handlers that delegate to `_authorize_admin_ajax()`.
* Internationalization: every admin string is now wrapped in `__()` / `esc_html__()` / `esc_attr__()` against the `patcherly` text domain. `languages/patcherly.pot` ships with the plugin and an Italian translation (`patcherly-it_IT.po`) is bundled. WordPress 4.6+ auto-loads bundled translations from `<plugin>/languages/` -- the explicit (and now plugin-check-discouraged) `load_plugin_textdomain()` call was removed.
* Legacy proxy removal: the shared-host `api_proxy.php` deployment mode and its `patcherly_proxy_uses_api_prefix` option were retired -- the connector now talks only to the direct FastAPI host.
* Plugin updates: removed the in-plugin `update-checker.php` self-updater so the plugin complies with the WordPress.org `plugin_updater_detected` rule. Once WordPress.org approves the listing, updates are delivered by the directory; before approval, operators install/update by uploading `patcherly.zip` from the latest GitHub release via Plugins -> Add New -> Upload Plugin.
* Header alignment: `Tested up to` and `Stable tag` now match the plugin header; `Requires at least` bumped to 5.3 to match `wp_timezone_string()` availability.
* WordPress.org submission polish: added an **External services & privacy** section enumerating what data the connector sends to `api.patcherly.com`, expanded the FAQ (account requirement, opt-in, rollback, trialware), added `== Screenshots ==` captions, linked the Privacy Policy and Terms of Service, and reframed Beta as a free Public Beta to match guideline 6 (SaaS) and guideline 7 (consent).

= 1.44.0 =

* Connector parity updates for rollback/apply payload contracts.
* Improved low-confidence and policy handling notes.
* Stability and diagnostics improvements.

== Upgrade Notice ==

= 1.49.0 =

WordPress.org plugin-directory submission hardening: removes all pre-pairing outbound HTTP, encrypts OAuth secrets at rest, moves lock files into the uploads folder, drops hardcoded `wp-content` paths, and enforces OAuth AJAX nonces. No customer action required after upgrade.

= 1.47.0 =

Recommended security and quality update. Standardizes the text domain, hardens admin output escaping, and aligns the plugin metadata with WordPress.org submission requirements.