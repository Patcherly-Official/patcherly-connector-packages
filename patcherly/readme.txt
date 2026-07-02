=== Patcherly ===
Contributors: patcherly, shambix
Tags: bug-fixing, error-monitoring, ai, automation, patch-management
Requires at least: 5.3
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 2.1.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Donate Link: https://github.com/sponsors/Patcherly-Official

Fix WordPress & WooCommerce errors automatically. AI drafts a tested patch, you approve it, and you can always roll it back.

== Description ==

**Patcherly is in free Public Beta.** [Sign up at Patcherly.com](https://patcherly.com) for a free account — Beta includes Pro features at no cost. A free Personal plan continues after Beta, and early users keep a lasting discount on paid plans.

Patcherly watches your WordPress or WooCommerce site for PHP errors, alerts you as they happen, and uses AI to draft a fix. **You decide what gets patched and when** — nothing changes on your site without your say-so, unless you deliberately turn on auto-apply (available on paid plans).

Your visitors keep browsing while you fix issues in minutes instead of firefighting overnight.

= How it works =

# **Connect** — Activate the plugin and click **Connect with Patcherly**. A secure browser flow pairs your site with your account — no API keys to copy or paste.
# **Monitor** — Choose which log files to watch. New errors show up in wp-admin and in your Patcherly dashboard.
# **Review** — Each error is analyzed and a focused fix is proposed, with a confidence score.
# **Apply safely** — Approve a fix and the connector backs up the affected file(s) on your own server first, then applies the patch. If the site fails its health check afterward, the original is restored automatically.
# **Stay in control** — You can roll back any patch manually, any time. Auto-analyze and auto-apply are optional, plan-dependent, and configured in your Patcherly dashboard.

= Built to be safe =

* **You're always in the loop.** AI drafts the fix; you choose whether and when it ships, unless you've opted into auto-analyze / auto-apply.
* **Privacy by design.** No personal or sensitive data ever leaves your server — no database, media library, or user data. Patcherly only ever sees a sanitized error message, stack trace, and a short snippet of code around the fault line.
* **Nothing is final.** Every patch is tested, with automatic rollback if it fails a health check — and you can also roll back manually, any time.
* **Enterprise-grade connection.** The plugin talks to Patcherly over a secure, audited pairing and API layer — not long-lived secrets pasted into wp-config.

Full detail: [Security overview](https://patcherly.com/security) · [Privacy Policy](https://patcherly.com/legal/privacy-policy) · [WordPress connector help](https://help.patcherly.com/connectors/wordpress)

= Patcherly in wp-admin =

* Errors list with severity, status, and one-click actions
* Settings, diagnostics, and connector status at a glance
* Optional **Emergency Rescue** — keeps monitoring and rollback working even if a bad update stops the main plugin from loading
* Path exclusions so sensitive folders are never touched
* Pre-apply backups, stored **on your server only**

This plugin is a lightweight **connector**. Full settings, error history, team access, and billing live in your [Patcherly dashboard](https://app.patcherly.com). For low-confidence fixes, manual confirmation may still be required even with auto-apply turned on.

[Patcherly.com](https://patcherly.com) · [Dashboard](https://app.patcherly.com) · [Help Center](https://help.patcherly.com) · [Terms of Service](https://patcherly.com/legal/terms-of-service) · [Contact](https://patcherly.com/contact) · [Discord community](https://discord.gg/7yZkD9KNsS) · [Source on GitHub](https://github.com/Patcherly-Official)

== External services & privacy ==

This plugin connects to **Patcherly**, a hosted service run by [Shambix](https://www.shambix.com). The API lives at **api.patcherly.com**; your account and dashboard are at **app.patcherly.com**. A connection is required for monitoring and patching — before pairing, the plugin only shows local settings and diagnostics.

**Pairing.** Click **Connect with Patcherly** on the Settings page to start a secure browser-based flow. The only optional call before pairing is **Refresh** on the Connector Status panel, which just checks that Patcherly is reachable — nothing about your site content is sent until pairing completes.

**No phone-home before pairing.** Nothing is sent on install, activation, deactivation, theme switches, or normal page loads. After pairing, the connector reports errors from logs you've chosen to monitor, and only acts on what you approve — or what your plan's auto-apply settings allow.

**What's sent, per error or patch action:**

* Error message, stack trace, file path, and line number from monitored PHP logs
* A short code excerpt around the error — never full theme, plugin, or upload directories
* Basic site metadata: site URL, WordPress/PHP/plugin versions, connector identity
* Authentication material identifying your paired site

Secret-looking values are sanitized on your server before anything is sent. Patcherly is built around Privacy by Design and is GDPR-compliant — see the [Privacy Policy](https://patcherly.com/legal/privacy-policy) for the full picture.

**AI processing.** Sanitized excerpts may be processed by large language models to suggest a fix. Providers are contractually barred from using your content to train general-purpose models; results go only to your Patcherly account.

**Backups stay local.** Pre-apply file backups live only in the connector's folder on your server — Patcherly never receives or stores them. You control how long you keep them; deleting them limits manual rollback for those specific fixes.

**Account.** A free account is required to pair and use the service — [sign up here](https://patcherly.com). [Terms of Service](https://patcherly.com/legal/terms-of-service) · [Privacy Policy](https://patcherly.com/legal/privacy-policy).

**Source code.** GPLv2-or-later, developed at [github.com/Patcherly-Official](https://github.com/Patcherly-Official). If you'd like to support development and the free Personal plan, [GitHub Sponsors](https://github.com/sponsors/Patcherly-Official) is open.

== Installation ==

1. Upload the `patcherly` folder to `/wp-content/plugins/`, or install it from **Plugins → Add New** in wp-admin.
2. Activate **Patcherly** from **Plugins**.
3. Open **Patcherly** in the admin menu (Settings page opens by default).
4. Click **Connect with Patcherly** to pair your site. A step-by-step progress panel walks you through each stage.
5. That's it — your site is now monitored, and you'll be alerted the moment something breaks so you can review a fix.


== Screenshots ==

1. Patcherly settings page in wp-admin — one-click **Connect with Patcherly**, step-by-step pairing progress, Diagnostics, Connector Status, and a collapsed **Advanced settings** block.
2. Errors list in wp-admin — live error stream with severity, occurrence count, and the "Generate fix" action.
3. Patch review and apply — AI-generated patch preview, confidence score, and apply / rollback controls.


== Frequently Asked Questions ==

= Does this plugin replace the Patcherly dashboard? =

No. It's a simplified view of your recent errors and plugin settings. Full settings, error history, sites, team, notifications, and billing live only in your [Patcherly dashboard](https://app.patcherly.com).

= Do I need a Patcherly account? =

Yes, a free one. [Sign up at patcherly.com](https://patcherly.com), then install the plugin and pair it. You can explore the plugin's local settings without an account, but monitoring and fixes require pairing.

= What data does this plugin send off-site, and where? =

Only what's needed to diagnose and fix a bug: error details, a short code excerpt around the fault, and basic site metadata (PHP/plugin versions and similar). It never sends your database, media library, or user data — and pre-apply backups always stay on your server. See **External services & privacy** above.

= Is anything sent without my consent? =

No. Nothing is sent until you click **Connect with Patcherly** and complete pairing. After that, you choose which errors to analyze, fix, or ignore. Disconnecting from your Patcherly dashboard, or removing the plugin, stops all communication.

= Can I roll back a failed fix? =

Yes, always. Before applying a patch, the connector backs up the affected file(s) on your own server — we never download or store your full codebase, and never see your database. If the post-apply check fails, rollback happens automatically. You can also roll back manually from your Patcherly dashboard at any time, as long as the backup still exists on your server (it's only removed if you delete it yourself, or uninstall the plugin with cleanup enabled).

= Is the plugin "trialware"? =

No. It's fully functional on every plan, including the free Personal plan. Paid plans only change your monthly quotas and capabilities — AI patches per month, custom monitored logs, auto-apply confidence threshold, and similar.

= Where can I find the source code? =

[github.com/Patcherly-Official/patcherly-connector-packages](https://github.com/Patcherly-Official/patcherly-connector-packages).

= What is Emergency Rescue mode? =

A tiny helper you confirm right after pairing (on by default). If a plugin update or a bad patch leaves your site on a white screen and the main plugin can't load, Rescue can still monitor, patch, or roll back — so a bug never locks you out of your own site. Turn it off in Settings → Advanced if you'd rather not use it.

= Does the plugin edit wp-config.php automatically? =

No. You can copy a small snippet in yourself, or opt in to the autowrite checkbox and click **Apply snippet now**. Saving settings never writes to wp-config.php on its own.


== Changelog ==

= 2.1.1 =

* WordPress.org directory copy refresh — clearer Beta callout, how-it-works and security summaries, and help/legal links.

= 2.0.7 =

* WordPress.org resubmission — review compliance updates for plugin paths, uploads-only storage, Emergency Rescue consent, and scoped Rescue logging.

= 2.0.6 =

* Hardened admin security — nonces on all AJAX and no-JS diagnostic form actions.
* Stricter settings sanitization for cache TTL and errors page size.
* Debug page scripts and styles now load through the standard WordPress enqueue API.
* Error severity in the Errors list and ingest payload now matches your Patcherly dashboard (Low / Medium / High / Critical).
* Repeated log errors are grouped server-side — the same unpatched error no longer floods your Errors list on every page view.

* Disconnect and lost OAuth connections now update your Patcherly dashboard target status promptly instead of staying green for days.
* Post-pairing onboarding — choose site context (Full / Minimal / Off) and confirm Emergency Rescue in one card; click Get started for explicit consent before install or upload.
* Emergency Rescue (recommended) — must-use helper enabled by default in onboarding; restores your site when the main plugin cannot load after a failed update or fix.
* WordPress.org compliance — canonical plugin paths, uploads-only connector storage, scoped Rescue logging, explicit opt-in for MU-plugin and wp-config writes.
* Errors page — Language and Error are separate columns again (Language hidden by default); saved column prefs from older versions are migrated so the error text column is not accidentally hidden.
* Errors page — fixed table layout so error text stays in the Error column; click to expand or double-click for a full read-only view including stack traces.
* Errors page — Ignore and Approve for Analysis actions match the Patcherly dashboard; ignore saves the error signature for future auto-skip.
* Log monitoring — PHP log severity (fatal, warning, info) is detected when errors are ingested.
* Connector Status — monitored, excluded, and patch exclusion paths list every path in a scrollable block; View collected context uses the same button style as Customize.
* Errors page — server-side pagination with first/prev/next/last controls; rows-per-page moved below the table (10–100, aligned with dashboard); API offset support for browsing beyond the first page.
* Errors page — clearer message when the Patcherly API rejects the errors list request.
* Emergency Rescue mode (optional) — after pairing, enable the must-use plugin in Settings → Advanced to ingest logs, roll back, and apply fixes when the main plugin cannot load.
* Deactivating removes Rescue only; uninstall with Cleanup on removes settings and the uploads/patcherly folder including backups.
* All outbound API calls (errors, ingest, OAuth refresh) now resolve the host from the configured Patcherly API endpoint setting.
* Debug log — Response column shows API detail or a short OK summary instead of staying blank.

= 2.0.1 =

* Connector Status — monitored paths, excluded paths, and patch exclusion paths now show your live target settings, with Customize buttons that open the right screen in your Patcherly dashboard (upgrade link when your plan needs Core or Pro).
* Site context for the AI — clearer privacy note that no database, user, or content data is shared; your workspace plan is shown after pairing with a link to billing to upgrade.
* View collected context — see what your site shares now and what Patcherly last stored, from Advanced settings or the Connector Status context-sharing row.

= 2.0.0 =

* Monitored Logs — log files at the website root (e.g. `/_error_log.log` or `_error_log.log`) are now accepted, including on managed-WordPress hosts like WP Engine and Kinsta where SFTP is jailed to the site root.


== Upgrade Notice ==

= 2.1.1 =

Directory listing copy update only — no action required after upgrade.
