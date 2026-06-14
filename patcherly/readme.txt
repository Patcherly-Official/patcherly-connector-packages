=== Patcherly ===
Contributors: patcherly, shambix
Tags: bug-fixing, error-monitoring, ai, automation, patch-management
Requires at least: 5.3
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.49.18
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

**Website Pairing.** Pairing uses a simple, secure, one-click flow — no API keys to copy or paste. Before pairing, the plugin contacts `api.patcherly.com` **only** in response to explicit operator actions on the Settings page: clicking "Connect with Patcherly" (starts pairing) or clicking "Refresh" on the Connector Status panel (a one-shot, cached, no-auth call to `/api/health/summary` so you can confirm Patcherly itself is reachable before pairing). It never reaches out on its own. After you click "Connect with Patcherly", your browser is redirected to the [Patcherly dashboard](https://app.patcherly.com) to confirm the pairing with your account.

**No phone-home before pairing.** The plugin makes zero outbound HTTP requests on plugin activation, deactivation, theme switch, or normal page loads. All traffic to Patcherly only starts once you actively initiate it — by pairing your site, clicking Refresh on the Status panel, or clicking "Refresh site context" — and the site-context upload is always a manual button on the settings page, never automatic.

**Data sent to api.patcherly.com.** For every error or bug detected on your website, and on every patch request, the connector sends:

* the error message, stack trace, file path, and line number captured from the PHP error logs you have opted into monitoring;
* a small snippet of the file around the error (just the lines the AI needs to generate an accurate patch) — never your full site files, your database (user data, content), or media;
* basic site metadata (site URL, WordPress version, PHP version, plugin version, and a connector ID);
* your site's authentication credential so Patcherly knows the request really came from you.

Sensitive-looking values (potential secrets, keys, tokens) are sanitized before any snippet leaves your server.

**AI processing.** Patcherly's backend forwards the sanitized snippet to large language models for analysis and patch generation. The specific LLM provider may change over time as Patcherly evaluates models for quality, latency, and cost; in every case the provider is contractually prohibited from using customer code for model training, and outputs are returned only to your Patcherly account.

**Data stored on YOUR server.** Pre-apply backups of files patched by Patcherly stay in a local backup folder on your server only. Patcherly never receives them. Retention of those backups is up to you (we never delete them) as well as deletion, but doing so will impede manual rollback, shall it be needed for a rollback (we advise to keep them for at least 30 days).

**Account required.** At minimum, a free Patcherly account is required to use the plugin services. Sign-up: [https://patcherly.com](https://patcherly.com). Terms of Service: [https://patcherly.com/legal/terms-of-service](https://patcherly.com/legal/terms-of-service). Privacy Policy: [https://patcherly.com/legal/privacy-policy](https://patcherly.com/legal/privacy-policy).

**Source code.** The plugin is open source under GPLv2-or-later. Development happens at [github.com/Patcherly-Official](https://github.com/Patcherly-Official).

If you would like to support us, and help us keeping a free Personal plan available to all forever, you can head over to our [GitHub Sponsors page](https://github.com/sponsors/Patcherly-Official) and make a donation.

== Installation ==

1. Upload the `patcherly` folder to `/wp-content/plugins/` 
2. Activate **Patcherly** from **Plugins** in wp-admin.
3. Open **Patcherly** in the admin menu (Settings page opens by default).
4. Click **Connect with Patcherly** to pair the site with your Patcherly account. A step-by-step progress panel shows you each stage of the pairing.

== Screenshots ==

1. Patcherly settings page in wp-admin — one-click **Connect with Patcherly**, step-by-step pairing progress, Diagnostics, Connector Status, and a collapsed **Advanced settings** block.
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

No. The plugin only talks to api.patcherly.com after you actively pair the site by clicking **Connect with Patcherly**. Before pairing, no error data or site information is transmitted. After pairing, the connector starts monitoring your website for errors; once an error happens, it's sent to Patcherly so you can get an analysis and an AI-generated fix. If you approve the fix, Patcherly sends it back to your connector to apply. Disconnecting the site in the Patcherly dashboard, or deleting the plugin, stops all communication with Patcherly.

= Can I roll back a failed fix? =

Yes. Before applying any patch, the connector saves a backup of the affected file(s) into its local backup folder on YOUR server. If the post-apply health check fails, an auto-rollback restores the originals from the backup immediately. You can also trigger a manual rollback from wp-admin or the dashboard at any time, as long as the backup folder and file backup(s) still exists on your server.

= Is the plugin "trialware"? =

No. The plugin is fully functional in all plans, including the free Personal plan. Paid tiers only change quotas and capabilities on the Patcherly service backend (number of monitored sites, AI patches per month, auto-apply confidence, etc.), not the plugin code on your server.

= Where can I find the source code? =

The plugin is GPLv2-or-later. Source is mirrored at [github.com/Patcherly-Official](https://github.com/Patcherly-Official).

== Changelog ==

= 1.48.0 – 1.49.9 =

* New look — refreshed header and footer brand bar, redesigned Settings page, "Patcherly" menu with a new shield icon.
* New Demo page — 20 example errors and a guided tour to explore the plugin without pairing a real site. Completely offline.
* New Debug Mode (opt-in, off by default) — local log of API calls to help with support. Cleared automatically when turned off.
* Friendlier pairing — step-by-step progress panel and clear error messages, with a one-click link to your dashboard if your site isn't registered yet.
* Errors page — full action parity with the dashboard (Analyze / Preview / Accept / Approve / Apply / Rollback / Restore / Dismiss / Delete), in-place patch preview, status hover-tooltips, manageable columns (Language hidden by default), and click-to-expand long messages.
* Connector Status panel — plugin version, authentication, signing, workspace, target, and last connection at a glance.
* Settings reorganised — Connector Status above Diagnostics, one button per diagnostic with its own inline result.
* Context-sharing consent — pick Full / Minimal / Off after pairing (defaults to Off). Change any time in Advanced settings.
* Privacy + security — no outbound calls before you pair, and stored credentials are now encrypted at rest.
* Bugfix — Debug Mode and Demo submenu checkboxes now persist correctly when saved.

= 1.47.0 =

* Stronger credential hygiene — removing a website / workspace / user revokes credentials immediately.
* Safer log paths — custom log paths are validated before any file is read.
* Fully translatable admin interface — ships with a template and an Italian translation.
* Cleaner plugin code — full pass against the official WordPress plugin-check tool.
* Direct connection to api.patcherly.com (the optional shared-host proxy mode was retired).
* In-plugin self-updater removed — updates will arrive automatically once the plugin is approved on WordPress.org.
* Expanded Privacy and FAQ sections.

= 1.44.0 =

* Rollback / apply payload contract alignment with the rest of the Patcherly platform.
* Improved low-confidence and policy handling.
* General stability and diagnostics improvements.

== Upgrade Notice ==

= 1.49.0 =

Privacy and security update. The plugin no longer makes any outbound call before you actively pair the site, and your stored credentials are now encrypted at rest. No action required after upgrade.

= 1.47.0 =

Recommended security and quality update. Stronger credential hygiene, safer log-path validation, fully translatable admin interface, and a cleaner plugin code base.