=== Patcherly ===
Contributors: patcherly, shambix
Tags: bug-fixing, error-monitoring, patch-management, ai, debug
Requires at least: 5.3
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 2.5.13
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html
Donate Link: https://github.com/sponsors/Patcherly-Official

Catch WordPress and WooCommerce errors 24/7. Get bug fixes ready to review and apply in seconds, rollback anytime. Built by WordPress experts.

== Description ==

**Patcherly catches WordPress and WooCommerce errors and provides bug fixes ready to review and apply in seconds.**

We've all been there...

- A plugin update ships a broken function call on your PHP version. Checkout dies on Friday night. You're debugging at 11pm while your customers panic.

- A theme update changes something subtle and now 5% of your checkout flow errors. You're chasing your developer for days. Meanwhile, you're losing orders.

- A custom integration breaks and your customers can't access their accounts. Bad reviews roll in, your reputation takes the hit.

**This is what Patcherly finally stops.** It was built by WordPress experts with 15+ years experience debugging and fixing these exact bugs. 

Patcherly watches your site 24/7. When something breaks, it detects it instantly, proposes a fix tailored to **your** website (not some generic AI fix), backs up your files on **your** server, and waits for **your** approval.

You stay in control. You review the fix. You decide. If something's wrong, rollback is one click (and automatic if our tests fail). Your site stays yours.

> Think of it as giving yourself the superpower to fix production bugs safely and instantly, without waiting for days while the outage is costing you customers and reputation, giving you peace of mind back.

= How it works =

1. **Watch** - Install the plugin, pair your site in 2 minutes, and Patcherly starts monitoring.
2. **Think** - When an error happens, Patcherly analyzes it with full context about your site and proposes a focused fix.
3. **Fix** - You review and approve. We back up your files on your server. The patch applies. Tests run. If anything's off, automatic rollback.

That's it. You're always in the loop. Nothing changes without you.

= Free to start. 30-day Pro trial included. =

Install the plugin, pair your site, and get a full 30-day Pro trial with no credit card. After that, keep the free Personal plan or subscribe. See [pricing](https://patcherly.com/pricing).

= Built on trust =

Your files stay on your server. Period. We never store your source code, database, or media. Only what's needed to fix a bug leaves your site: error details and a short code snippet. Pre-apply backups live on your infrastructure, never ours. Your code doesn't train AI models and we never ask for access to your website or credentials.

= Resources =

[Patcherly.com](https://patcherly.com) · [Help Center](https://help.patcherly.com) · [Security](https://patcherly.com/security) · [Privacy](https://patcherly.com/legal/privacy-policy) · [Discord](https://discord.gg/7yZkD9KNsS) 


== Installation ==

1. Install **Patcherly** from **Plugins → Add New**, or upload the `patcherly` folder to `/wp-content/plugins/`.
2. Activate the plugin.
3. Go to **Patcherly → Home**.
4. Click **Connect with Patcherly** and finish pairing.
5. Done — your site is monitored.


== Screenshots ==

1. Patcherly Home — connection status, recent activity, and metrics.
2. Errors list — live errors with severity and quick actions.
3. Patch review — what's being fixed, why, and approve or skip.


== Frequently Asked Questions ==

= Do I need a Patcherly account? =

Yes, but it's free. [Sign up](https://patcherly.com), install the plugin, and connect. You'll get a 30-day full Pro trial immediately.

= What if I don't like a fix? =

No problem. Rollback with one click from the dashboard, or manually anytime the backup exists on your server.

= What data leaves my site? =

Only what's needed to diagnose and fix: error details, a code snippet, and basic site metadata. Never your database, media, or user data. Backups stay on your server. You can check exactly what gets sent from the Settings page -> Context. [Privacy Policy](https://patcherly.com/legal/privacy-policy).

= Is anything sent before I connect? =

No. Nothing happens until you complete **Connect with Patcherly** in the plugin.

= Does this replace my dashboard? =

No. wp-admin shows errors and recent activity. Full history, multiple sites, team access, and billing live in the [dashboard](https://app.patcherly.com).

= Can I turn on auto-apply? =

Yes, optional. Most keep manual approval on. Enable auto-apply in your dashboard if you want Patcherly to apply fixes automatically if the fix confidence is above 90% (available on paid plans).

= What is Emergency Rescue? =

A safety net that stays active even if the main plugin can't load (e.g. a bad theme custom code or plugin update crashed your site completely). Keeps monitoring, patching and rollback available when you need them most. On by default; disable in Settings → Advanced if you prefer.

= Does the plugin edit my wp-config.php? =

Only with your consent, and only when needed. Pairing never changes wp-config. After you connect, **Get started** can apply the debug snippet if the site has no logging yet and you leave that checkbox on. If logging is already configured, Get started skips the snippet. Later you can paste it manually or use **Apply snippet now** in Settings → Advanced.

= Where's the source? =

[github.com/Patcherly-Official/patcherly-connector-packages](https://github.com/Patcherly-Official/patcherly-connector-packages)


== Changelog ==

= 2.5.12 =
* Emergency Rescue no longer writes Permission denied warnings into PHP error logs when the must-use file cannot be updated (common on managed hosts such as WP Engine).

= 2.5.11 =
* Home Overview “Errors found” card links to the plugin Errors page.
* Home account bar includes a Settings button next to Connect/Disconnect.

= 2.5.10 =
* Custom log discovery no longer shows a false upgrade prompt on Core and Pro plans; the notice on Home appears below Overview.
* Footer Sign up and pairing prompts link to registration with attribution parameters for analytics.

= 2.5.9 =
* Sign-up links from the plugin open the dashboard registration page (not a dead `/signup` URL).

= 2.5.7 =
* After you connect the site, Get started can install Emergency Rescue and optionally apply the wp-config debug snippet (with your consent). Pairing itself still does not change those files.
* Errors list filters now include a **Show only ignored** toggle (matches the Patcherly dashboard).
* Hiding an error no longer surfaces a confusing HTTP 409 in the browser console when the error was already ignored.
* Stops PHP warnings when checking whether Python or Node is available on hosts that block `exec`.
* After activation, the “Plugin activated.” notice includes a bold link to pair the site from the Patcherly Home screen.
* Debug-log wp-config snippet also turns off on-screen PHP errors (`display_errors`) so admin deprecation notices stay in `debug.log` only — re-apply the snippet if an older block is already present.
* When Emergency Rescue cannot overwrite its must-use file (permissions), Patcherly stops retrying on every page load so PHP error logs are not flooded.
* Tested with WordPress 7.1.

= 2.5.3 =
* Complete rewrite: aligned tone and messaging with Patcherly's core philosophy. Removed generic language, added relatable pain points and emphasis on control and trust.

= 2.5.2 =
* Maintenance release aligned with current Patcherly connector package.

= 2.5.0 =
* First public release on WP.org
* Improved signup copy and trial FAQ for hosted plans.


== Upgrade Notice ==

= 2.5.7 =

Adds a **Show only ignored** filter on the Errors page, fixes a console warning when hiding an already-ignored error, and stops PHP warnings on hosts that block shell `exec` during optional Python/Node detection.

= 2.5.3 =

Recommended — now aligned with Patcherly's core messaging and positioned for WordPress users.