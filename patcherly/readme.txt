=== Patcherly Connector ===
Contributors: patcherly,shambix
Tags: bug-fixing, patch-management, error-monitoring, ai, automation, diagnostics
Requires at least: 5.0
Tested up to: 6.7
Requires PHP: 7.4
Stable tag: 1.46.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Monitor and fix bugs & errors on your WordPress / WooCommerce website, automatically & in real time.

== Description ==

Patcherly monitors bugs & errors on your WordPress / WooCommerce website in real time, so you can get notified as it happens, review the custom tailored AI-powered patch, approve the fix to be applied directly to your site, with backup and auto-rollback if a patch is faulty, in seconds. Your website will up and running again without your users and customers never noticing the bug.

** Patcherly is currently in *Private Beta*: [sign up](https://patcherly.com)
 and enjoy a Pro Plan (all features included!) for FREE, until the end of the Beta. Personal plan (free) available afterwards. Every Beta user will be personally onboarded in minutes, by the founder. **

This plugin serves as a "connector" between your website and the Patcherly platform.
We never see, store, save or upload your website files, user data or database, we don't need to.
All the files stay on your server, including the backups we take of your files before patching them.
Your code is never used to train a commercial AI and if there is any sensitive data in your files, we sanitize it before analyzing the error and providing a patch.

Patcherly is the best of AI, combined with [privacy and safety by design](https://patcherly.com/security).

Key capabilities:

* Error list and status tools directly in wp-admin.
* Every patch creates a snapshot of the affected files, rollback in seconds.
* Log paths customization for error monitoring.
* Path exclusion support for file safe filtering (exclude folders and files from patching).

The Pro Plan (available for FREE to all, during the Beta) includes 10 websites to monitor and fix from a single account, 100 AI-powered bug fixes per month included, patch auto-apply feature, advanced patch live testing, custom AI confidence settings for auto-apply, custom log paths for monitoring. Auto-rollback is included in all plans.

Beta users will enjoy a generous discount on paid plans, once the Beta is over, or they can switch to the Personal plan (free), forever.

[Patcherly.com](https://patcherly.com) | [Help Center](https://help.patcherly.com) | [Get in touch](https://patcherly.com/contact) | [Join the Discord Community](https://discord.gg/7yZkD9KNsS) | [Patcherly on Github](https://github.com/Patcherly-Official)

Notes:

* Post-apply automated restart is a feature only available for Python and Node.js web apps, not for WordPress websites.
* For low-confidence patches (< 90% by default), dashboard manual confirmation may be required even with auto-apply on.

== Installation ==

1. Upload the `patcherly` folder to `/wp-content/plugins/` 
2. Activate **Patcherly Connector** from **Plugins** in wp-admin.
3. Open **Patcherly Connector** in the admin menu.
4. Configure your Patcherly API URL and credentials.

== Frequently Asked Questions ==

= Does this plugin replace the Patcherly dashboard? =

No. It provides the site-side connector flow. Human review and policy confirmations are still managed in the Patcherly dashboard where required.

= Can I roll back a failed fix? =

Yes. The connector reports backup/apply/rollback outcomes using the API contract and supports manual rollback flows.

= Does this plugin support automatic app restart after apply? =

Not for WordPress targets. Restart automation currently applies to Python and Node.js connector targets.

== Changelog ==

= 1.44.0 =

* Connector parity updates for rollback/apply payload contracts.
* Improved low-confidence and policy handling notes.
* Stability and diagnostics improvements.

== Upgrade Notice ==

= 1.44.0 =

Recommended update for improved rollback/apply contract alignment and connector stability.
