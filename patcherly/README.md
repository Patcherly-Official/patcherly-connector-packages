# Patcherly WordPress Plugin

WordPress integration for Patcherly: monitor and fix bugs & errors on your WordPress / WooCommerce website, safely, automatically, and in real time.

## License

This plugin is licensed under the **GNU General Public License v2.0 or later** (GPL-2.0-or-later). See [`LICENSE`](LICENSE) in this directory.

Use of the **Patcherly service** is separate from the license on this code: see [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use). We provide **official support** only for **unmodified** releases from our official distribution channels.

## Privacy posture

- **No phone-home before pairing.** The plugin makes zero outbound HTTP requests on plugin activation, deactivation, theme switch, or normal page loads. All traffic to Patcherly only starts once you've paired your site.
- **One external host only.** Pairing and post-pairing traffic both go to `api.patcherly.com`.
- **Credentials encrypted at rest.** Your site's authentication credentials are stored encrypted in your WordPress database.
- **Context upload is opt-in.** Information about your WordPress install (active plugins, theme, WooCommerce status) is uploaded only when you click the **Refresh site context** button on the settings page — never automatically.

## Post-apply automated restart

**Not supported for WordPress targets.** Automated shell restarts after a fix are available only for **Python**, **Node.js**, and standalone **PHP** connector targets — see the main [connectors README](../README.md) and the Help Center guide [App restart automation](https://help.patcherly.com/features/app-restart/). This plugin continues the normal fix/apply flow without post-apply automation, because the WordPress plugin directory does not allow plugins to run arbitrary commands on the host server.

## Features

- **One-click pairing** — no API keys to copy or paste.
- **Signed, verified messages** — every call between your site and Patcherly is cryptographically signed and verified.
- **Error management in wp-admin** — view, filter, and act on errors from the Patcherly system without leaving WordPress.
- **Patches with backups** — every patch creates a snapshot of the affected files on your server. Rollback restores them byte-for-byte.
- **Plan-aware UI** — your workspace plan drives which actions are visible (Auto Apply, Auto Analysis, etc.); the plugin mirrors the dashboard's policy.

## Installation

This plugin is the recommended way to connect a WordPress target.

1. Upload the `patcherly` folder to your `/wp-content/plugins/` directory (or install the release ZIP via **Plugins → Add New → Upload Plugin**).
2. Activate **Patcherly** from **Plugins** in wp-admin.
3. Open **Patcherly** in the admin menu (look for the shield icon).
4. Click **Connect with Patcherly** to pair the site with your Patcherly account.

## Configuration

### Connection

- **Patcherly Connection** — pair / disconnect with one click. Status (connected, token expiry) is shown next to the button.
- **Patcherly Server URL (Advanced)** — pre-filled with `https://api.patcherly.com`. Tucked into a collapsed "Advanced" section; only edit this if you self-host Patcherly.

### Operational

- **Errors Cache TTL** — how long to cache the errors list (seconds; `0` disables caching).
- **Cleanup on Uninstall** — when enabled, removes all plugin settings and the `wp-content/uploads/patcherly/` folder (including backups) on delete. Deactivation only removes the Rescue must-use file; settings and backups stay until uninstall or manual deletion.

## How pairing works

1. Click **Connect with Patcherly**. Your browser opens the Patcherly dashboard so you can confirm the pairing with your account.
2. Confirm in the dashboard. The plugin receives a secure credential and stores it (encrypted) in your WordPress database.
3. From that point on, every call between your site and Patcherly is signed.
4. Click **Disconnect** any time to clear the credential and stop all communication with Patcherly.

## Usage

### Error management

The Errors page lets you:

- **View errors** — browse with filtering by status, severity, and language.
- **Bulk operations** — select and delete multiple errors at once.
- **Detailed view** — full error context, stack trace, file snippet, and apply / rollback controls.

### Site-context refresh

Click **Refresh site context** on the Settings page to send your latest WordPress / plugins / theme / WooCommerce / database information to Patcherly. This is the only action that uploads site context, and it only runs when you click the button.

## Fixes and approvals

The plugin lists errors and applies approved patches; it does not replace the dashboard for human review of low-confidence fixes or policy-gated patches:

- **Low-confidence fixes** — if a fix's AI confidence is below your workspace (or user) minimum, the dashboard asks a human to confirm before it can be applied. The plugin shows a clear notice in that case.
- **Path exclusion gates** — your workspace's path rules govern which files are monitored and which can be patched. See [Path rules for targets](../../help/getting-started/path-exclusion.md) in the Help Center.

## Deactivation and uninstall

- **Deactivate** — stops scheduled tasks and removes the Rescue must-use plugin. Settings and `wp-content/uploads/patcherly/` (including backups) stay on disk. Reactivating reinstalls Rescue when the site is still paired.
- **Uninstall** — always removes Rescue and debug-mode data.
- **Uninstall with Cleanup on Uninstall** — also deletes plugin options and the entire `wp-content/uploads/patcherly/` folder.

## Troubleshooting

### "Patcherly API is currently unreachable"

The plugin tried to reach `api.patcherly.com` and got a transport error. Retry in a few minutes, and check your firewall / proxy. Your site must be able to make outbound HTTPS requests to Patcherly.

### "Invalid or expired nonce"

Reload the Patcherly settings page and click **Connect with Patcherly** again. (For security, WordPress automatically rotates the pairing form's security token every 12 hours.)

### Pairing succeeded but later requests fail

Click **Disconnect**, then **Connect with Patcherly** again to refresh your credentials. If the issue persists, contact support.

### HTTPS / TLS issues

If you see "This endpoint requires HTTPS in production mode": make sure your WordPress site is served over HTTPS. If your site sits behind a reverse proxy (nginx, Cloudflare, Render, etc.), make sure that proxy forwards the `X-Forwarded-Proto: https` header upstream. Most managed WordPress hosts handle this for you.

## Security

- **Encrypted credentials.** Your authentication credentials are stored encrypted in your WordPress database — never as plain text. A database-only leak cannot read them.
- **Signed messages.** Every API call between your site and Patcherly is cryptographically signed and verified at the other end. Tampered or replayed messages are rejected automatically.
- **No way to disable signing.** Fix payloads without a valid signature are refused — this protects you from someone trying to push a malicious patch to your site.
- **Revoke any time.** Click **Disconnect** in the plugin settings to invalidate your current credentials.

## Support

- Check the troubleshooting section above.
- Review your WordPress error logs (in your host's control panel).
- Re-pair via **Disconnect** + **Connect with Patcherly** if anything looks off.
- Join the [Patcherly Discord Community](https://discord.gg/7yZkD9KNsS), ask for help, share feedback, or get Priority Support on paid plans through the Patcherly Dashboard.
