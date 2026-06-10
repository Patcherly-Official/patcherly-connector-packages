# Patcherly WordPress Plugin

WordPress integration for Patcherly: monitor and fix bugs & errors on your WordPress / WooCommerce website, safely, automatically & in real time.

## License

This plugin is licensed under the **GNU General Public License v2.0 or later** (GPL-2.0-or-later). See [`LICENSE`](LICENSE) in this directory.

Use of the **Patcherly service** is separate from the license on this code: see [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use). We provide **official support** only for **unmodified** releases from our official distribution channels.

## Privacy posture (v1.49.0+)

- **No phone-home before pairing.** The plugin makes **zero** outbound HTTP requests on `init`, plugin activation, deactivation, or theme switch. All API traffic is gated on the OAuth bundle being present (`patcherly_oauth_is_paired()`).
- **One external host only.** Pairing and post-pairing traffic both go exclusively to `api.patcherly.com` (with `apidev.patcherly.com` as a one-shot fallback during the pairing click when the production host is unreachable).
- **OAuth secrets encrypted at rest.** `access_token`, `refresh_token`, and `hmac_secret` are AEAD-encrypted with libsodium (`pcx1:` envelope, key derived from `wp_salt('secure_auth')` + per-install nonce). Falls back to plaintext storage on hosts that disable libsodium.
- **Context upload is opt-in.** The site-context bundle (active plugins, theme, ACF map, WooCommerce status) is collected and uploaded **only** when the admin clicks the "Refresh site context" button on the settings page.

## Post-apply automated restart

**Not supported for WordPress targets.** Automated shell restarts after patches are available only for **Python** and **Node.js** connector targets (see main [connectors README](../README.md) and the Help Center guide **[App restart automation](https://help.patcherly.com/features/app-restart/)**). This plugin continues the normal fix/apply flow without post-apply automation.

## Features

- **OAuth 2.0 Device Authorization Grant pairing** — no API keys to copy; one-click "Connect with Patcherly" flow.
- **HMAC-signed API communication** — every outbound call carries a signed request with the bundle-provided HMAC secret.
- **Error management** — view, filter, and act on errors from the Patcherly system in wp-admin.
- **Patch apply with pre-apply backups** — restores affected files byte-for-byte on rollback.
- **Entitlement-aware guidance** — workspace plan entitlements drive Auto Apply, Auto Analysis, and dashboard surfaces; the connector mirrors the policy.

## Installation

This plugin is the recommended way to connect a WordPress target.

1. Upload the `patcherly` folder to your `/wp-content/plugins/` directory (or install the release ZIP via **Plugins → Add New → Upload Plugin**).
2. Activate **Patcherly** from **Plugins** in wp-admin.
3. Open **Patcherly** in the admin menu (look for the shield icon).
4. Click **Connect with Patcherly** to pair the site via OAuth Device Authorization.

## Configuration

### Connection

- **Patcherly Connection** — pair / disconnect button driven by the OAuth Device flow. Status (connected / token expiry / scopes) is shown next to it.
- **Patcherly Server URL (Advanced)** — pre-filled with `https://api.patcherly.com` on activation. Tucked into a collapsed "Advanced" section; only edit if you self-host Patcherly. If you customise the URL, no fallback is attempted (you are pinned to your URL).

### Operational

- **Errors Cache TTL** — how long to cache error lists (seconds; `0` disables caching).
- **Cleanup on Uninstall** — whether to delete plugin options when uninstalling.

## OAuth pairing flow

1. Click **Connect with Patcherly**. The plugin calls `POST /api/oauth/device` on the configured server (with a one-shot fallback to `apidev.patcherly.com` if the production host is unreachable and you have not customised the URL).
2. Your browser is redirected to the Patcherly dashboard at [app.patcherly.com](https://app.patcherly.com) to confirm the pairing with your account.
3. The plugin polls `POST /api/oauth/token` until you confirm in the dashboard. On success, the OAuth bundle (`access_token`, `refresh_token`, `hmac_secret`, `target_id`, `tenant_id`) is persisted as encrypted options.
4. From that point on, all connector calls sign requests with the bundle.
5. Click **Disconnect** to clear the bundle and stop all outbound traffic.

## Usage

### Error management

The Errors page lets you:

- **View errors** — browse with filtering by status, severity, language.
- **Bulk operations** — select and delete multiple errors.
- **Detailed view** — full error context, stack trace, file snippet, and apply / rollback controls.

### Site-context refresh

Click **Refresh site context** on the settings page to upload the latest WordPress / plugins / theme / ACF / WooCommerce / database metadata to Patcherly. This is the only action that posts site context to the API and it is admin-driven.

## API contract notes (fixes and approvals)

Server-side rules can return **409** when a fix cannot be promoted automatically:

- **`low_confidence_confirmation_required`** — confidence is below the workspace (or user) minimum. Human operators finish confirmation in the **dashboard**; REST clients must follow OpenAPI (`acknowledge_low_confidence` on approve/accept) before retrying.
- **Path exclusion gates** — separate **`exclude_paths`** (monitoring/ingest) from **`patch_exclude_paths`** (analysis/approve/apply). Help Center: [Path rules for targets](../../help/getting-started/path-exclusion.md).

This plugin lists errors and applies approved patches on the server; it does not replace the dashboard **confirmation** UX for low-confidence or policy blocks.

## Troubleshooting

### "Patcherly API is currently unreachable"

The plugin tried the configured Server URL (default `https://api.patcherly.com`) — and, if you are still on the default, the `apidev.patcherly.com` fallback — and got a transport error from both. Retry in a few minutes; check your firewall/proxy.

### "Invalid or expired nonce"

Reload the Patcherly settings page (the admin nonce rotates every 12 hours) and click **Connect with Patcherly** again.

### Pairing succeeded but later requests fail

Click **Disconnect**, then **Connect with Patcherly** again to refresh the OAuth bundle. If the issue persists, check the OAuth-bundle options under the `patcherly_oauth_*` prefix in `wp_options` — corrupted ciphertext (e.g. after a manual DB restore from a different install) cannot be decrypted and will require re-pairing.

### HTTPS / TLS issues

**Error**: "This endpoint requires HTTPS in production mode" (403)

**Cause**: The API server's TLS enforcement isn't detecting that the original request was over HTTPS. This usually means a reverse proxy in front of FastAPI is terminating TLS and forwarding to the backend over HTTP without setting the standard forwarded-proto header.

**Solution**: Ensure your reverse proxy (nginx / Cloudflare / Render edge / etc.) forwards the `X-Forwarded-Proto: https` header to the FastAPI server.

## Security

### Encrypted secret storage

`access_token`, `refresh_token`, and `hmac_secret` are AEAD-encrypted with `sodium_crypto_secretbox` before they hit `wp_options`. The 32-byte key is derived from `SHA-256( wp_salt('secure_auth') || patcherly_oauth_install_nonce )`. A DB-only compromise that does not also leak `wp-config.php` cannot decrypt the bundle.

If libsodium is unavailable on your host, the plugin gracefully degrades to plaintext storage and the readme.txt note flags it; legacy plaintext bundles also load transparently and are re-encrypted in place on the first call after the host is upgraded to include libsodium.

### HMAC request signing

Every API call is signed with `HMAC-SHA256` over `<METHOD>\n<path>\n<timestamp>\n<body>` and pinned to a 5-minute replay window. Constant-time comparison via `hash_equals()` on the server.

## Support

For support and issues:

1. Check the troubleshooting section above.
2. Review WordPress error logs (the plugin funnels diagnostic output through `patcherly_debug_log()`, gated behind `WP_DEBUG`).
3. Re-pair via **Disconnect** + **Connect with Patcherly** if the OAuth bundle is suspect.
4. Join the [Patcherly Discord Community](https://discord.gg/7yZkD9KNsS), ask for help, share your feedback and insights, or get Priority Support on paid plans through the Patcherly Dashboard.
