<div align="center">

<a href="https://patcherly.com"><img src="https://patcherly.com/assets/img/logo_patcherly_light.png" alt="Patcherly" width="280" /></a>


**Catch production errors early. Understand them fast. Ship fixes with confidence.**

Official connectors that pair with your Patcherly account: from **bug detection → AI custom fix → your approval → safe patching on your server** — with auto-backups, testing and rollback all included.

**For a limited time**, new accounts include a **30-day trial** of the full **Pro** plan — **no credit card required**. Cancel anytime. [Sign up](https://patcherly.com) · [Pricing](https://patcherly.com/pricing) · [Trial help](https://help.patcherly.com/billing/trial/).


[![Patcherly](https://img.shields.io/badge/Patcherly-2.6.0-10b981?style=flat-square)](https://patcherly.com)

[![npm @patcherly/nodejs-connector](https://img.shields.io/npm/v/@patcherly/nodejs-connector?label=Node.js&logo=npm&style=flat-square)](https://www.npmjs.com/package/@patcherly/nodejs-connector)
[![PyPI patcherly-connector](https://img.shields.io/pypi/v/patcherly-connector?label=Python&logo=pypi&logoColor=white&style=flat-square)](https://pypi.org/project/patcherly-connector/)
[![Packagist patcherly/php-connector](https://img.shields.io/packagist/v/patcherly/php-connector?label=PHP&logo=packagist&logoColor=white&style=flat-square)](https://packagist.org/packages/patcherly/php-connector)
[![WordPress Patcherly Connector](https://img.shields.io/wordpress/plugin/v/patcherly?label=WordPress&logo=wordpress&logoColor=white&style=flat-square)](https://wordpress.org/plugins/patcherly/)

### Development & Support

[![Docs](https://img.shields.io/badge/docs.patcherly.com-333333?style=flat-square)](https://docs.patcherly.com)
[![Help](https://img.shields.io/badge/help.patcherly.com-1869f5?style=flat-square)](https://help.patcherly.com)
[![Discord](https://img.shields.io/badge/Discord-join-5865f2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/7yZkD9KNsS)
[![Donate](https://img.shields.io/github/sponsors/Patcherly-Official?label=Sponsors&logo=GitHub)](https://github.com/sponsors/Patcherly-Official)

> **Per-connector versions:** each stack bumps independently on release. Prefer `@latest` / unpinned registry installs for your stack, or pin from [GitHub Releases](https://github.com/Patcherly-Official/patcherly-connector-packages/releases/latest).

</div>

---

## What's in this repo

| Path | Stack | Purpose | Docs |
|------|-------|---------|------|
| [`python/`](python/) | ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white&style=flat-square) | Any framework that logs to a file or stdout | [Install guide](https://help.patcherly.com/connectors/python/) |
| [`nodejs/`](nodejs/) | ![Node.js](https://img.shields.io/badge/-Node.js-339933?logo=node.js&logoColor=white&style=flat-square) | Express, Fastify, Next.js, etc. | [Install guide](https://help.patcherly.com/connectors/nodejs/) |
| [`php/`](php/) | ![PHP](https://img.shields.io/badge/-PHP-777BB4?logo=php&logoColor=white&style=flat-square) | Standalone Laravel, Symfony, or custom apps | [Install guide](https://help.patcherly.com/connectors/php/) |
| [`patcherly/`](patcherly/) | ![WordPress](https://img.shields.io/badge/-WordPress-21759B?logo=wordpress&logoColor=white&style=flat-square) | WordPress plugin | [Install guide](https://help.patcherly.com/connectors/wordpress/) |

---

## Quick install — Node / Python / PHP

**One command** installs the agent and launches the OAuth pairing flow:

| Platform | Command |
|----------|---------|
| macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/install \| sudo bash` |
| Windows PowerShell | `irm "https://api.patcherly.com/install.ps1" \| iex` |

The CLI prints a **verification URL** and a short **user code** — open the URL in any browser, sign in to your dashboard, pick the website/app (site), and confirm the code. Credentials are saved to `~/.patcherly/credentials.json` (or `/root/.patcherly/` when run as root). Then start the agent (on Linux with systemd: `systemctl start patcherly-connector`; otherwise run `start.sh` / `start.ps1` from your install directory) — see [After install](#after-install).

> [!TIP]
> The installer auto-detects Node.js → Python → PHP and always installs the latest connector. To force a specific runtime, set `CONNECTOR_TYPE=nodejs` (or `python` / `php`). To downgrade to an older connector, see [Installing an older connector version](https://help.patcherly.com/getting-started/installing-connector/#installing-an-older-connector-version). Prefer package managers instead? Use [npm](https://www.npmjs.com/package/@patcherly/nodejs-connector), [PyPI](https://pypi.org/project/patcherly-connector/), or [Packagist](https://packagist.org/packages/patcherly/php-connector), then run `patcherly login`.

### Install paths and overrides

| Env var | Default | Notes |
|---------|---------|-------|
| `INSTALL_DIR` | `/opt/patcherly-connector` (Linux/macOS) · `%USERPROFILE%\patcherly-connector` (Windows) | The Linux default follows the FHS convention for self-contained app packages and matches the auto-generated `patcherly-connector` systemd unit's `WorkingDirectory`. The Windows default is user-scope (no UAC prompts). |
| `SKIP_LOGIN` | unset | Set to `1` to skip the auto-launched pairing flow at the end of install (useful for image-baking, CI, or unattended provisioning). |
| `CONNECTOR_TYPE` | auto-detected | Force `nodejs` / `python` / `php`. (`AGENT_TYPE` accepted as legacy alias.) |

Example with overrides — env vars must come **after** `sudo`, not before `curl` (sudo strips most env vars from its child by default, so `VAR=value curl ... | sudo bash` would silently ignore them):

```bash
curl -sSL https://api.patcherly.com/install | \
  sudo INSTALL_DIR=/srv/patcherly CONNECTOR_TYPE=python SKIP_LOGIN=1 bash
```

### Pair later (or re-pair)

If you used `SKIP_LOGIN=1`, or just need a fresh token, run:

| Platform | Command |
|----------|---------|
| macOS / Linux | `sudo /opt/patcherly-connector/start.sh login` |
| Windows PowerShell | `& "$env:USERPROFILE\patcherly-connector\start.ps1" login` |
| Package install (npm / pip / composer) | `patcherly login` |

> [!NOTE]
> On Linux, the `sudo` prefix is only needed when the installer enabled the `patcherly-connector` systemd service — credentials must land in `/root/.patcherly/credentials.json` for the root-run service to read them. The installer also prints the exact command for your install path on success, so check the install output if you used a custom `INSTALL_DIR`.

Per-language guides: **[Node.js](https://help.patcherly.com/connectors/nodejs/)** · **[Python](https://help.patcherly.com/connectors/python/)** · **[PHP](https://help.patcherly.com/connectors/php/)**. Full overview: **[Connectors overview](https://help.patcherly.com/connectors/overview/)**.

## Quick install — WordPress

In WordPress admin: **Plugins → Add New → search "Patcherly Connector" → Install → Activate**, then click **Pair connector** in the plugin settings.

> [!NOTE]
> The plugin runs the same OAuth Device Authorization Grant flow on your behalf — no API keys to copy or paste.

Customer guide: **[WordPress connector](https://help.patcherly.com/connectors/wordpress/)**.

---

## After install

- Connector status, site health, and pending approvals live in **Sites** in your [Patcherly dashboard](https://app.patcherly.com/targets).
- Start the agent and keep it running — on Linux the universal installer enables a `patcherly-connector` systemd unit (`systemctl start patcherly-connector`); on Windows run `start.ps1` (and keep that process running); PHP can also use cron. Details: [Installing a connector](https://help.patcherly.com/getting-started/installing-connector/) and your stack's install guide. The installer writes `start.sh` / `start.ps1` for pairing and startup.
- Configure path exclusions and patch policies in the dashboard site settings — see [Path rules for sites](https://help.patcherly.com/getting-started/path-exclusion/).

---

## Backup-URL protection (web-facing sites)

Every connector auto-writes an `.htaccess` (`Deny from all`) inside its backup directory. That covers Apache with `AllowOverride All`, but is **silently ignored on Nginx** and on Apache with `AllowOverride None`.

If your backup directory could sit under the public document root, copy the ready-to-paste Nginx or Apache vhost snippet from [**Hardening: backup folders and the public web**](https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web) on the help site (full coverage matrix included).

---

## Security

Connectors pair via **OAuth** (no API keys to copy into config) and sign traffic with a **per-token HMAC secret**. Fix payloads are **signature-verified before apply**; suspicious AI output can be quarantined. Built-in log redaction runs before ingest; you can add **custom sanitizer patterns** per site.

Documentation quick links:

- [Connectors overview](https://help.patcherly.com/connectors/overview/) — OAuth, HMAC, capability matrix, automatic redaction
- [Prompt injection protection](https://help.patcherly.com/security/prompt-injection-protection/)
- [Custom sanitizer patterns](https://help.patcherly.com/security/custom-sanitizer-patterns/)
- [Post-apply restart safety](https://help.patcherly.com/security/post-apply-restart-safety/) — app restart / shell steps (Python, Node, PHP)

Per-stack guides: **[Node.js](https://help.patcherly.com/connectors/nodejs/)** · **[Python](https://help.patcherly.com/connectors/python/)** · **[PHP](https://help.patcherly.com/connectors/php/)** · **[WordPress](https://help.patcherly.com/connectors/wordpress/)**.

---

## Support & community

- **[help.patcherly.com](https://help.patcherly.com)** — documentation, FAQ, troubleshooting.
- **[Discord community](https://discord.gg/7yZkD9KNsS)** — ask questions, share feedback, get help from the team and other users. The founder is active there.
- **[Patcherly dashboard](https://app.patcherly.com)** — paid plans get priority support through dedicated ticketing.
- **[Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)** — connector source bugs and feature requests on GitHub.

---

## Licensing

| Area | License |
|------|---------|
| Python / Node / PHP agents + everything outside `patcherly/` | [Proprietary limited-use](LICENSE) — see also [`python/LICENSE`](python/LICENSE), [`nodejs/LICENSE`](nodejs/LICENSE), [`php/LICENSE`](php/LICENSE) |
| WordPress plugin (`patcherly/`) | [GPL-2.0-or-later](patcherly/LICENSE) (required by WordPress.org) |

**Patcherly** is a registered trademark, property of Shambix.

Using the **Patcherly service** (accounts, API, official support) is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. We provide official product support only for **unmodified** connector releases from our official sources.
