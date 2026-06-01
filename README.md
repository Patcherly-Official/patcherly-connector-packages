<div align="center">

<a href="https://patcherly.com"><img src="https://patcherly.com/assets/img/logo_patcherly_light.png" alt="Patcherly" width="240" /></a>

# Patcherly Connectors

**Auto-detect and fix production errors in your apps.**
Open-source agents that pair with your Patcherly account via OAuth — no API keys to copy or rotate.

[![Latest release](https://img.shields.io/github/v/release/Patcherly-Official/patcherly-connector-packages?label=release&color=10b981&style=flat-square)](https://github.com/Patcherly-Official/patcherly-connector-packages/releases/latest)
[![Discord — join](https://img.shields.io/badge/Discord-join-5865f2?logo=discord&logoColor=white&style=flat-square)](https://discord.gg/7yZkD9KNsS)
[![Docs — help.patcherly.com](https://img.shields.io/badge/docs-help.patcherly.com-10b981?style=flat-square)](https://help.patcherly.com)

</div>

Full customer documentation lives at **[help.patcherly.com](https://help.patcherly.com)** — start with the [Connectors overview](https://help.patcherly.com/connectors/overview/).

---

## What's in this repo

| Path | Stack | Purpose |
|------|-------|---------|
| [`python/`](python/) | ![Python](https://img.shields.io/badge/-Python-3776AB?logo=python&logoColor=white&style=flat-square) | Any framework that logs to a file or stdout |
| [`nodejs/`](nodejs/) | ![Node.js](https://img.shields.io/badge/-Node.js-339933?logo=node.js&logoColor=white&style=flat-square) | Express, Fastify, Next.js, etc. |
| [`php/`](php/) | ![PHP](https://img.shields.io/badge/-PHP-777BB4?logo=php&logoColor=white&style=flat-square) | Standalone Laravel, Symfony, or custom apps |
| [`patcherly/`](patcherly/) | ![WordPress](https://img.shields.io/badge/-WordPress-21759B?logo=wordpress&logoColor=white&style=flat-square) | `Patcherly Connector` plugin |

---

## Quick install — Node / Python / PHP

**One command** installs the agent and immediately launches the OAuth pairing flow:

| Platform | Command |
|----------|---------|
| macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/api/public/install.sh \| sudo bash` |
| Windows PowerShell | `irm "https://api.patcherly.com/api/public/install.ps1" \| iex` |

The CLI prints a **verification URL** and a short **user code** — open the URL in any browser, sign in to your dashboard, pick the website/app (target), and confirm the code. Credentials are saved to `~/.patcherly/credentials.json` (or `/root/.patcherly/` when run as root) and monitoring starts automatically.

> [!TIP]
> The installer auto-detects Node.js → Python → PHP and always installs the latest agent. To force a specific runtime, set `AGENT_TYPE=nodejs` (or `python` / `php`). To downgrade to an older agent, see [Installing an older connector version](https://help.patcherly.com/getting-started/installing-connector/#installing-an-older-connector-version).

### Install paths and overrides

| Env var | Default | Notes |
|---------|---------|-------|
| `INSTALL_DIR` | `/opt/patcherly-connector` (Linux/macOS) · `%USERPROFILE%\patcherly-connector` (Windows) | The Linux default follows the FHS convention for self-contained app packages and matches the auto-generated `patcherly-agent` systemd unit's `WorkingDirectory`. The Windows default is user-scope (no UAC prompts). |
| `SKIP_LOGIN` | unset | Set to `1` to skip the auto-launched pairing flow at the end of install (useful for image-baking, CI, or unattended provisioning). |
| `AGENT_TYPE` | auto-detected | Force `nodejs` / `python` / `php`. |

Example with overrides — env vars must come **after** `sudo`, not before `curl` (sudo strips most env vars from its child by default, so `VAR=value curl ... | sudo bash` would silently ignore them):

```bash
curl -sSL https://api.patcherly.com/api/public/install.sh | \
  sudo INSTALL_DIR=/srv/patcherly AGENT_TYPE=python SKIP_LOGIN=1 bash
```

### Pair later (or re-pair)

If you used `SKIP_LOGIN=1`, or just need a fresh token, run:

| Platform | Command |
|----------|---------|
| macOS / Linux | `sudo /opt/patcherly-connector/start.sh login` |
| Windows PowerShell | `& "$env:USERPROFILE\patcherly-connector\start.ps1" login` |
| Package install (pip / npm) | `patcherly login` |

> [!NOTE]
> On Linux, the `sudo` prefix is only needed when the installer enabled the `patcherly-agent` systemd service — credentials must land in `/root/.patcherly/credentials.json` for the root-run service to read them. The installer also prints the exact command for your install path on success, so check the install output if you used a custom `INSTALL_DIR`.

Per-language guides: **[Node.js](https://help.patcherly.com/connectors/nodejs/)** · **[Python](https://help.patcherly.com/connectors/python/)** · **[PHP](https://help.patcherly.com/connectors/php/)**.

## Quick install — WordPress

In WordPress admin: **Plugins → Add New → search "Patcherly Connector" → Install → Activate**, then click **Pair connector** in the plugin settings.

> [!NOTE]
> The plugin runs the same OAuth Device Authorization Grant flow on your behalf — no API keys to copy or paste.

Plugin internals: [`patcherly/README.md`](patcherly/README.md). User guide: **[WordPress connector](https://help.patcherly.com/connectors/wordpress/)**.

---

## After install

- Connector status, target health, and pending approvals live in **Targets** in your [Patcherly dashboard](https://app.patcherly.com/targets).
- Run the agent as a service (`systemd`, Windows Service, or cron for PHP) — the universal installer can generate a `start.sh` / `start.ps1` wrapper for you.
- Configure path exclusions and patch policies in the dashboard target settings — see [Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/).

---

## Backup-URL protection (web-facing targets)

Every connector auto-writes an `.htaccess` (`Deny from all`) inside its backup directory. That covers Apache with `AllowOverride All`, but is **silently ignored on Nginx** and on Apache with `AllowOverride None`.

If your backup directory could sit under the public document root, copy the ready-to-paste Nginx or Apache vhost snippet from [**Hardening: backup folders and the public web**](https://help.patcherly.com/connectors/overview/#hardening-backup-folders-and-the-public-web) on the help site (full coverage matrix included).

---

## Support & community

- **[help.patcherly.com](https://help.patcherly.com)** — customer documentation, FAQ, troubleshooting.
- **[Discord community](https://discord.gg/7yZkD9KNsS)** — ask questions, share feedback, get help from the team and other users. The founder is active there.
- **[Patcherly dashboard](https://app.patcherly.com)** — paid plans get priority support directly through the dashboard.
- **[Report a bug](https://github.com/Patcherly-Official/patcherly-connector-packages/issues)** — connector source bugs and feature requests on GitHub.

---

## Licensing

| Area | License |
|------|---------|
| Python / Node / PHP agents + everything outside `patcherly/` | [MIT](LICENSE) — see also [`python/LICENSE`](python/LICENSE), [`nodejs/LICENSE`](nodejs/LICENSE), [`php/LICENSE`](php/LICENSE) |
| WordPress plugin (`patcherly/`) | [GPL-2.0-or-later](patcherly/LICENSE) |

Using the **Patcherly service** (accounts, API, official support) is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. We provide official product support only for **unmodified** connector releases from our official sources.
