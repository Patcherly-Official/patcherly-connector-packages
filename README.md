# Patcherly Connectors

**Release version:** `1.42.0` (see [`VERSION`](VERSION); keep in sync with the main app and with `PATCHERLY_CONNECTOR_VERSION` in Python / Node / PHP agents and the WordPress plugin header).

Connectors perform **target log monitoring** (watching logs/paths on your stack), **error ingestion** to the API, and apply fixes. All connectors (Python, Node, PHP, WordPress) support the same full workflow: ingest → analyze → fix → apply → test results. See [`docs/error_management/ERROR_PIPELINE.md`](../docs/error_management/ERROR_PIPELINE.md) for **target backup** vs **system backup** and terminology.

## Install in the fewest steps

1. **Dashboard:** Open **Targets** → select a target → **Connect** → **Generate install token**.
2. **Run one command** for your platform (token expires in 30 min):

   | Platform | Command |
   |----------|---------|
   | macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/api/public/install.sh \| sudo bash -s -- --token <token>` |
   | Windows PowerShell | `irm "https://api.patcherly.com/api/public/install.ps1" -OutFile install.ps1; .\install.ps1 -Token <token>` |

   The script auto-detects Node.js, Python, or PHP and installs the right connector.

3. **WordPress:** Install the **Patcherly Connector** plugin (Plugins → Add New), set Server URL, then log in with your Patcherly account to sync the agent key.

4. **FTP only:** From Connect, download **web_installer.php**, upload to your server, then visit `https://your-site.com/web_installer.php?token=<token>`.

See [Installing a connector](../help/getting-started/installing-connector.md) and [Agents (run modes)](../docs/connectors/agents.md) for details.

## Connector types

| Connector | Location | Install via |
|-----------|----------|-------------|
| Python | `python/` | Universal installer or manual `pip` + run `python_agent.py` |
| Node | `nodejs/` | Universal installer or manual `npm install` + run `node_agent.js` |
| PHP | `php/` | Universal installer or web installer or manual run `php_agent.php` |
| WordPress | `wp-patcherly/` | Plugin upload + activate; config in WP admin |

## Post-apply app restart (Pro)

Automated **shell steps after a successful patch** (e.g. `systemctl reload`, `pm2 restart`) are supported only for **`targets.type`** **`python`** and **`nodejs`**. **PHP** and **WordPress** connectors do not run this automation (hosting model does not match the v1 contract).

- **User guide:** [help/features/app-restart.md](../help/features/app-restart.md) (dashboard setup, YAML, limits, safety).
- **Developer contract:** [docs/connectors/post-apply-restart.md](../docs/connectors/post-apply-restart.md) (endpoints, telemetry, env vars).
- Configure YAML under **Dashboard → Targets → App restart** (requires **app_restart** entitlement and opt-in).
- The agent calls **`GET /api/targets/{id}/post-apply-config/connector`** (signed response; manifest UTF-8 bytes must match **`content_sha256`**), then runs steps after **`apply_fix`** and before **`POST .../fix/apply-result`**, passing **`post_apply`** telemetry in the apply-result body.
- Optional **`PATCHERLY_POST_APPLY_DRY_RUN=1`**: log-only / no-exec mode (still sends telemetry with `dry_run: true`).
- Optional **`PATCHERLY_WORKFLOW_LOCK_WAIT_SEC`** (Python) / **`PATCHERLY_WORKFLOW_LOCK_WAIT_MS`** (Node): bounded wait for the apply/post-apply/apply-result lock.
- **Node:** run `npm install` in `connectors/nodejs` so the `yaml` package is available for manifest parsing.

## After install

- Start the agent (universal installer creates `start.sh`; or run the agent script directly).
- Optionally run as a service (systemd, Windows Service, or cron for PHP).
- Check **Targets** in the dashboard for connector status and health.
