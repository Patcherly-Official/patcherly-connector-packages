# Patcherly Connectors

Connectors monitor your app, send errors to Patcherly, and apply fixes. All connectors (Python, Node, PHP, WordPress) support the same full workflow: ingest → analyze → fix → apply → test results.

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

## After install

- Start the agent (universal installer creates `start.sh`; or run the agent script directly).
- Optionally run as a service (systemd, Windows Service, or cron for PHP).
- Check **Targets** in the dashboard for connector status and health.
