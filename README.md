# Patcherly Connectors

**Release version:** `1.42.0` (see [`VERSION`](VERSION); keep in sync with `PATCHERLY_CONNECTOR_VERSION` in agents and the WordPress plugin header.)

This folder holds **open-source connector source**: Python, Node.js, and PHP agents, the WordPress plugin, and installers. **Full customer documentation** is in the **[Patcherly Help Center](https://help.patcherly.com/)**, starting with **[Connectors overview](https://help.patcherly.com/connectors/overview/)** and **[Installing a connector](https://help.patcherly.com/getting-started/installing-connector/)**.

## Licensing

| Area | License |
|------|---------|
| Python, Node, PHP agents, universal installers, `web_installer.php`, and other files outside `wp-patcherly/` | [MIT License](LICENSE) (see also [`python/LICENSE`](python/LICENSE), [`nodejs/LICENSE`](nodejs/LICENSE), [`php/LICENSE`](php/LICENSE)) |
| WordPress plugin (`wp-patcherly/`) | [GNU General Public License v2.0 or later](wp-patcherly/LICENSE) (GPL-2.0-or-later) |

Using the **Patcherly service** (accounts, API, support) is governed by our [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use) policy. We provide **official product support** only for **unmodified** connector releases from our official sources.

## Web server snippets (optional)

If backup directories might sit under the web document root, administrators can add **vhost-level** rules so backup URL paths are not served. Canonical examples live **once** in this directory (not duplicated per connector):

- [`.nginx_backup_protection.conf`](.nginx_backup_protection.conf) — Nginx `location` example  
- [`apache_backup_protection.conf.example`](apache_backup_protection.conf.example) — Apache `LocationMatch` example  

Agents also write a **`.htaccess`** inside the backup folder when the server allows it. Customer-oriented explanation: **[Connectors overview](https://help.patcherly.com/connectors/overview/)** on the Help Center.

## Source layout

| Path | Contents |
|------|----------|
| [`python/`](python/) | Python agent |
| [`nodejs/`](nodejs/) | Node.js agent |
| [`php/`](php/) | PHP agent |
| [`wp-patcherly/`](wp-patcherly/) | WordPress plugin |

Installers and shared scripts at this directory’s root support packaging and distribution.

## Install in the fewest steps

Fast path from the dashboard (token expires in **30 minutes**):

1. **Dashboard:** **Targets** → select a target → **Connect** → **Generate install token**.
2. **One command** on the target server (replace `<token>` with the token from the dashboard):

   | Platform | Command |
   |----------|---------|
   | macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/api/public/install.sh \| sudo bash -s -- --token <token>` |
   | Windows PowerShell | `irm "https://api.patcherly.com/api/public/install.ps1" -OutFile install.ps1; .\install.ps1 -Token <token>` |

   The script auto-detects Node.js, Python, or PHP and installs the matching connector.

3. **WordPress:** Install the **Patcherly Connector** plugin (**Plugins → Add New**), set **Server URL**, then sign in with your Patcherly account to sync the agent key.

4. **FTP / file manager only:** From **Connect**, download **web_installer.php**, upload to your server, then open `https://your-site.com/web_installer.php?token=<token>` and follow the prompts.

More detail, CMD install, rollback, and stack-specific guides: **[Installing a connector](https://help.patcherly.com/getting-started/installing-connector/)** on the Help Center.

## After install

- Start the agent (the universal installer can create `start.sh`, or run the agent script directly).
- Optionally run as a service (systemd, Windows Service, or cron for PHP).
- Check **Targets** in the Patcherly dashboard for connector status and health.

## Post-apply app restart (Python / Node targets)

Optional automated shell steps after a successful patch are a **product feature** for eligible plans and **Python** / **Node.js** targets only. **Customer guide:** **[App restart automation](https://help.patcherly.com/features/app-restart/)**.
