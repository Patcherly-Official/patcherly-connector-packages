# Patcherly Connectors

**Release version:** `1.47.1` (kept in sync with `PATCHERLY_CONNECTOR_VERSION` in agents and the WordPress plugin header by the `setup/git-hooks/bump_version_from_branch.py` pre-commit hook and the release-publish workflow.)

This folder holds **open-source connector source**: Python, Node.js, and PHP agents, the WordPress plugin, and installers. **Full customer documentation** is in the **[Patcherly Help Center](https://help.patcherly.com/)**, starting with **[Connectors overview](https://help.patcherly.com/connectors/overview/)** and **[Installing a connector](https://help.patcherly.com/getting-started/installing-connector/)**.

## Licensing

| Area | License |
|------|---------|
| Python, Node, PHP agents, universal installers, and other files outside `patcherly/` | [MIT License](LICENSE) (see also [`python/LICENSE`](python/LICENSE), [`nodejs/LICENSE`](nodejs/LICENSE), [`php/LICENSE`](php/LICENSE)) |
| WordPress plugin (`patcherly/`) | [GNU General Public License v2.0 or later](patcherly/LICENSE) (GPL-2.0-or-later) |

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
| [`patcherly/`](patcherly/) | WordPress plugin |

Installers and shared scripts at this directory’s root support packaging and distribution.

## Path lists (`exclude_paths` vs `patch_exclude_paths`)

Connectors cache and enforce **`exclude_paths`** (monitoring / ingest + **apply-time refusal**). **`patch_exclude_paths`** exist only on the Patcherly server for analysis/approve gates. Full matrix: **[PATH_LISTS.md](PATH_LISTS.md)**. Help Center: **[Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/)**.

## Install in the fewest steps

Connectors authenticate via **OAuth 2.0 Device Authorization Grant** (RFC 8628). The flow is identical across runtimes: install the connector, then run the bundled `patcherly login` command to pair it with a target. The dashboard prompts you with a short user code; once you approve it, the connector receives an access token + refresh token + per-token HMAC signing secret.

1. **Install** the connector on the target server:

   | Platform | Command |
   |----------|---------|
   | macOS / Linux / WSL | `curl -sSL https://api.patcherly.com/api/public/install.sh \| sudo bash` |
   | Windows PowerShell | `irm "https://api.patcherly.com/api/public/install.ps1" \| iex` |

   The script auto-detects Node.js, Python, or PHP and installs the matching connector.

2. **Pair** the connector with a target:

   ```
   cd /opt/patcherly-connector && ./start.sh login
   ```

   The CLI prints a `verification_uri` + `user_code`. Open the URL in any browser, sign in to your Patcherly dashboard, pick the target, and confirm the code. The connector saves its credentials to `~/.patcherly/credentials.json` and you're done.

3. **WordPress:** Install the **Patcherly Connector** plugin (**Plugins → Add New**), then click **Pair connector** in the plugin settings — the plugin runs the same OAuth flow on your behalf.

More detail, CMD install, rollback, and stack-specific guides: **[Installing a connector](https://help.patcherly.com/getting-started/installing-connector/)** on the Help Center.

## After install

- Start the agent (the universal installer can create `start.sh` / `start.ps1`, or run the agent script directly).
- Optionally run as a service (systemd, Windows Service, or cron for PHP).
- Check **Targets** in the Patcherly dashboard for connector status and health.

## Post-apply app restart (Python / Node targets)

Optional automated shell steps after a successful patch are a **product feature** for eligible plans and **Python** / **Node.js** targets only. **Customer guide:** **[App restart automation](https://help.patcherly.com/features/app-restart/)**.

## Connector parity baseline (runtime internals)

To reduce drift across Node/PHP/patcherly implementations, connector internals are converging on canonical method names while keeping backward-compatible aliases.

- Preferred internal method naming: `collectAll`, `saveContext`, `loadContext`, `hasChanged`
- Backup manager naming: `createBackup`, `restoreBackup`, `listBackups`
- Existing snake_case names remain supported during transition to avoid breaking older call paths.

> Connector pre-apply backups are intentionally **customer-managed** with **indefinite retention**. Connectors do **not** ship a `cleanupOldBackups` helper — that retention model belongs to the Patcherly application's own database-backup workflow (`server/app/services/db_backup.py`), governed by the superadmin-only `backup_retention_days` / `db_backup_retention_days` settings. Do not reintroduce a cleanup helper on the connector side without confirming the requirement with product first.

## Path-boundary hardening defaults

Connector backup/restore/queue flows now enforce a root-boundary policy before touching filesystem paths:

- Default allowed root: connector process working directory
- Optional overrides: `PATCHERLY_TARGET_ROOTS`
- Multi-root format: OS path separator delimited (`:` on Linux/macOS, `;` on Windows)

Any backup/restore/queue path outside the allowed roots is rejected (or skipped for backup collection) to reduce traversal risk.

Patch application follows the same root-boundary policy (`PATCHERLY_TARGET_ROOTS`). Agents also **refuse to apply** hunks targeting paths that match the cached **monitoring** `exclude_paths` list (Python, Node, PHP, WordPress). That is **not** the same as **`patch_exclude_paths`**, which is evaluated only on the server—see **[PATH_LISTS.md](PATH_LISTS.md)**.

Post-apply command execution hardening now defaults to argv-based execution in Python connectors and rejects shell metacharacter command chains from remote manifests.

## Workflow and paid-feature alignment matrix

The connectors are aligned on the same core server workflow contract while keeping platform-specific execution models.

| Capability | Python | Node.js | PHP | WordPress (`patcherly`) |
|---|---|---|---|---|
| Error ingest (`/api/errors/ingest`) | ✅ | ✅ | ✅ | ✅ |
| Analyze + fetch fix (`/analyze`, `/fix`) | ✅ | ✅ | ✅ | ✅ |
| HMAC-verified fix response | ✅ | ✅ | ✅ | ✅ |
| Apply + rollback backups | ✅ | ✅ | ✅ | ✅ |
| Apply result (`/fix/apply-result`) | ✅ | ✅ | ✅ | ✅ |
| Agent testing report (`/test/results`, 402-aware) | ✅ | ✅ | ✅ | ✅ |
| Exclude-path filtering | ✅ | ✅ | ✅ | ✅ |
| Context upload (`/api/context/upload`) | ✅ | ✅ | ✅ | ✅ |
| Connector status + key/hmac sync | ✅ | ✅ | ✅ | ✅ |
| Local queue + drain/retry | ✅ | ✅ | ✅ | ✅ |
| Post-apply app restart automation (paid) | ✅ | ✅ | ❌ (not applicable) | ❌ (not applicable) |
| Continuous log monitor daemon | ✅ | ✅ | ✅ | ❌ (plugin/admin-triggered flow) |

Notes:
- PHP and WordPress intentionally do not run post-apply shell restart automation.
- WordPress intentionally uses plugin lifecycle/admin/AJAX orchestration instead of a standalone daemon process.
- **Two path lists on each target:** **monitoring exclusions** (`exclude_paths`, shipped to connectors for filtering) vs **patch exclusions** (`patch_exclude_paths`, enforced server-side for analysis/approve/apply). End-user copy: Help Center **[Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/)**.
- **Low-confidence fixes:** Human confirmation for approve/accept is **dashboard-first**. Connectors poll/apply already-approved work; if your automation hits policy blocks, resolve them in the app—see [`patcherly/README.md`](patcherly/README.md) notes for operators.
