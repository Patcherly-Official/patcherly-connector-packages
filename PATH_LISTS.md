# Path lists: what connectors know vs what the server enforces

Patcherly uses **three** layers of path rules on every target. Each has a distinct purpose and a different enforcement point:

| Layer | API field / source | Sent to connectors? | Purpose | Editable? |
|-------|-------------------|---------------------|---------|-----------|
| **Monitoring exclusions** | `exclude_paths` (target column) | **Yes** (cached ~5 min) | **Monitoring / noise** — filter before ingest; connectors also **refuse to apply** patches to matching file paths (last-line defense). | All plans |
| **Default patch exclusions** | `DEFAULT_PATCH_EXCLUDE_PATHS` in `server/app/core/path_matcher.py` | **No** (server-only) | **Hard floor** — always excluded from analysis / approve / apply for every target. Protects system paths, connector infrastructure, secrets, VCS dirs, dependency trees, and framework-specific sensitive files. Returned by `GET /api/targets` as `patch_exclude_defaults` (informational). | **Never — not tenant-editable** |
| **Custom patch exclusions** | `patch_exclude_paths` (target column) | **No** (server-only) | **Tenant-configured additions** to the default floor. Additional paths where analysis / approve / apply must not proceed. | Requires **`advanced_fixes`** (Core, Pro). Server returns `402 advanced_fixes_required` on POST/PUT when a non-empty list is submitted without it. |

The **effective patch exclusion list** used at every analysis / approve / apply gate is `DEFAULT_PATCH_EXCLUDE_PATHS (for type) + patch_exclude_paths`. Tenants can never remove entries from the default floor, even if they have the `advanced_fixes` entitlement. On plan downgrade, existing `patch_exclude_paths` remain stored and enforced server-side.

## Log paths

Connectors discover which log files to monitor from `GET /api/targets/{id}/log-paths/connector`. The response now always includes both **preset** and **custom** paths:

| Source | Where defined | Plan gate |
|--------|--------------|-----------|
| `preset_paths` | `PRESET_LOG_PATHS` in `server/app/core/path_matcher.py` (per connector type) | **All plans** — always returned |
| `custom_paths` | `target_log_paths` table (stored by tenant) | **`advanced_error_monitoring`** (Core, Pro) |

**Connectors must not maintain their own fallback log path lists.** All connector code that contained hardcoded fallback arrays (Python, Node.js, PHP) has been removed. The API response is the single source of truth.

## Apply-time behaviour (all first-party agents)

When a fix is applied locally, agents check the **cached `exclude_paths`** (monitoring) list before writing each file:

- **Node** (`node_agent.js`): `isPathExcluded` → `Refusing to apply patch to excluded path`
- **Python** (`python_agent.py`): same pattern
- **PHP** (`php_agent.php`): same pattern  
- **WordPress** (`patcherly.php`): same pattern

Those checks use the **monitoring** list. Server-side patch exclusions (default floor + tenant custom) prevent a disallowed fix from reaching **approved** state in the first place; connectors do not re-implement them.

## Confidence and path gates

Low-confidence and path rules are **primarily enforced by the API** before the connector polls an approved fix. Connectors do not re-implement **`patch_exclude_paths`** or confidence thresholds locally.

## Dashboard display

The **Edit Target** and **Create Target** modals in the dashboard show:

- **Always-excluded patch paths** — the full default list for the target's connector type (collapsible, read-only).
- **Custom patch exclusions** textarea — editable only on Core / Pro.
- **Log Paths modal** → **Preset log paths** section — the server-defined presets for the type (read-only, above the custom paths list).

## Help Center (end users)

Customer-facing copy: **[Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/)** on the Help Center.
