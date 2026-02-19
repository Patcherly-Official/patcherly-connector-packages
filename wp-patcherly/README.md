# Patcherly Connector WordPress Plugin

WordPress integration for Patcherly, the Multi-Tenant AI-Powered APR (Automated Problem Resolution) System. This plugin allows WordPress sites to connect to the central APR server, configure agent API keys, send test ingests, and manage error reporting.

## Features

- **Smart Connection System** - Intelligent connection flow with automatic credential synchronization
- **HMAC Signing Support** - Secure API communication with automatic HMAC secret management
- **Agent Key Management** - Automatic agent key synchronization and rotation
- **Error Management** - View, filter, and manage errors from the APR system
- **Real-time Status** - Live connection status with detailed diagnostic information
- **Force Resync** - Manual credential synchronization and connection reset

## Installation

**WordPress sites:** This plugin is the recommended way to connect a WordPress target. Upload, activate, and configure the Patcherly Server URL; the agent key syncs via JWT login.

**Alternative: Universal installer** — For non-WordPress targets (PHP, Node, Python), use the dashboard **Connect** flow: generate an install token and run the one-line shell installer or use the web installer (FTP). For WordPress, the plugin remains the recommended path; the dashboard can still generate an install token for any target (plugin users can use JWT login for key sync).

1. Upload the `wp-patcherly` folder to your `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Patcherly Connector' in the WordPress admin menu to configure

**Upgrading from older (APR-named) versions:** Options are migrated once from `apr_*` to `patcherly_*`; your settings are preserved. Old admin URLs (`?page=apr-connector`) redirect to `patcherly-connector`. Backup and queue paths use `patcherly_backups` / `patcherly_queue.jsonl` by default, with fallback to legacy `apr_backups` / `apr_queue.jsonl` if they already exist.

## Configuration

### Basic Setup

1. **Patcherly Server URL**: Enter the URL of Patcherly API server (e.g., default is `https://api.patcherly.com`)
2. **Agent API Key**: This will be automatically synchronized when you log in
3. **HMAC Settings**: Automatically configured based on server settings

### Advanced Settings

- **Errors Cache TTL**: How long to cache error lists (seconds, 0 disables caching)
- **Enable HMAC Signing**: Automatically configured from server
- **HMAC Secret**: Automatically synchronized from server
- **Cleanup on Uninstall**: Whether to delete plugin options when uninstalling

## Smart Connection Flow

The plugin uses an intelligent connection system that automatically handles authentication and credential synchronization:

### Connection Phases

1. **Test Basic Connectivity** → Patcherly server reachable?
   - ✅ **SUCCESS** → Continue to next phase
   - ❌ **FAILURE** → Show "Cannot connect to Patcherly server"

2. **Agent Key Validation** → Agent key exists and configured?
   - ✅ **YES** → Test agent key with HMAC signing
   - ❌ **NO** → Show login form for credential sync

3. **Agent Key Test Result**:
   - ✅ **SUCCESS** → Update cached values, show "Connected"
   - 🔄 **HMAC_MISMATCH** → Auto-sync HMAC secret, retry connection
   - ❌ **INVALID_KEY** → Show login form for re-authentication

4. **JWT Login Flow** (when login required):
   - ✅ **Login Successful** → Sync agent keys → Update plugin options
   - ❌ **Login Failed** → Show error message with details

5. **Agent Key Synchronization**:
   - ✅ **Keys Found** → Update plugin with new credentials
   - ❌ **No Valid Keys** → Show "Contact support" message

### Automatic Features

- **HMAC Secret Sync**: Automatically retrieves and updates HMAC secrets when mismatched
- **Agent Key Rotation**: Supports automatic key rotation with grace periods
- **Credential Caching**: Stores credentials securely in WordPress options
- **Error Recovery**: Intelligent retry logic for temporary connection issues

## Usage

### Connector Status

The status panel shows real-time information about:
- **API**: Server reachability status
- **Deployment**: Docker or server deployment type
- **Database**: Database type (MySQL/PostgreSQL)
- **Agent Key**: Key validity and active status
- **Tenant**: Associated tenant information
- **Target**: Target website information

### Force Resync

Use the "Force Resync" button to:
- Clear all cached credentials
- Re-establish connection with Patcherly server
- Sync latest agent keys and HMAC secrets
- Resolve connection issues

### Error Management

The Errors page allows you to:
- **View Errors**: Browse errors with filtering by status, severity, language
- **Bulk Operations**: Select and delete multiple errors
- **Real-time Updates**: Automatic refresh with configurable caching
- **Detailed Information**: View full error details and metadata

## Troubleshooting

### Connection Issues

1. **"API server unavailable"**
   - Check that Patcherly server URL is correct
   - Verify server is running and accessible
   - Check firewall/network connectivity

2. **"HMAC signature mismatch"**
   - Click "Force Resync" to update HMAC secret
   - Verify HMAC is enabled on both server and plugin

3. **"Agent key is invalid"**
   - Use the login form to re-authenticate
   - Contact administrator if no valid keys exist

4. **"Login failed"**
   - Verify username and password are correct
   - Check user has appropriate permissions
   - Ensure user has access to targets

### Common Solutions

- **Force Resync**: Resolves most credential and connection issues
- **Clear Cache**: Disable errors cache TTL temporarily for testing
- **Check Logs**: Review WordPress error logs for detailed information
- **Server Status**: Verify Patcherly server health via `/api/health/summary`

### HTTPS/TLS Issues

**Error**: "This endpoint requires HTTPS in production mode" (403)

**Cause**: The API server's TLS enforcement isn't detecting that the original request was over HTTPS. This typically happens in proxy deployments where the proxy communicates with the backend over HTTP.

**Solution**: Ensure the proxy forwards the `X-Forwarded-Proto: https` header. The api_proxy.php has been updated (v0.4.0) to automatically detect and forward this header. If you're using a custom proxy setup, ensure it sets:
```
X-Forwarded-Proto: https
```

**Verification**: Check that your WordPress site is running over HTTPS (URL starts with `https://`). The plugin will automatically detect this and forward the appropriate headers.

## Security

### HMAC Signing

The plugin supports HMAC signing for secure API communication:
- Automatic secret synchronization from server
- Configurable enable/disable via server settings
- SHA-256 signature algorithm with timestamp validation
- Automatic retry with updated secrets

### Agent Key Security

- Keys are stored securely in WordPress options
- Support for key rotation with grace periods
- Automatic key validation and synchronization
- Secure JWT-based authentication for key retrieval

## API Endpoints Used

The plugin communicates with these APR server endpoints:

- `/api/health/summary` - Basic connectivity test
- `/api/targets/connector-status` - Detailed connection status
- `/api/targets/hmac-config` - HMAC configuration sync
- `/api/targets/agent-key-config` - Agent key configuration sync
- `/api/auth/login` - JWT authentication
- `/api/targets` - Target information
- `/api/agent-keys` - Agent key management
- `/api/errors` - Error management

## Development

### File Structure

```
wp-patcherly/
├── wp-patcherly.php          # Main plugin file
├── assets/
│   ├── css/
│   │   └── patcherly-connector.css  # Plugin styles
│   └── js/
│       ├── patcherly-status.js   # Status display logic
│       ├── patcherly-settings.js # Settings page logic
│       └── patcherly-errors.js   # Error management logic
└── README.md                  # This file
```

### Hooks and Filters

The plugin provides WordPress hooks for customization:
- `patcherly_connector_activate` - Plugin activation (backup dir protection)
- `patcherly_connector_deactivate` - Plugin deactivation
- `patcherly_connector_uninstall` - Plugin uninstall
- `patcherly_connector_flush_error_transients` - Cache management

### AJAX Actions

Available AJAX endpoints:
- `patcherly_smart_connect` - Smart connection flow
- `patcherly_force_resync` - Force credential resync
- `patcherly_jwt_login` - JWT authentication
- `patcherly_connector_status` - Connection status
- `patcherly_test_connection` - Test server connectivity
- `patcherly_send_sample` - Send sample error for testing
- `patcherly_errors_list` - Error listing
- `patcherly_flush_errors_cache` - Cache management
- `patcherly_hmac_status` - HMAC configuration status

## Changelog

### Version 0.4.1
- Fixed "Send Sample Error" feature - now uses proper AJAX handler
- Fixed endpoint construction for error ingestion (now uses build_api_endpoint)
- Improved error handling and response formatting for sample error submission
- Added tenant_id and target_id to sample error payload when available

### Version 0.4.0
- Fixed HTTPS detection for HMAC/agent key endpoints in proxy deployments
- Fixed endpoint URL construction for auto-update functions (now uses build_api_endpoint)
- Enhanced api_proxy.php to properly forward X-Forwarded-Proto header
- Improved TLS enforcement compatibility with shared hosting environments
- Better support for automatic credential synchronization over HTTPS

### Version 0.3.0
- Added smart connection system
- Implemented automatic HMAC secret synchronization
- Added JWT login flow for agent key sync
- Added Force Resync functionality
- Improved error handling and user feedback
- Enhanced security with proper credential management

### Version 0.2.0
- Added HMAC signing support
- Improved error caching
- Enhanced status display
- Added bulk error operations

### Version 0.1.0
- Initial release
- Basic Patcherly server connectivity
- Agent key configuration
- Error viewing and management

## Releasing updates (developers)

Update logic lives in `update-checker.php` (separate from main plugin logic). It fetches `wp-patcherly-update.json` from GitHub and shows "Update available" when the remote version is newer.

**Repo constant:** To point at a different GitHub repo, define `PATCHERLY_UPDATE_REPO` in `wp-config.php` before the plugin loads, e.g. `define('PATCHERLY_UPDATE_REPO', 'owner/repo');`. Default is `Patcherly-Official/patcherly-connector-packages`. The update JSON and zip URLs are derived from this (e.g. `.../releases/download/connector-packages/wp-patcherly-update.json` and `.../wp-patcherly.zip`).

Sites with the plugin check for updates from the `release/latest` branch. To release an update:

1. **Bump the plugin version** in `wp-patcherly.php`: edit only the plugin header at the top of the file (single source for version and compatibility):
   - `Version:` (e.g. `* Version: 0.5.1`)
   - Optionally `Requires at least:` and `Tested up to:` for WordPress compatibility.
2. Push to a release branch (e.g. `release/1.36.0`). The [update-release-latest](https://github.com/Jany-M/ai-web-assistant/blob/main/.github/workflows/update-release-latest.yml) workflow will:
   - Update `release/latest` to point to that branch.
   - Build `connector-packages/wp-patcherly.zip` and `connector-packages/wp-patcherly-update.json` (with version and download URL).
   - Commit them to `release/latest`.

Sites fetch the update JSON (cached for 12 hours). When the remote version is greater than the installed version, WordPress shows "Update available" and users can update from the Plugins screen. To force an immediate check, users can clear the cache or wait for the next automatic check.

## Support

For support and issues:
1. Check the troubleshooting section above
2. Review WordPress error logs
3. Use Force Resync to resolve credential issues
4. Contact your Patcherly system administrator

## License

This plugin is part of the Patcherly system and follows the same licensing terms as the main application.
