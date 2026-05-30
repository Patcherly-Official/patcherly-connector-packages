# Patcherly Connector WordPress Plugin

WordPress integration for Patcherly, the Multi-Tenant AI-Powered Automated Problem Resolution system. This plugin allows WordPress sites to connect to the central Patcherly server, configure agent API keys, send test ingests, and manage error reporting.

## License

This plugin is licensed under the **GNU General Public License v2.0 or later** (GPL-2.0-or-later). See [`LICENSE`](LICENSE) in this directory.

Use of the **Patcherly service** is separate from the license on this code: see [Terms of Service](https://patcherly.com/legal/terms-of-service) and [Acceptable Use](https://patcherly.com/legal/acceptable-use). We provide **official support** only for **unmodified** releases from our official distribution channels.

## Post-apply automated restart

**Not supported for WordPress targets** Automated shell restarts after patches are available only for **Python** and **Node.js** connector targets (see main [connectors README](../README.md) and the Help Center guide **[App restart automation](https://help.patcherly.com/features/app-restart/)**). This plugin continues the normal fix/apply flow without post-apply automation.

## Features

- **Smart Connection System** - Intelligent connection flow with automatic credential synchronization
- **HMAC Signing Support** - Secure API communication with automatic HMAC secret management
- **Agent Key Management** - Automatic agent key synchronization and rotation
- **Error Management** - View, filter, and manage errors from the Patcherly system
- **Real-time Status** - Live connection status with detailed diagnostic information
- **Force Resync** - Manual credential synchronization and connection reset
- **Entitlement-aware guidance** - If workspace plan entitlements do not include advanced analytics, dashboard Metrics/Usage surfaces show upgrade guidance with preview-only data styling

## Installation

**WordPress sites:** This plugin is the recommended way to connect a WordPress target. Upload, activate, and configure the Patcherly Server URL; the agent key syncs via JWT login.

1. Upload the `patcherly` folder to your `/wp-content/plugins/` directory
2. Activate the plugin through the 'Plugins' menu in WordPress
3. Go to 'Patcherly Connector' in the WordPress admin menu to configure

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
- **Database**: PostgreSQL (primary SQL database)
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

## Path lists (operator note)

Connectors receive **`exclude_paths`** (monitoring) from the API; **`patch_exclude_paths`** are **server-side only**. See the repo’s **[`../PATH_LISTS.md`](../PATH_LISTS.md)** and the Help Center **[Path rules for targets](https://help.patcherly.com/getting-started/path-exclusion/)**.

## API contract notes (fixes and approvals)

Server-side rules can return **409** when a fix cannot be promoted automatically:

- **`low_confidence_confirmation_required`** — Confidence is below the workspace (or user) minimum. Human operators finish confirmation in the **dashboard**; REST clients must follow OpenAPI (`acknowledge_low_confidence` on approve/accept) before retrying.
- **Path exclusion gates** — Separate **`exclude_paths`** (monitoring/ingest) from **`patch_exclude_paths`** (analysis/approve/apply). Help Center: [Path rules for targets](../../help/getting-started/path-exclusion.md).

This plugin lists errors and applies approved patches on the server; it does not replace the dashboard **confirmation** UX for low-confidence or policy blocks.

## Developer references

Implementation-level details (API endpoints, WordPress hooks, and AJAX action map) are documented in [`docs/connectors/agents.md`](../../docs/connectors/agents.md).

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

## Plugin updates

For end users: update from the standard WordPress Plugins screen when "Update available" appears.

Release workflow and update-check implementation details for developers/operators are documented in [`docs/connectors/agents.md`](../../docs/connectors/agents.md).

## Support

For support and issues:
1. Check the troubleshooting section above
2. Review WordPress error logs
3. Use Force Resync to resolve credential issues
4. Contact your Patcherly system administrator
