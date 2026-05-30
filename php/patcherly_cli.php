<?php
/**
 * `patcherly` CLI — PHP connector OAuth onboarding (Phase-4).
 *
 * Subcommands:
 *   login        Run the device-authorization flow and save the token bundle.
 *   logout       Revoke the current token and delete the local credential file.
 *   status       Print tenant/target/scope/expiry of the current token.
 *   refresh      Force a refresh-token rotation.
 *
 * Configuration:
 *   --api-base / PATCHERLY_API_BASE   (default: https://api.patcherly.com)
 *   --client-id / PATCHERLY_CLIENT_ID (default: patcherly-connector-php)
 *
 * Run: `php patcherly_cli.php login`
 */

declare(strict_types=1);

require_once __DIR__ . '/credential_store.php';
require_once __DIR__ . '/oauth_client.php';

if (PHP_SAPI !== 'cli') {
    fwrite(STDERR, "patcherly_cli.php is meant to be run from the command line.\n");
    exit(1);
}

function patcherly_cli_parse_args(array $argv): array
{
    $cmd = 'help';
    $opts = [
        'api-base'  => getenv('PATCHERLY_API_BASE') ?: 'https://api.patcherly.com',
        'client-id' => getenv('PATCHERLY_CLIENT_ID') ?: 'patcherly-connector-php',
        'json'      => false,
    ];
    for ($i = 1; $i < count($argv); $i++) {
        $a = $argv[$i];
        if (strpos($a, '--') === 0) {
            $eq = strpos($a, '=');
            if ($eq !== false) {
                $key = substr($a, 2, $eq - 2);
                $val = substr($a, $eq + 1);
                $opts[$key] = $val;
            } else {
                $key = substr($a, 2);
                if (isset($argv[$i + 1]) && strpos($argv[$i + 1], '--') !== 0) {
                    $opts[$key] = $argv[++$i];
                } else {
                    $opts[$key] = true;
                }
            }
        } elseif (in_array($a, ['login', 'logout', 'status', 'refresh', 'help'], true)) {
            $cmd = $a;
        }
    }
    $opts['cmd'] = $cmd;
    return $opts;
}

function patcherly_cli_login(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    fwrite(STDERR, "Requesting device code from {$opts['api-base']} ...\n");
    $dc = patcherly_oauth_request_device_code($opts['api-base'], $opts['client-id']);
    if ($opts['json']) {
        fwrite(STDOUT, json_encode($dc, JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(
            STDERR,
            "\nOpen this URL in your browser:\n  {$dc['verification_uri_complete']}\n\n" .
            "or visit {$dc['verification_uri']} and enter:\n  {$dc['user_code']}\n\n" .
            "Waiting for approval (this code expires in {$dc['expires_in']}s) ...\n"
        );
    }
    $bundle = patcherly_oauth_poll_for_token(
        $opts['api-base'],
        $opts['client-id'],
        $dc['device_code'],
        (int) ($dc['interval'] ?? 5),
        (int) ($dc['expires_in'] ?? 900)
    );
    $store->save($bundle);
    if ($opts['json']) {
        $safe = $bundle;
        $safe['access_token'] = '<redacted>';
        $safe['refresh_token'] = isset($bundle['refresh_token']) ? '<redacted>' : null;
        $safe['hmac_secret'] = '<redacted>';
        fwrite(STDOUT, json_encode($safe, JSON_PRETTY_PRINT) . "\n");
    } else {
        fwrite(
            STDERR,
            "\nLogin successful. Bound to target_id=" . ($bundle['target_id'] ?? 'unknown') .
            " tenant_id=" . ($bundle['tenant_id'] ?? 'unknown') . "\n" .
            'Credentials saved to ' . $store->getFilePath() . "\n"
        );
    }
}

function patcherly_cli_logout(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $creds = $store->load();
    if ($creds !== null && (!empty($creds['access_token']) || !empty($creds['refresh_token']))) {
        try {
            patcherly_oauth_revoke_token(
                $opts['api-base'],
                $opts['client-id'],
                (string) ($creds['refresh_token'] ?? $creds['access_token'])
            );
        } catch (Throwable $e) {
            fwrite(STDERR, 'Warning: revoke failed: ' . $e->getMessage() . "\n");
        }
    }
    $store->clear();
    fwrite(STDERR, "Logged out. Local credentials cleared.\n");
}

function patcherly_cli_status(): void
{
    $store = new PatcherlyCredentialStore();
    $creds = $store->load();
    if ($creds === null) {
        fwrite(STDERR, "Not logged in. Run `patcherly login` first.\n");
        exit(2);
    }
    $out = [
        'target_id'         => $creds['target_id'] ?? null,
        'tenant_id'         => $creds['tenant_id'] ?? null,
        'scope'             => $creds['scope'] ?? null,
        'expires_at'        => $creds['expires_at'] ?? null,
        'expired'           => $store->isExpired($creds, 0),
        'has_refresh_token' => !empty($creds['refresh_token']),
        'file'              => $store->getFilePath(),
    ];
    fwrite(STDOUT, json_encode($out, JSON_PRETTY_PRINT) . "\n");
}

function patcherly_cli_refresh(array $opts): void
{
    $store = new PatcherlyCredentialStore();
    $fresh = patcherly_oauth_ensure_fresh_token($opts['api-base'], $opts['client-id'], $store);
    fwrite(STDERR, "Refreshed. Now valid until " . ($fresh['expires_at'] ?? 'unknown') . "\n");
}

$opts = patcherly_cli_parse_args($argv);
try {
    switch ($opts['cmd']) {
        case 'login':
            patcherly_cli_login($opts);
            break;
        case 'logout':
            patcherly_cli_logout($opts);
            break;
        case 'status':
            patcherly_cli_status();
            break;
        case 'refresh':
            patcherly_cli_refresh($opts);
            break;
        case 'help':
        default:
            fwrite(STDOUT, "Usage: php patcherly_cli.php <login|logout|status|refresh> [--api-base URL] [--client-id ID] [--json]\n");
    }
} catch (Throwable $e) {
    fwrite(STDERR, "patcherly: " . $e->getMessage() . "\n");
    exit(1);
}
