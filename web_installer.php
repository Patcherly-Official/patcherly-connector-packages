<?php
/**
 * Patcherly Web Installer (Plan B)
 * Usage: Upload this file to your server and visit it in a browser.
 * Token-based: https://your-site.com/web_installer.php?token=YOUR_TOKEN
 * Key-based:   https://your-site.com/web_installer.php?api_key=YOUR_KEY
 */

$apiBase = getenv('PATCHERLY_API_BASE') ?: 'https://api.patcherly.com';
$apiBase = rtrim($apiBase, '/');
$installDir = __DIR__ . '/patcherly-connector';
$token = isset($_GET['token']) ? trim((string) $_GET['token']) : '';
$apiKey = isset($_GET['api_key']) ? trim((string) $_GET['api_key']) : '';
$serverUrl = $apiBase;

if ($token !== '') {
    $redeemUrl = $apiBase . '/api/public/install/redeem?token=' . urlencode($token);
    $ch = curl_init($redeemUrl);
    if ($ch === false) {
        $tokenError = 'cURL init failed';
    } else {
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_HTTPHEADER => ['Accept: application/json'],
        ]);
        $resp = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($code === 200 && $resp !== false) {
            $data = json_decode($resp, true);
            if (isset($data['agent_api_key'], $data['api_base_url'])) {
                $apiKey = $data['agent_api_key'];
                $serverUrl = rtrim($data['api_base_url'], '/');
            } else {
                $tokenError = 'Invalid redeem response';
            }
        } else {
            $tokenError = 'Token expired or already used';
        }
    }
}

function log_msg($msg, $type = 'INFO') {
    $color = $type === 'ERROR' ? 'red' : ($type === 'SUCCESS' ? 'green' : '#333');
    echo '<div style="color:' . $color . '; margin-bottom: 5px;"><strong>[' . htmlspecialchars($type) . ']</strong> ' . htmlspecialchars($msg) . '</div>';
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Patcherly Connector Installer</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px; line-height: 1.6; }
        .card { background: #f9f9f9; padding: 20px; border-radius: 8px; border: 1px solid #ddd; }
        code { background: #eee; padding: 2px 6px; border-radius: 3px; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; font-size: 1rem; }
        .btn:hover { background: #0056b3; }
        input[type="text"] { width: 300px; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>Patcherly Connector Installer</h1>

    <?php if (isset($tokenError)): ?>
        <div class="card" style="border-color: #dc3545;">
            <p style="color: #dc3545;"><strong>Token error:</strong> <?php echo htmlspecialchars($tokenError); ?></p>
            <p>Use a fresh install token from your Patcherly dashboard, or install with your Agent API Key below.</p>
        </div>
    <?php endif; ?>

    <?php if ($apiKey === ''): ?>
        <div class="card">
            <h3>Configuration Required</h3>
            <p>Enter your <strong>Install Token</strong> (from dashboard) or your <strong>Agent API Key</strong>.</p>
            <form method="GET" style="margin-top: 1em;">
                <p>
                    <label>Install Token (recommended):</label><br>
                    <input type="text" name="token" placeholder="Paste token from dashboard" style="width: 100%; max-width: 400px;">
                </p>
                <p>— or —</p>
                <p>
                    <label>Agent API Key:</label><br>
                    <input type="text" name="api_key" placeholder="Paste API key">
                </p>
                <button type="submit" class="btn">Start Installation</button>
            </form>
        </div>
    <?php else: ?>
        <div class="card">
            <h3>Installation Progress</h3>
            <?php
            log_msg('Checking environment...');
            if (!function_exists('curl_init')) {
                log_msg('PHP cURL extension is missing!', 'ERROR');
                echo '</div></body></html>';
                exit;
            }
            if (!is_writable(__DIR__)) {
                log_msg('Current directory is not writable. Cannot create installation folder.', 'ERROR');
                echo '</div></body></html>';
                exit;
            }

            if (!file_exists($installDir)) {
                if (mkdir($installDir, 0755, true)) {
                    log_msg('Created installation directory: ' . $installDir, 'SUCCESS');
                } else {
                    log_msg('Failed to create directory.', 'ERROR');
                    echo '</div></body></html>';
                    exit;
                }
            }

            log_msg('Downloading agent package...');
            $artifactBase = '';
            $configUrl = $apiBase . '/api/public/config';
            $ch = curl_init($configUrl);
            if ($ch !== false) {
                curl_setopt_array($ch, [
                    CURLOPT_RETURNTRANSFER => true,
                    CURLOPT_FOLLOWLOCATION => true,
                    CURLOPT_TIMEOUT => 10,
                    CURLOPT_HTTPHEADER => ['Accept: application/json'],
                ]);
                $configResp = curl_exec($ch);
                curl_close($ch);
                if ($configResp !== false) {
                    $config = json_decode($configResp, true);
                    if (is_array($config) && !empty($config['artifact_base_url'])) {
                        $artifactBase = rtrim($config['artifact_base_url'], '/');
                    }
                }
            }
            if ($artifactBase === '') {
                $artifactBase = 'https://github.com/Patcherly-Official/patcherly-connector-packages/releases/download/connector-packages';
            }
            $zipUrl = $artifactBase . '/php-agent.zip';
            $zipPath = $installDir . '/php-agent-download.zip';
            $downloaded = false;
            $ch = curl_init($zipUrl);
            if ($ch !== false) {
                $fp = fopen($zipPath, 'w');
                if ($fp !== false) {
                    curl_setopt_array($ch, [
                        CURLOPT_FILE => $fp,
                        CURLOPT_FOLLOWLOCATION => true,
                        CURLOPT_TIMEOUT => 60,
                    ]);
                    if (curl_exec($ch) !== false && curl_getinfo($ch, CURLINFO_HTTP_CODE) === 200) {
                        $downloaded = true;
                    }
                    fclose($fp);
                }
                curl_close($ch);
            }
            if ($downloaded && file_exists($zipPath) && class_exists('ZipArchive')) {
                $zip = new ZipArchive();
                if ($zip->open($zipPath) === true) {
                    $zip->extractTo($installDir);
                    $zip->close();
                    log_msg('Extracted PHP agent package.', 'SUCCESS');
                } else {
                    $downloaded = false;
                }
                @unlink($zipPath);
            } else {
                $downloaded = false;
            }
            if (!$downloaded) {
                log_msg('Package download failed; installing from local files if present.', 'INFO');
                $files_to_create = ['php_agent.php', 'backup_manager.php', 'patch_applicator.php', 'queue_manager.php', 'sanitizer.php'];
                foreach ($files_to_create as $file) {
                    $path = $installDir . '/' . $file;
                    if (file_exists(__DIR__ . '/' . $file)) {
                        if (copy(__DIR__ . '/' . $file, $path)) {
                            log_msg("Installed $file");
                        }
                    } else {
                        file_put_contents($path, "<?php\n// Patcherly $file – copy full file from repo if needed.\n");
                        log_msg("Created placeholder $file (copy full file from repo for full functionality)");
                    }
                }
            }

            $envContent = "AGENT_API_KEY=" . $apiKey . "\nSERVER_URL=" . $serverUrl . "\n";
            if (file_put_contents($installDir . '/.env', $envContent)) {
                log_msg('Configuration saved (.env)', 'SUCCESS');
            }

            log_msg('Installation successful!', 'SUCCESS');
            ?>
        </div>

        <div class="card" style="margin-top: 20px; border-color: #28a745;">
            <h3 style="color: #28a745;">Next Step: Setup Persistence</h3>
            <p>Set up a <strong>Cron Job</strong> to run the agent periodically (e.g. every minute):</p>
            <div style="background: #333; color: #fff; padding: 15px; border-radius: 5px; overflow-x: auto;">
                <code>php <?php echo htmlspecialchars($installDir); ?>/php_agent.php</code>
            </div>
            <p style="margin-top: 15px; font-size: 0.9em; color: #666;">
                Use the full path to PHP if needed (e.g. /usr/bin/php).
            </p>
        </div>

        <div style="margin-top: 20px;">
            <p style="color: #dc3545;"><strong>Security:</strong> Delete this <code>web_installer.php</code> file from your server after setup.</p>
        </div>
    <?php endif; ?>
</body>
</html>
