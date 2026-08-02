<?php
/**
 * Source contract: WP auto-pipeline analyze-async / approve must sign and send
 * the same empty body (parity with Node/Python after the '{}' HMAC bug).
 *
 * Run: php connectors/patcherly/tests/test-analyze-async-hmac-empty-body.php
 */

$plugin = dirname(__DIR__) . '/patcherly.php';
$src = file_get_contents($plugin);
if ($src === false) {
    fwrite(STDERR, "FAIL: cannot read patcherly.php\n");
    exit(1);
}

function fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

if (!preg_match(
    '/function\s+analyze_and_wait_for_error\s*\([^)]*\)\s*\{(?P<body>[\s\S]*?)\n    \}/',
    $src,
    $m
)) {
    fail('analyze_and_wait_for_error not found');
}
$waitBody = $m['body'];

if (strpos($waitBody, "sign_request('POST', \$path_async_signing, ''") === false) {
    fail('analyze-async must sign with empty body');
}
if (strpos($waitBody, "'body' => '{}'") !== false) {
    fail('analyze-async must not POST {} while signing empty (HMAC mismatch)');
}
if (strpos($waitBody, "wp_remote_post(\$endpoint_async, ['timeout' => 30, 'headers' => \$headers_async, 'body' => ''])") === false
    && strpos($waitBody, "'body' => ''") === false) {
    fail('analyze-async must POST empty body matching the signature');
}

// Auto-pipeline approve lives just after analyze_and_wait in process_error / similar.
$approveIdx = strpos($src, '$path_approve_signing');
if ($approveIdx === false) {
    fail('approve auto-pipeline signing path missing');
}
$approveSlice = substr($src, $approveIdx, 500);
if (strpos($approveSlice, "sign_request('POST', \$path_approve_signing, ''") === false) {
    fail('approve auto-pipeline must sign with empty body');
}
if (strpos($approveSlice, "'body' => '{}'") !== false) {
    fail('approve auto-pipeline must not POST {} while signing empty');
}
if (strpos($approveSlice, "'body' => ''") === false) {
    fail('approve auto-pipeline must send empty body');
}

echo "OK test-analyze-async-hmac-empty-body.php\n";
exit(0);
