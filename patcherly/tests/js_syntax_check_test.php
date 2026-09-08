<?php
/**
 * Thin compatibility wrapper for the shared connector syntax gate.
 *
 * connectors/scripts/check_connector_syntax.py owns the shipped PHP/JS paths;
 * keep no independent file list here.
 */
declare(strict_types=1);

$checker = dirname(__DIR__, 2)
    . DIRECTORY_SEPARATOR . 'scripts'
    . DIRECTORY_SEPARATOR . 'check_connector_syntax.py';
$python = getenv('PYTHON') ?: 'python';
$command = escapeshellarg($python)
    . ' ' . escapeshellarg($checker)
    . ' --connector patcherly 2>&1';

$output = [];
$code = 0;
exec($command, $output, $code);
fwrite($code === 0 ? STDOUT : STDERR, implode(PHP_EOL, $output) . PHP_EOL);
exit($code);
