<?php
/**
 * Source contract: connectors must drop log lines without an extractable file path.
 */

$root = dirname(__DIR__, 3);

$files = [
    'nodejs/patcherly_agent.js' => 'if (!filePath)',
    'python/patcherly_agent.py' => 'if not file_path:',
    'php/patcherly_agent.php' => 'if (!$filePath)',
    'patcherly/patcherly.php' => 'if (!$file_path)',
    'patcherly/rescue/patcherly-rescue.php' => 'if (!$file_path)',
];

foreach ($files as $rel => $needle) {
    $path = $root . '/connectors/' . $rel;
    $src = @file_get_contents($path);
    if ($src === false) {
        fwrite(STDERR, "FAIL: missing {$path}\n");
        exit(1);
    }
    if (strpos($src, $needle) === false) {
        fwrite(STDERR, "FAIL: {$rel} missing mandatory path gate ({$needle})\n");
        exit(1);
    }
}

echo "OK mandatory_path_gate_contract\n";
