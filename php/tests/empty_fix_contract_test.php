<?php
/**
 * empty_fix auto-apply / approved-poll contract (PHP agent source).
 * Run: php connectors/php/tests/empty_fix_contract_test.php
 */

declare(strict_types=1);

$src = file_get_contents(dirname(__DIR__) . '/patcherly_agent.php');
if ($src === false) {
    fwrite(STDERR, "FAIL: cannot read patcherly_agent.php\n");
    exit(1);
}

function assert_true(bool $ok, string $msg): void {
    if (!$ok) {
        fwrite(STDERR, "FAIL: $msg\n");
        exit(1);
    }
    echo "ok - $msg\n";
}

assert_true(substr_count($src, "'empty_fix'") >= 2, 'empty_fix message appears for poll + auto-apply paths');
assert_true(str_contains($src, "trim(\$data['fix']) !== ''"), 'auto-apply requires non-empty trimmed fix');
assert_true(str_contains($src, "trim(\$data['fix']) === ''"), 'approved-poll treats whitespace as empty');

echo "ALL PASSED\n";
