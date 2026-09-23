<?php
/**
 * resolve_patch_target_path_test.php
 *
 * Pins root-jail parity with Python/Node: existing absolute paths outside
 * cwd / PATCHERLY_TARGET_ROOTS must not win; nested app/ paths still resolve.
 *
 * Usage:
 *   php connectors/php/tests/resolve_patch_target_path_test.php
 */

putenv('PATCHERLY_AGENT_NOAUTORUN=1');
error_reporting(E_ALL & ~E_DEPRECATED);

require_once dirname(__DIR__) . '/patcherly_agent.php';

function rpt_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

final class ResolvePathTestableAgent extends PHPAgent {
    public function __construct() {
        // skip parent wiring
    }

    public function resolve(string $filePath): string {
        $m = new ReflectionMethod(PHPAgent::class, 'resolvePatchTargetPath');
        $m->setAccessible(true);
        return (string)$m->invoke($this, $filePath);
    }

    public function childEnv(): array {
        $m = new ReflectionMethod(PHPAgent::class, 'buildPostApplyChildEnv');
        $m->setAccessible(true);
        return $m->invoke($this);
    }
}

$agent = new ResolvePathTestableAgent();
$tmp = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-rptp-php-' . getmypid();
@mkdir($tmp, 0700, true);
$prevRoots = getenv('PATCHERLY_TARGET_ROOTS');
$prevCwd = getcwd();
putenv('PATCHERLY_TARGET_ROOTS');
chdir($tmp);

try {
    @mkdir($tmp . DIRECTORY_SEPARATOR . 'app', 0700, true);
    $nested = $tmp . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'logic.php';
    file_put_contents($nested, "<?php\n");
    file_put_contents($tmp . DIRECTORY_SEPARATOR . 'logic.php', "WRONG\n");
    $got = $agent->resolve('app/logic.php');
    if (realpath($got) !== realpath($nested)) {
        rpt_fail("nested app/logic.php expected {$nested}, got {$got}");
    }

    $outside = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'patcherly-rptp-out-' . getmypid() . '.php';
    file_put_contents($outside, "EVIL\n");
    $gotOut = $agent->resolve($outside);
    if (realpath($gotOut) === realpath($outside)) {
        rpt_fail('absolute path outside roots must not resolve to itself');
    }
    $cwdReal = realpath($tmp);
    $gotReal = realpath($gotOut) ?: $gotOut;
    if (strpos(str_replace('\\', '/', (string)$gotReal), str_replace('\\', '/', (string)$cwdReal)) !== 0) {
        rpt_fail("outside-root fallback must stay under cwd, got {$gotOut}");
    }
    @unlink($outside);

    putenv('PATCHERLY_OAUTH_CLIENT_SECRET=s3cret');
    putenv('PATCHERLY_ACCESS_TOKEN=tok');
    putenv('PATCHERLY_BACKUP_ROOT=/tmp/backups');
    putenv('DATABASE_URL=postgres://app@db/app');
    $env = $agent->childEnv();
    if (!empty($env['PATCHERLY_OAUTH_CLIENT_SECRET']) || !empty($env['PATCHERLY_ACCESS_TOKEN'])) {
        rpt_fail('child env must strip Patcherly auth keys');
    }
    if (($env['DATABASE_URL'] ?? null) !== 'postgres://app@db/app') {
        rpt_fail('child env must keep DATABASE_URL');
    }
    if (($env['PATCHERLY_BACKUP_ROOT'] ?? null) !== '/tmp/backups') {
        rpt_fail('child env must keep non-secret PATCHERLY_BACKUP_ROOT');
    }
} finally {
    chdir($prevCwd ?: $tmp);
    if ($prevRoots === false) {
        putenv('PATCHERLY_TARGET_ROOTS');
    } else {
        putenv('PATCHERLY_TARGET_ROOTS=' . $prevRoots);
    }
    // best-effort cleanup
    @unlink($tmp . DIRECTORY_SEPARATOR . 'app' . DIRECTORY_SEPARATOR . 'logic.php');
    @unlink($tmp . DIRECTORY_SEPARATOR . 'logic.php');
    @rmdir($tmp . DIRECTORY_SEPARATOR . 'app');
    @rmdir($tmp);
}

echo "resolve_patch_target_path_test.php: OK\n";
