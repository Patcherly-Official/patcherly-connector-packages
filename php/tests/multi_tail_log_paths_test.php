<?php
/**
 * Pins PHP multi-tail: serverLogPaths are all candidates; custom-first order
 * from the API is preserved; validateLogPath accepts /var/log/apache2/*.log.
 *
 * Usage: php connectors/php/tests/multi_tail_log_paths_test.php
 */

putenv('PATCHERLY_AGENT_NOAUTORUN=1');
error_reporting(E_ALL & ~E_DEPRECATED);

require_once dirname(__DIR__) . '/patcherly_agent.php';

function mt_fail(string $msg): void {
    fwrite(STDERR, "FAIL: {$msg}\n");
    exit(1);
}

class MultiTailProbeAgent extends PHPAgent {
    public function __construct() {
        // Skip parent ctor (OAuth / network).
    }

    public function setServerPaths(array $paths): void {
        $ref = new ReflectionClass(PHPAgent::class);
        $p = $ref->getProperty('serverLogPaths');
        $p->setAccessible(true);
        $p->setValue($this, $paths);
        $lf = $ref->getProperty('logFile');
        $lf->setAccessible(true);
        $lf->setValue($this, $paths[0] ?? 'logs/error.log');
    }

    /** @return list<string> */
    public function exposeMonitored(): array {
        $m = new ReflectionMethod(PHPAgent::class, 'monitoredLogPaths');
        $m->setAccessible(true);
        return $m->invoke($this);
    }
}

$tmp = sys_get_temp_dir() . '/patcherly_mt_' . bin2hex(random_bytes(4));
if (!mkdir($tmp) && !is_dir($tmp)) {
    mt_fail("cannot create tmp {$tmp}");
}
$custom = $tmp . '/studioweb19-error.log';
$preset = $tmp . '/apache-error.log';
file_put_contents($custom, "old\n");
file_put_contents($preset, "old\n");

try {
    PHPAgent::validateLogPath('/var/log/apache2/studioweb19-error.log');
} catch (Throwable $e) {
    mt_fail('validateLogPath must accept apache vhost custom path: ' . $e->getMessage());
}

$agent = new MultiTailProbeAgent();
// Custom first (API merge order), then preset — both must be tailed.
$agent->setServerPaths([$custom, $preset]);
$monitored = $agent->exposeMonitored();
if (count($monitored) < 2) {
    mt_fail('expected multi-tail of custom + preset, got: ' . implode(', ', $monitored));
}
if ($monitored[0] !== $custom) {
    mt_fail('custom path must be first (wins over preset): ' . $monitored[0]);
}
if (!in_array($preset, $monitored, true)) {
    mt_fail('preset path must still be monitored');
}

// Cleanup
@unlink($custom);
@unlink($preset);
@rmdir($tmp);

echo "multi_tail_log_paths_test.php: OK\n";
