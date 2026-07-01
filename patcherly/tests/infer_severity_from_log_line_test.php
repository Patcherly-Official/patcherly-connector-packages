<?php
if (!defined('ABSPATH') && PHP_SAPI !== 'cli') { exit; }
// phpcs:disable WordPress.WP.AlternativeFunctions,WordPress.NamingConventions.PrefixAllGlobals -- dev-only static contract test.

function infer_severity_fail($msg) { fwrite(STDERR, "FAIL: {$msg}\n"); exit(1); }

require_once __DIR__ . '/test-ingest-severity-contract.php';
