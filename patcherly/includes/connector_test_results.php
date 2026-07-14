<?php
/**
 * Shared connector smoke-test payload for POST /errors/{id}/test/results.
 * Used by the main plugin and rescue MU after a successful apply-result when
 * advanced_agent_testing keeps the API row in `applying` until tests are reported.
 */

if (!defined('ABSPATH')) {
    exit;
}

if (!function_exists('patcherly_connector_smoke_test_results_api_path')) {
    function patcherly_connector_smoke_test_results_api_path(string $error_id): string {
        $error_id = trim($error_id);
        return '/errors/' . rawurlencode($error_id) . '/test/results';
    }
}

if (!function_exists('patcherly_build_connector_smoke_test_results_payload')) {
    /**
     * @return array<string, mixed>|null
     */
    function patcherly_build_connector_smoke_test_results_payload(string $error_id, bool $apply_success): ?array {
        $error_id = trim($error_id);
        if ($error_id === '') {
            return null;
        }
        $passed = $apply_success ? 1 : 0;
        $failed = $apply_success ? 0 : 1;
        return [
            'error_id'        => $error_id,
            'total_tests'     => 1,
            'passed'          => $passed,
            'failed'          => $failed,
            'skipped'         => 0,
            'execution_time'  => 0,
            'results'         => [
                [
                    'test_name' => 'connector_smoke',
                    'status'    => $apply_success ? 'passed' : 'failed',
                    'duration'  => 0,
                    'message'   => $apply_success ? 'Apply success' : 'Apply failed or rolled back',
                ],
            ],
            'framework'       => 'connector_smoke',
            'language'        => 'php',
            'executed_by'     => 'agent',
        ];
    }
}
