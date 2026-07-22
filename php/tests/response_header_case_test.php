<?php
/**
 * response_header_case_test.php
 *
 * Uvicorn emits lowercase response header names. sendGet must store keys
 * lowercased so lookups for x-patcherly-signature succeed (Node/Python
 * clients are case-insensitive; PHP curl HEADERFUNCTION is not).
 *
 *   php connectors/php/tests/response_header_case_test.php
 */

function normalize_response_header_key(string $name): string {
    return strtolower(trim($name));
}

$raw = [
    "x-patcherly-signature: abc\r\n",
    "X-Patcherly-Timestamp: 123\r\n",
    "Content-Type: application/json\r\n",
];

$headers = [];
foreach ($raw as $line) {
    $parts = explode(':', $line, 2);
    if (count($parts) < 2) {
        continue;
    }
    $headers[normalize_response_header_key($parts[0])] = trim($parts[1]);
}

assert(($headers['x-patcherly-signature'] ?? null) === 'abc', 'lowercase signature key');
assert(($headers['x-patcherly-timestamp'] ?? null) === '123', 'lowercase timestamp key');
assert(!isset($headers['X-Patcherly-Signature']), 'mixed-case key must not be used');
assert(($headers['content-type'] ?? null) === 'application/json');

echo "response_header_case_test.php: OK\n";
