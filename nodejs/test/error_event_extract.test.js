'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  extractErrorEvents,
  IncompleteLogCarry,
  looksIncompleteErrorBlock,
} = require('../lib/error_event_extract');

const FULL = [
  "2026-07-25 21:08:06,980 ERROR RuntimeError: invalid shipping zone: 'zone-INVALID' [work/6]",
  'Traceback (most recent call last):',
  '  File "/app/server.py", line 179, in do_GET',
  '    _json(self, 200, _run_work(n))',
  '  File "/app/server.py", line 125, in _run_work',
  '    raise RuntimeError(f"invalid shipping zone: {SHIPPING_ZONE!r}")',
  "RuntimeError: invalid shipping zone: 'zone-INVALID'",
];

test('complete traceback is one event', () => {
  const { events, leftover } = extractErrorEvents(FULL, { holdIncomplete: true });
  assert.equal(leftover.length, 0);
  assert.equal(events.length, 1);
  assert.match(events[0], /Traceback/);
  assert.match(events[0], /line 125/);
});

test('partial traceback is held then merged', () => {
  const carry = new IncompleteLogCarry({ holdSeconds: 30 });
  assert.deepEqual(carry.ingestNewLines('/log', FULL.slice(0, 3), 1000), []);
  const second = carry.ingestNewLines('/log', FULL.slice(3), 1000.5);
  assert.equal(second.length, 1);
  assert.match(second[0], /RuntimeError: invalid shipping zone/);
  assert.match(second[0], /line 125/);
});

test('plain ERROR line emits immediately', () => {
  const { events, leftover } = extractErrorEvents(
    ['2025-01-01 12:00:00 ERROR Something failed'],
    { holdIncomplete: true }
  );
  assert.equal(leftover.length, 0);
  assert.equal(events.length, 1);
});

test('looksIncomplete detects mid-traceback', () => {
  assert.equal(looksIncompleteErrorBlock(FULL.slice(0, 3)), true);
  assert.equal(looksIncompleteErrorBlock(FULL), false);
});

test('PHP fatal + Stack trace is one event', () => {
  const lines = [
    '[2026-08-24T14:59:23+00:00] PHP Fatal error:  Uncaught TypeError: Cannot access offset of type string on string in /nas/content/live/oit/wp-content/themes/oxfam-new/landing/landing-rossa.php:54',
    'Stack trace:',
    '#0 /nas/content/live/oit/wp-includes/template-loader.php(132): include()',
    '#1 /nas/content/live/oit/wp-blog-header.php(19): require_once(\'/nas/content/li...\')',
    '#2 /nas/content/live/oit/index.php(17): require(\'/nas/content/li...\')',
    '#3 {main}',
    '  thrown in /nas/content/live/oit/wp-content/themes/oxfam-new/landing/landing-rossa.php:54',
  ];
  const { events, leftover } = extractErrorEvents(lines, { holdIncomplete: true });
  assert.equal(leftover.length, 0);
  assert.equal(events.length, 1);
  assert.match(events[0], /Uncaught TypeError/);
  assert.match(events[0], /Stack trace:/);
  assert.match(events[0], /#0 \/nas\/content\/live\/oit\/wp-includes\/template-loader\.php/);
  assert.match(events[0], /thrown in .*landing-rossa\.php:54/);
});

test('WP demo ERROR + failed companion produces no orphan stack', () => {
  const lines = [
    '2026-08-27T11:40:27+00:00 ERROR [patcherly-wp-demo/work/7] DivisionByZeroError: Division by zero in /var/www/html/wp-content/patcherly-demo/logic.php:12',
    '#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): patcherly_wp_demo_price_display(500)',
    '#1 /var/www/html/wp-content/patcherly-demo/work7_runner.php(11): patcherly_wp_demo_work7()',
    '#2 {main}',
    '[27-Aug-2026 11:40:27 UTC] patcherly-wp-demo work/7 failed: DivisionByZeroError: Division by zero in /var/www/html/wp-content/patcherly-demo/logic.php:12',
    '#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): patcherly_wp_demo_price_display(500)',
    '#1 /var/www/html/wp-content/patcherly-demo/work7_runner.php(11): patcherly_wp_demo_work7()',
    '#2 {main}',
  ];
  const { events, leftover } = extractErrorEvents(lines, { holdIncomplete: true });
  assert.equal(leftover.length, 0);
  assert.equal(events.length, 2);
  assert.match(events[0], /ERROR \[patcherly-wp-demo\/work\/7\]/);
  assert.match(events[1], /work\/7 failed:/);
  assert.equal(events[0].trimStart().startsWith('#'), false);
  assert.equal(events[1].trimStart().startsWith('#'), false);
});

test('bare #N frames do not start an event', () => {
  const { events, leftover } = extractErrorEvents(
    [
      '#0 /var/www/html/wp-content/patcherly-demo/logic.php(32): f()',
      '#1 /x.php(1): g()',
      '#2 {main}',
    ],
    { holdIncomplete: true }
  );
  assert.equal(events.length, 0);
  assert.equal(leftover.length, 0);
});

test('WP ERROR + partial #N held until {main}', () => {
  const { events, leftover } = extractErrorEvents(
    [
      '2026-08-27T11:40:27+00:00 ERROR [patcherly-wp-demo/work/7] DivisionByZeroError: Division by zero in /x.php:12',
      '#0 /x.php(32): f()',
    ],
    { holdIncomplete: true }
  );
  assert.equal(events.length, 0);
  assert.ok(leftover.length > 0);
});
