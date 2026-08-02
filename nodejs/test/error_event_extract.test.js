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
