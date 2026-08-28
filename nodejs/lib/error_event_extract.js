'use strict';

/**
 * Multi-line log error event extraction with incomplete-block carry.
 * Mirrors connectors/python/lib/error_event_extract.py
 */

const START_OR_CONT =
  /^(Traceback\s|File\s+["']|Exception:|Error:\s|PHP\s+(?:Fatal|Parse|Warning|Notice|Deprecated))/i;
const ERROR_WORD = /\b(error|exception|traceback|fatal|failed|failure)\b/i;
const PYTHON_EXCEPTION_LINE = /^\w+(?:Error|Exception):/i;
const TRACEBACK_LINE = /^\s*Traceback\b/i;
const FILE_FRAME = /^\s*File\s+["']/;
const ERROR_EXCEPTION_HEADER = /\bERROR\b.*\b\w+(?:Error|Exception)\s*:/i;
const PHP_STACK_HEADER = /^\s*Stack trace\s*:/i;
const PHP_FRAME = /^\s*#\d+\s+/;
const PHP_THROWN_IN = /^\s*thrown\s+in\s+/i;
const NODE_AT_FRAME = /^\s+at\s+/;

const DEFAULT_INCOMPLETE_HOLD_SECONDS = 2.0;
const DEFAULT_MAX_PENDING_LINES = 500;

function pythonTracebackClosed(lines) {
  let sawTb = false;
  for (const line of lines) {
    const stripped = String(line).trim();
    if (!stripped) continue;
    if (TRACEBACK_LINE.test(stripped)) {
      sawTb = true;
      continue;
    }
    if (sawTb && PYTHON_EXCEPTION_LINE.test(stripped)) return true;
  }
  return false;
}

function orphanFileStackClosed(lines) {
  let sawFile = false;
  for (const line of lines) {
    const stripped = String(line).trim();
    if (!stripped) continue;
    if (FILE_FRAME.test(line)) {
      sawFile = true;
      continue;
    }
    if (sawFile && PYTHON_EXCEPTION_LINE.test(stripped)) return true;
  }
  return false;
}

function phpStackClosed(lines) {
  for (const line of lines) {
    const stripped = String(line).trim();
    if (!stripped) continue;
    if (PHP_THROWN_IN.test(stripped)) return true;
    if (PHP_FRAME.test(stripped) && stripped.includes('{main}')) return true;
  }
  return false;
}

function looksIncompleteErrorBlock(lines) {
  if (!lines || !lines.length) return false;
  const nonempty = lines.map((ln) => String(ln).replace(/\r?\n$/, '')).filter((ln) => ln.trim());
  if (!nonempty.length) return false;

  const hasTraceback = nonempty.some((ln) => TRACEBACK_LINE.test(ln.trim()));
  const hasFile = lines.some((ln) => FILE_FRAME.test(ln));
  const hasPhpStack = nonempty.some(
    (ln) => PHP_STACK_HEADER.test(ln.trim()) || PHP_FRAME.test(ln.trim())
  );
  const hasNodeAt = lines.some((ln) => NODE_AT_FRAME.test(ln));

  if (hasTraceback) return !pythonTracebackClosed(lines);
  if (hasFile && !hasTraceback) return !orphanFileStackClosed(lines);
  // WP debug.log often emits ERROR + bare #N frames (no "Stack trace:" label).
  if (hasPhpStack) return !phpStackClosed(lines);

  const last = nonempty[nonempty.length - 1].trim();
  if (ERROR_EXCEPTION_HEADER.test(last) && !hasTraceback && !hasFile) return true;
  if (
    /\bERROR\b/i.test(last) &&
    /\bError\s*:/.test(last) &&
    !hasNodeAt &&
    nonempty.length <= 2
  ) {
    return true;
  }
  return false;
}

function extractErrorEvents(lines, { holdIncomplete = true } = {}) {
  const events = [];
  let current = [];

  const flush = () => {
    if (current.length) {
      events.push(current.join('\n'));
      current = [];
    }
  };

  for (const raw of lines) {
    const line = String(raw);
    const stripped = line.trim();
    const caretOnly =
      /^[\s^~]+$/.test(line.replace(/\r?\n$/, '')) ||
      (stripped.length > 0 && /^[\^~]+$/.test(stripped));
    const isCont =
      current.length > 0 &&
      (line.startsWith(' ') ||
        line.startsWith('\t') ||
        stripped.startsWith('at ') ||
        stripped.startsWith('raise ') ||
        (stripped.length && stripped[0] === '#') ||
        PHP_STACK_HEADER.test(stripped) ||
        PHP_THROWN_IN.test(stripped) ||
        PYTHON_EXCEPTION_LINE.test(stripped) ||
        caretOnly);
    if (START_OR_CONT.test(line) || isCont) {
      current.push(line.replace(/\r?\n$/, ''));
    } else if (ERROR_WORD.test(stripped)) {
      flush();
      current.push(line.replace(/\r?\n$/, ''));
    } else if (current.length && stripped === '') {
      flush();
    } else if (current.length) {
      flush();
    }
  }

  let leftover = [];
  if (current.length) {
    if (holdIncomplete && looksIncompleteErrorBlock(current)) {
      leftover = current.slice();
      current = [];
    } else {
      flush();
    }
  }

  if (!events.length) {
    const errorLines = lines
      .map((l) => String(l).replace(/\r?\n$/, ''))
      .filter(
        (l) =>
          /\b(error|exception|traceback|fatal|critical|failed|failure|rejection)\b/i.test(l) ||
          /^\s*\w+(Error|Exception):/i.test(l)
      );
    if (errorLines.length && !leftover.length) {
      events.push(errorLines.join('\n'));
    }
  }

  return { events, leftover };
}

class IncompleteLogCarry {
  constructor({
    holdSeconds = DEFAULT_INCOMPLETE_HOLD_SECONDS,
    maxPendingLines = DEFAULT_MAX_PENDING_LINES,
  } = {}) {
    this.holdSeconds = Number(holdSeconds);
    this.maxPendingLines = Number(maxPendingLines);
    this._pending = new Map();
    this._since = new Map();
  }

  clear(path) {
    this._pending.delete(path);
    this._since.delete(path);
  }

  ingestNewLines(path, newLines, now = Date.now() / 1000) {
    const pending = this._pending.get(path) || [];
    const combined = pending.concat(newLines || []);
    if (!combined.length) return [];

    let force = false;
    if (this._since.has(path) && now - this._since.get(path) >= this.holdSeconds) {
      force = true;
    }
    if (combined.length >= this.maxPendingLines) force = true;

    const { events, leftover } = extractErrorEvents(combined, {
      holdIncomplete: !force,
    });
    if (leftover.length) {
      this._pending.set(path, leftover);
      if (!this._since.has(path)) this._since.set(path, now);
    } else {
      this.clear(path);
    }
    return events;
  }
}

module.exports = {
  extractErrorEvents,
  looksIncompleteErrorBlock,
  IncompleteLogCarry,
  DEFAULT_INCOMPLETE_HOLD_SECONDS,
  DEFAULT_MAX_PENDING_LINES,
};
