/**
 * AUTO-GENERATED from config/settings_schema.yaml + log_ingest_skip_patterns.yaml — do not edit by hand.
 * Shared log-line → error_type → severity inference and pre-ingest noise filtering.
 */
'use strict';

const DEFAULT_ERROR_TYPE_SEVERITIES = {
  "database": "High",
  "fatal": "High",
  "hook": "Medium",
  "import": "Low",
  "logic": "Medium",
  "notice": "Low",
  "null_reference": "Medium",
  "other": "High",
  "parse": "Medium",
  "reference": "Medium",
  "runtime": "Medium",
  "syntax": "Low",
  "type": "Medium",
  "typo": "Low",
  "warning": "Low",
};

const LOG_INGEST_KEEP_PATTERNS = [
  "PHP\\s+Fatal",
  "PHP\\s+Parse\\s+error",
  "PHP\\s+Recoverable\\s+fatal",
  "^Fatal error:",
  "Maximum execution time|Allowed memory size",
  "Uncaught\\s+\\S*(Error|Exception)",
  "^Traceback\\s",
  "^\\w+(Error|Exception):",
  "^Exception:",
  "^Error:\\s",
  "Unhandled\\s+(Promise\\s+)?Rejection",
  "uncaughtException|uncaught exception",
  "Assertion failed",
  "File\\s+[\"']",
  "^\\s*#\\d+\\s+",
  "^\\s+at\\s+",
  "\"level\"\\s*:\\s*\"(error|fatal|critical)\"",
  "\"level\"\\s*:\\s*50\\b",
  "\"severity\"\\s*:\\s*\"(ERROR|CRITICAL|FATAL)\"",
].map((p) => new RegExp(p, 'i'));
const LOG_INGEST_SKIP_PHP_PREFIX = new RegExp("^PHP\\s+(Notice|Deprecated|Warning|Strict\\s+standards|Info)\\s*:", 'i');
const LOG_INGEST_SKIP_PATTERNS = [
  "^\\(node:\\d+\\)\\s+\\[DEP\\d+\\]",
  "DeprecationWarning:",
  "^UserWarning:",
  "^\\[info\\]",
  "^INFO:",
  "^DEBUG:",
].map((p) => new RegExp(p, 'i'));
const LOG_INGEST_SKIP_SUBSTRINGS = ["auditor:scan", "\"kind\":\"installed-plugin\""];
const LOG_INGEST_FAILURE_SIGNAL = new RegExp("\\b(error|exception|traceback|fatal|critical|panic|failed|failure|rejection|errno|segfault)\\b|^\\w+(Error|Exception):", 'i');

function shouldSkipLogLineForIngest(logLine) {
  const line = String(logLine || '').trim();
  if (!line) return true;
  for (const re of LOG_INGEST_KEEP_PATTERNS) {
    if (re.test(line)) return false;
  }
  if (LOG_INGEST_SKIP_PHP_PREFIX && LOG_INGEST_SKIP_PHP_PREFIX.test(line)) return true;
  for (const re of LOG_INGEST_SKIP_PATTERNS) {
    if (re.test(line)) return true;
  }
  const lower = line.toLowerCase();
  for (const sub of LOG_INGEST_SKIP_SUBSTRINGS) {
    if (sub && lower.includes(String(sub).toLowerCase())) return true;
  }
  if (!LOG_INGEST_FAILURE_SIGNAL.test(line)) return true;
  return false;
}


function inferErrorTypeFromLogLine(logLine) {
  const line = String(logLine || '').toLowerCase();
  if (line.includes('parse error')) return 'parse';
  if (line.includes('fatal error')) return 'fatal';
  if (line.includes('database')) return 'database';
  if (line.includes('warning') || line.includes('deprecated')) return 'warning';
  if (line.includes('notice')) return 'notice';
  if (line.includes('uncaught') || /\berror\b/.test(line)) return 'runtime';
  return 'other';
}

function severityForErrorType(errorType) {
  const key = String(errorType || '').toLowerCase();
  return DEFAULT_ERROR_TYPE_SEVERITIES[key] || 'High';
}

function buildIngestSeverityFields(logLine) {
  const error_type = inferErrorTypeFromLogLine(logLine);
  return {
    error_type,
    severity: severityForErrorType(error_type),
  };
}

module.exports = {
  DEFAULT_ERROR_TYPE_SEVERITIES,
  shouldSkipLogLineForIngest,
  inferErrorTypeFromLogLine,
  severityForErrorType,
  buildIngestSeverityFields,
};
