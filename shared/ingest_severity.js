/**
 * Shared log-line → error_type → severity inference for connector ingest payloads.
 * Canonical severity: Low | Medium | High | Critical (Settings → Metrics).
 */

const DEFAULT_ERROR_TYPE_SEVERITIES = {
  syntax: 'Low',
  typo: 'Low',
  null_reference: 'Medium',
  logic: 'Medium',
  other: 'High',
  runtime: 'Medium',
  import: 'Low',
  type: 'Medium',
  reference: 'Medium',
  fatal: 'High',
  warning: 'Low',
  notice: 'Low',
  parse: 'Medium',
  hook: 'Medium',
  database: 'High',
};

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
  inferErrorTypeFromLogLine,
  severityForErrorType,
  buildIngestSeverityFields,
};
