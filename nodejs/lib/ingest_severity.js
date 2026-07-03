/**
 * AUTO-GENERATED from config/settings_schema.yaml error_type_configurations — do not edit by hand.
 * Shared log-line → error_type → severity inference for connector ingest payloads.
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
