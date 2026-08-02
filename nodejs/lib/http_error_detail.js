/**
 * Unwrap FastAPI/HTTP error bodies for connector soft-stops.
 * Prefer nested `detail.code`; fall back to top-level `code`.
 */

'use strict';

/** Same set as dashboard FIX_APPROVE_STATUSES / server POST_ANALYSIS_REVIEW_STATUSES. */
const FIX_APPROVE_STATUSES = new Set(['awaiting_approval', 'manual_review_required']);

const APPROVE_409_SOFT_STOP_CODES = new Set([
  'empty_fix',
  'low_confidence_confirmation_required',
  'auto_apply_not_enabled',
  'approve_requires_post_analysis',
]);

function httpErrorDetail(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return {};
  const detail = payload.detail;
  if (detail && typeof detail === 'object' && !Array.isArray(detail)) return detail;
  return payload;
}

function httpErrorCode(payload) {
  const detail = httpErrorDetail(payload);
  if (detail.code == null || detail.code === '') return null;
  return String(detail.code);
}

module.exports = {
  FIX_APPROVE_STATUSES,
  APPROVE_409_SOFT_STOP_CODES,
  httpErrorDetail,
  httpErrorCode,
};
