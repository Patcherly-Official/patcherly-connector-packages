'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  APPROVE_409_SOFT_STOP_CODES,
  FIX_APPROVE_STATUSES,
  httpErrorCode,
  httpErrorDetail,
} = require('../lib/http_error_detail.js');

describe('http_error_detail', () => {
  it('prefers nested detail.code', () => {
    const payload = { detail: { code: 'empty_fix', message: 'x' }, code: 'wrong' };
    assert.equal(httpErrorCode(payload), 'empty_fix');
    assert.equal(httpErrorDetail(payload).code, 'empty_fix');
  });

  it('falls back to top-level code', () => {
    assert.equal(httpErrorCode({ code: 'auto_apply_not_enabled' }), 'auto_apply_not_enabled');
  });

  it('reads approve_requires_post_analysis', () => {
    assert.equal(
      httpErrorCode({ detail: { code: 'approve_requires_post_analysis' } }),
      'approve_requires_post_analysis',
    );
  });

  it('soft-stops error_path_blocked', () => {
    assert.equal(APPROVE_409_SOFT_STOP_CODES.has('error_path_blocked'), true);
    assert.equal(httpErrorCode({ detail: { code: 'error_path_blocked' } }), 'error_path_blocked');
  });

  it('exposes fix-approve statuses without bare analyzed', () => {
    assert.equal(FIX_APPROVE_STATUSES.has('awaiting_approval'), true);
    assert.equal(FIX_APPROVE_STATUSES.has('manual_review_required'), true);
    assert.equal(FIX_APPROVE_STATUSES.has('analyzed'), false);
  });
});
