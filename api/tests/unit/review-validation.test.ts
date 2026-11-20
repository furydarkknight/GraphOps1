import assert from "node:assert/strict";
import test from "node:test";
import {
  validateReviewDecision,
  validateUpdateSummary,
} from "../../src/lib/review-validation.js";

test("approval may omit an optional decision note", () => {
  const res = validateReviewDecision("APPROVED", undefined);
  assert.equal(res.valid, true);
  if (res.valid) {
    assert.equal(res.status, "APPROVED");
  }
});

test("rejection requires at least 10 characters explanation", () => {
  const short = validateReviewDecision("REJECTED", "Too brief");
  assert.equal(short.valid, false);

  const good = validateReviewDecision("REJECTED", "Action would disconnect active database replication cluster.");
  assert.equal(good.valid, true);
  if (good.valid) {
    assert.equal(good.status, "REJECTED");
  }
});

test("validateUpdateSummary enforces minimum 5 characters", () => {
  assert.equal(validateUpdateSummary("abc").valid, false);
  assert.equal(validateUpdateSummary("Host isolated and creds rotated").valid, true);
});
