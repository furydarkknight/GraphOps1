// ─── Review / decision validation (ported from BrandFlight review-validation.ts)
// Generic helpers for validating human-entered approval/rejection notes.

export type ReviewDecisionResult =
  | { valid: true; status: "APPROVED"; note?: string }
  | { valid: true; status: "REJECTED"; note: string }
  | { valid: false; error: string };

const MIN_REJECTION_LENGTH = 10;

export function validateReviewDecision(
  status: string,
  note: string | undefined,
): ReviewDecisionResult {
  if (status === "APPROVED") {
    const trimmed = note?.trim();
    return { valid: true, status: "APPROVED", ...(trimmed ? { note: trimmed } : {}) };
  }

  if (status === "REJECTED") {
    const trimmed = note?.trim() ?? "";
    if (trimmed.length < MIN_REJECTION_LENGTH) {
      return {
        valid: false,
        error: `A rejection note of at least ${MIN_REJECTION_LENGTH} characters is required.`,
      };
    }
    return { valid: true, status: "REJECTED", note: trimmed };
  }

  return { valid: false, error: `Unknown decision status: "${status}".` };
}

export type SummaryValidationResult =
  | { valid: true; summary: string }
  | { valid: false; error: string };

const MIN_SUMMARY_LENGTH = 5;

export function validateUpdateSummary(
  summary: string | undefined,
): SummaryValidationResult {
  const trimmed = summary?.trim() ?? "";
  if (trimmed.length < MIN_SUMMARY_LENGTH) {
    return {
      valid: false,
      error: `An update summary of at least ${MIN_SUMMARY_LENGTH} characters is required.`,
    };
  }
  return { valid: true, summary: trimmed };
}
