import { createHash, randomBytes } from "node:crypto";
import { canonicalJson } from "./incident-passport.js";

// ─── Evidence receipts (ported from BrandFlight audit-receipts.ts) ────────────
// A receipt is an immutable record that a specific hunt ran against a specific
// graph snapshot with a specific policy configuration, and produced a specific
// result. The receipt ID is a 32-byte random hex string; only server-issued IDs
// are accepted.

export function sha256Text(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function sha256Json(value: unknown): string {
  return sha256Text(canonicalJson(value));
}

export function createEvidenceReceiptId(): string {
  return randomBytes(32).toString("hex");
}

export type HuntConfiguration = {
  policyId: string | null;
  ruleIds: string[];
  snapshotId: string;
  parameters: Record<string, unknown>;
};

/** Deterministic hash of the hunt configuration. */
export function huntConfigHash(config: HuntConfiguration): string {
  const stable = {
    policyId: config.policyId,
    ruleIds: [...config.ruleIds].sort(),
    snapshotId: config.snapshotId,
    parameters: config.parameters,
  };
  return sha256Text(canonicalJson(stable));
}

/** Hash of raw ingest payload (used as inputHash on GraphSnapshot). */
export function ingestInputHash(events: unknown[]): string {
  return sha256Json(events);
}
