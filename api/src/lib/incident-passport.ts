import { createHmac, timingSafeEqual } from "node:crypto";

// ─── Incident Passport (ported from BrandFlight release-passport.ts) ─────────
// HMAC-sha256 over a canonical JSON snapshot. The signing secret is separate
// from the JWT secret so each can be rotated independently.

export type IncidentPassportSnapshot = {
  schemaVersion: 1;
  incident: {
    id: string;
    title: string;
    severity: string;
    policyId: string | null;
    snapshotId: string;
    snapshotInputHash: string;
  };
  hunt: {
    runId: string;
    configHash: string;
    resultHash: string;
  } | null;
  blastRadius: {
    riskScore: number;
    impactedAssets: number;
    crownJewelExposure: boolean;
  } | null;
  containment: {
    planId: string;
    actions: Array<{ type: string; target: string }>;
    approvedAt: string;
    approvedById: string;
    approvedByName: string;
  } | null;
  approval: {
    decision: "ISSUED";
    issuedById: string;
    issuedByName: string;
    issuedAt: string;
  };
};

/** Stable JSON serialisation — key ordering cannot change the digest. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value) ?? "null";
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(",")}]`;
  }
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .filter((k) => record[k] !== undefined)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJson(record[k])}`)
    .join(",")}}`;
}

export function createIncidentPassport(
  snapshot: IncidentPassportSnapshot,
  signingSecret: string,
) {
  return {
    snapshot,
    passportHash: createHmac("sha256", signingSecret)
      .update(canonicalJson(snapshot), "utf8")
      .digest("hex"),
  };
}

export function verifyIncidentPassportHash(
  snapshot: unknown,
  expectedHash: string,
  signingSecret: string,
): boolean {
  const expected = Buffer.from(expectedHash, "hex");
  const actual = createHmac("sha256", signingSecret)
    .update(canonicalJson(snapshot), "utf8")
    .digest();
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
