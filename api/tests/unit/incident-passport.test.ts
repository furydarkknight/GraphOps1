import assert from "node:assert/strict";
import test from "node:test";
import {
  canonicalJson,
  createIncidentPassport,
  verifyIncidentPassportHash,
  type IncidentPassportSnapshot,
} from "../../src/lib/incident-passport.js";

const sampleSnapshot: IncidentPassportSnapshot = {
  schemaVersion: 1,
  incident: {
    id: "incident-c1-001",
    title: "Lateral Movement to Domain Controller DC-01",
    severity: "CRITICAL",
    policyId: "policy-soc-001",
    snapshotId: "snap-1000-01",
    snapshotInputHash: "a".repeat(64),
  },
  hunt: {
    runId: "hunt-run-001",
    configHash: "b".repeat(64),
    resultHash: "c".repeat(64),
  },
  blastRadius: {
    riskScore: 88.5,
    impactedAssets: 14,
    crownJewelExposure: true,
  },
  containment: {
    planId: "contain-plan-001",
    actions: [
      { type: "ISOLATE_HOST", target: "host:ws-0014" },
      { type: "DISABLE_ACCOUNT", target: "user:it-admin-priv" },
    ],
    approvedAt: "2026-11-14T20:30:00.000Z",
    approvedById: "user-mgr-01",
    approvedByName: "Morgan Manager",
  },
  approval: {
    decision: "ISSUED",
    issuedById: "user-mgr-01",
    issuedByName: "Morgan Manager",
    issuedAt: "2026-11-14T20:35:00.000Z",
  },
};

test("canonical JSON is independent of object key insertion order", () => {
  assert.equal(
    canonicalJson({ z: 1, a: { y: true, x: false } }),
    canonicalJson({ a: { x: false, y: true }, z: 1 }),
  );
});

test("incident passport digest verifies the issued snapshot", () => {
  const secret = "test-signing-secret-at-least-32-chars-long";
  const passport = createIncidentPassport(sampleSnapshot, secret);
  assert.match(passport.passportHash, /^[a-f0-9]{64}$/);
  assert.equal(
    verifyIncidentPassportHash(passport.snapshot, passport.passportHash, secret),
    true,
  );
});

test("incident passport detects any single-field tampering", () => {
  const secret = "test-signing-secret-at-least-32-chars-long";
  const passport = createIncidentPassport(sampleSnapshot, secret);
  const tampered = {
    ...passport.snapshot,
    incident: {
      ...passport.snapshot.incident,
      severity: "LOW", // Tampered severity!
    },
  };
  assert.equal(
    verifyIncidentPassportHash(tampered, passport.passportHash, secret),
    false,
  );
});

test("incident passport is cryptographically bound to the signing secret", () => {
  const passport = createIncidentPassport(sampleSnapshot, "secret-one-at-least-32-chars-long-xxx");
  assert.equal(
    verifyIncidentPassportHash(passport.snapshot, passport.passportHash, "secret-two-at-least-32-chars-long-yyy"),
    false,
  );
});
