import assert from "node:assert/strict";
import test from "node:test";
import {
  sha256Text,
  sha256Json,
  createEvidenceReceiptId,
  huntConfigHash,
  ingestInputHash,
  type HuntConfiguration,
} from "../../src/lib/evidence-receipt.js";

test("sha256Text generates valid 64-char hex digest", () => {
  const hash = sha256Text("graphops-telemetry-payload");
  assert.match(hash, /^[a-f0-9]{64}$/);
});

test("createEvidenceReceiptId returns unique 64-char hex strings", () => {
  const id1 = createEvidenceReceiptId();
  const id2 = createEvidenceReceiptId();
  assert.equal(id1.length, 64);
  assert.equal(id2.length, 64);
  assert.notEqual(id1, id2);
});

test("huntConfigHash is deterministic regardless of ruleId order", () => {
  const configA: HuntConfiguration = {
    policyId: "pol-1",
    ruleIds: ["HUNT-LM-001", "HUNT-CR-001"],
    snapshotId: "snap-1",
    parameters: { timeWindowHours: 24 },
  };
  const configB: HuntConfiguration = {
    policyId: "pol-1",
    ruleIds: ["HUNT-CR-001", "HUNT-LM-001"],
    snapshotId: "snap-1",
    parameters: { timeWindowHours: 24 },
  };

  assert.equal(huntConfigHash(configA), huntConfigHash(configB));
});

test("ingestInputHash produces identical hash for equivalent json arrays", () => {
  const events = [
    { EventID: 1, Computer: "WS-01", User: "alice" },
    { EventID: 4624, Computer: "SRV-01", User: "bob" },
  ];
  assert.equal(ingestInputHash(events), ingestInputHash(events));
});
