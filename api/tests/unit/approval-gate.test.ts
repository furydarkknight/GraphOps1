import assert from "node:assert/strict";
import test from "node:test";
import {
  evaluateApprovalGate,
  getApprovalGateError,
  formatApproverDecisionNote,
  MIN_OVERRIDE_LENGTH,
  type GateFinding,
} from "../../src/lib/approval-gate.js";

test("empty findings list produces READY gate", () => {
  const gate = evaluateApprovalGate([]);
  assert.equal(gate.status, "READY");
  assert.equal(getApprovalGateError(gate), null);
});

test("hard-stop rule codes produce BLOCKED status that cannot be overridden", () => {
  const findings: GateFinding[] = [
    {
      severity: "CRITICAL",
      category: "INTEGRITY",
      ruleCode: "MISSING_INCIDENT_ID",
      title: "Incident ID is missing or invalid",
    },
  ];
  const gate = evaluateApprovalGate(findings);
  assert.equal(gate.status, "BLOCKED");
  assert.equal(gate.hardStops.length, 1);
  const err = getApprovalGateError(gate, "A very long override note that should not bypass hard stops.");
  assert.match(err!, /hard-stop issue\(s\) that cannot be overridden/i);
});

test("CRITICAL findings require minimum human override note", () => {
  const findings: GateFinding[] = [
    {
      severity: "CRITICAL",
      category: "CONTAINMENT",
      ruleCode: "DC_DISRUPTION_RISK",
      title: "Isolating Domain Controller may cause widespread auth failures",
    },
  ];
  const gate = evaluateApprovalGate(findings);
  assert.equal(gate.status, "REQUIRES_OVERRIDE");

  // Short override fails
  assert.match(
    getApprovalGateError(gate, "Too short")!,
    /at least 20 characters/i,
  );

  // Sufficient override passes
  assert.equal(
    getApprovalGateError(gate, "Approved exception: secondary backup domain controller DC-02 is operational and taking traffic."),
    null,
  );
});

test("formatApproverDecisionNote logs approver and overridden rules", () => {
  const gate = evaluateApprovalGate([
    {
      severity: "CRITICAL",
      category: "CONTAINMENT",
      ruleCode: "RISK-01",
      title: "Risk title",
    },
  ]);
  const note = formatApproverDecisionNote(gate, "Business critical operation", "Morgan Manager");
  assert.match(note, /Approver: Morgan Manager/);
  assert.match(note, /RISK-01/);
  assert.match(note, /Business critical operation/);
});
