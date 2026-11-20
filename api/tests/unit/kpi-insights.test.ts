import assert from "node:assert/strict";
import test from "node:test";
import {
  buildKpiInsights,
  type ExceptionRequestRecord,
} from "../../src/lib/kpi-insights.js";

test("aggregates containment exception reasons and decision outcomes", () => {
  const requests: ExceptionRequestRecord[] = [
    {
      id: "req-1",
      exceptionReason: "BUSINESS_CRITICAL",
      decisionNote: "Production ERP server cannot be isolated during month-end closing",
      status: "APPROVED",
    },
    {
      id: "req-2",
      exceptionReason: "BUSINESS_CRITICAL",
      decisionNote: "Payroll processing ongoing",
      status: "APPROVED",
    },
    {
      id: "req-3",
      exceptionReason: "FALSE_POSITIVE",
      decisionNote: "Scheduled vulnerability scanner",
      status: "REJECTED",
    },
    {
      id: "req-4",
      exceptionReason: "RULE_INCORRECT",
      decisionNote: "Pending review",
      status: "PENDING",
    },
  ];

  const insights = buildKpiInsights(requests);
  assert.equal(insights.totalExceptions, 4);
  assert.equal(insights.approved, 2);
  assert.equal(insights.rejected, 1);
  assert.equal(insights.pending, 1);

  const bizCrit = insights.categories.find((c) => c.category === "BUSINESS_CRITICAL");
  assert.ok(bizCrit);
  assert.equal(bizCrit.total, 2);
  assert.equal(bizCrit.approved, 2);
});
