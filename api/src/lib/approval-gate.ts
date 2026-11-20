// ─── Approval gate (ported from BrandFlight release-gate.ts) ─────────────────
// Controls whether a containment plan can be approved without override, needs a
// human override justification, or is hard-blocked.

export type GateFinding = {
  severity: "CRITICAL" | "HIGH";
  category: string;
  ruleCode: string;
  title: string;
};

export type ApprovalGateStatus =
  | "READY"
  | "REQUIRES_OVERRIDE"
  | "BLOCKED";

export type ApprovalGate = {
  status: ApprovalGateStatus;
  hardStops: GateFinding[];
  highRiskFindings: GateFinding[];
  warnings: GateFinding[];
};

/** Hard-stop rule codes — these cannot be overridden by any role. */
const HARD_STOP_CODES = new Set([
  "MISSING_INCIDENT_ID",
  "UNVERIFIED_PASSPORT",
]);

export function evaluateApprovalGate(findings: GateFinding[]): ApprovalGate {
  const hardStops = findings.filter((f) => HARD_STOP_CODES.has(f.ruleCode));
  const highRisk = findings.filter(
    (f) => !HARD_STOP_CODES.has(f.ruleCode) && f.severity === "CRITICAL",
  );
  const warnings = findings.filter((f) => f.severity === "HIGH");

  const status: ApprovalGateStatus =
    hardStops.length > 0
      ? "BLOCKED"
      : highRisk.length > 0
        ? "REQUIRES_OVERRIDE"
        : "READY";

  return { status, hardStops, highRiskFindings: highRisk, warnings };
}

export const MIN_OVERRIDE_LENGTH = 20;

/** Returns null if the override justification is acceptable; an error message if not. */
export function getApprovalGateError(
  gate: ApprovalGate,
  overrideNote?: string,
): string | null {
  if (gate.status === "BLOCKED") {
    return `This plan has ${gate.hardStops.length} hard-stop issue(s) that cannot be overridden: ${gate.hardStops.map((s) => s.title).join(", ")}.`;
  }
  if (gate.status === "REQUIRES_OVERRIDE") {
    const note = overrideNote?.trim() ?? "";
    if (note.length < MIN_OVERRIDE_LENGTH) {
      return `A justification of at least ${MIN_OVERRIDE_LENGTH} characters is required to override high-risk findings.`;
    }
  }
  return null;
}

export function formatApproverDecisionNote(
  gate: ApprovalGate,
  note: string,
  approverName: string,
): string {
  const lines: string[] = [
    `APPROVAL DECISION`,
    `Approver: ${approverName}`,
    `Gate status: ${gate.status}`,
  ];
  if (gate.highRiskFindings.length > 0) {
    lines.push(
      `High-risk findings overridden: ${gate.highRiskFindings.map((f) => f.ruleCode).join(", ")}`,
    );
  }
  if (note.trim()) lines.push(`Note: ${note.trim()}`);
  return lines.join("\n");
}
