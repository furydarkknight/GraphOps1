// ─── SOC KPI Insights (ported from BrandFlight governance-insights.ts) ───────
// Aggregates containment exception requests by reason category, decision
// outcome and recurring rule references. Used by SOC_MANAGER dashboard.

export const EXCEPTION_REASON_CATEGORIES = [
  "BUSINESS_CRITICAL",
  "RULE_INCORRECT",
  "ACCEPTABLE_RISK",
  "FALSE_POSITIVE",
] as const;

export type ExceptionReasonCategory =
  (typeof EXCEPTION_REASON_CATEGORIES)[number];
export type ExceptionDecisionOutcome = "APPROVED" | "REJECTED";

export interface ExceptionRequestRecord {
  id: string;
  exceptionReason: string | null;
  decisionNote: string | null;
  status: string;
}

export type ExceptionInsightCategory =
  | ExceptionReasonCategory
  | "UNCATEGORIZED";

export interface ExceptionInsightBucket {
  category: ExceptionInsightCategory;
  total: number;
  pending: number;
  approved: number;
  rejected: number;
}

export interface ExceptionRuleInsight {
  ruleCode: string;
  total: number;
  approved: number;
  rejected: number;
}

export interface KpiInsights {
  totalExceptions: number;
  pending: number;
  approved: number;
  rejected: number;
  categories: ExceptionInsightBucket[];
  topRules: ExceptionRuleInsight[];
  recurringRuleThreshold: number;
  // SOC-specific KPIs (populated from incident data externally)
  mttdMinutes?: number;
  mttrMinutes?: number;
  alertReductionRatio?: number;
  assetsProtected?: number;
}

const RECURRING_RULE_THRESHOLD = 2;

export function buildKpiInsights(
  requests: ExceptionRequestRecord[],
): KpiInsights {
  const buckets = new Map<ExceptionInsightCategory, ExceptionInsightBucket>();

  const allCategories: ExceptionInsightCategory[] = [
    ...EXCEPTION_REASON_CATEGORIES,
    "UNCATEGORIZED",
  ];
  for (const cat of allCategories) {
    buckets.set(cat, { category: cat, total: 0, pending: 0, approved: 0, rejected: 0 });
  }

  let totalPending = 0;
  let totalApproved = 0;
  let totalRejected = 0;
  const ruleCounts = new Map<
    string,
    { total: number; approved: number; rejected: number }
  >();

  for (const req of requests) {
    const cat: ExceptionInsightCategory =
      req.exceptionReason &&
      EXCEPTION_REASON_CATEGORIES.includes(
        req.exceptionReason as ExceptionReasonCategory,
      )
        ? (req.exceptionReason as ExceptionReasonCategory)
        : "UNCATEGORIZED";

    const bucket = buckets.get(cat)!;
    bucket.total++;

    const isApproved = req.status === "APPROVED";
    const isRejected = req.status === "REJECTED";

    if (isApproved) { bucket.approved++; totalApproved++; }
    else if (isRejected) { bucket.rejected++; totalRejected++; }
    else { bucket.pending++; totalPending++; }
  }

  return {
    totalExceptions: requests.length,
    pending: totalPending,
    approved: totalApproved,
    rejected: totalRejected,
    categories: [...buckets.values()],
    topRules: [...ruleCounts.entries()]
      .filter(([, v]) => v.total >= RECURRING_RULE_THRESHOLD)
      .map(([ruleCode, v]) => ({ ruleCode, ...v }))
      .sort((a, b) => b.total - a.total),
    recurringRuleThreshold: RECURRING_RULE_THRESHOLD,
  };
}
