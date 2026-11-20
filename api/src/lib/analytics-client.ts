import "dotenv/config";

/** Base URL of the analytics service. Must be set via ANALYTICS_URL env var. */
const ANALYTICS_URL = process.env.ANALYTICS_URL ?? "http://localhost:8000";
const API_KEY = process.env.ANALYTICS_API_KEY ?? "";

class AnalyticsError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "AnalyticsError";
  }
}

async function analyticsPost<T>(path: string, body: unknown): Promise<T> {
  const url = `${ANALYTICS_URL}${path}`;
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Internal-Key": API_KEY,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "(no body)");
    throw new AnalyticsError(res.status, `Analytics ${path} failed: ${text}`);
  }

  return res.json() as Promise<T>;
}

async function analyticsGet<T>(path: string): Promise<T> {
  const url = `${ANALYTICS_URL}${path}`;
  const res = await fetch(url, {
    headers: { "X-Internal-Key": API_KEY },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "(no body)");
    throw new AnalyticsError(res.status, `Analytics GET ${path} failed: ${text}`);
  }

  return res.json() as Promise<T>;
}

// ─── Typed request / response shapes ─────────────────────────────────────────
// These are intentionally loose here; the FastAPI /openapi.json schema is the
// source of truth. Run `make generate` to regenerate strict types.

export type AnalyticsHealth = {
  status: string;
  model_mode: "onnx" | "tfidf_fallback";
  llm_mode: "gemini" | "rag_only";
};

export type NormaliseRequest = { events: unknown[]; label?: string };
export type GraphSnapshotResult = {
  node_count: number;
  edge_count: number;
  input_hash: string;
  graph_json: { nodes: unknown[]; edges: unknown[] };
};

export type HuntRunRequest = {
  graph_json: unknown;
  rules: unknown[];
  parameters?: Record<string, unknown>;
};
export type HuntLeadResult = {
  hunt_leads: unknown[];
  config_hash: string;
  result_hash: string;
};

export type PathsRequest = { graph_json: unknown; sources: string[]; targets: string[]; k?: number };
export type PathsResult = { paths: unknown[]; choke_points: unknown[] };

export type BlastRadiusRequest = {
  graph_json: unknown;
  seeds: string[];
  time_limit_hours?: number;
  cascade_seed?: number;
};
export type BlastRadiusResult = {
  impacted_nodes: unknown[];
  crown_jewel_exposure: boolean;
  risk_score: number;
  confidence_interval: [number, number];
  hop_layers: unknown[];
};

export type ContainmentPlanRequest = {
  graph_json: unknown;
  incident: unknown;
  budget: number;
};
export type ContainmentPlanResult = { actions: unknown[]; expected_reduction: number };

export type ContainmentSimulateRequest = {
  graph_json: unknown;
  seeds: string[];
  actions: unknown[];
};
export type ContainmentSimulateResult = { residual_blast_radius: unknown };

export type AlertCorrelateRequest = { alerts: unknown[]; graph_json: unknown };
export type AlertCorrelateResult = {
  clusters: unknown[];
  alert_reduction_ratio: number;
};

export type ReportPdfRequest = { incident: unknown };

export type CopilotRequest = {
  masked_query: string;
  incident_summary?: unknown;
};
export type CopilotResult = {
  narrative: string;
  mode: string;
  sources: string[];
  rag_hits: unknown[];
};

export type SyntheticRequest = {
  size: number;
  seed?: number;
  campaigns?: string[];
};
export type SyntheticResult = {
  graph_json: unknown;
  ground_truth: unknown;
  input_hash: string;
  node_count: number;
  edge_count: number;
};

// ─── API calls ────────────────────────────────────────────────────────────────

export const analyticsClient = {
  health: () => analyticsGet<AnalyticsHealth>("/health"),
  normalise: (body: NormaliseRequest) =>
    analyticsPost<GraphSnapshotResult>("/normalise", body),
  huntsRun: (body: HuntRunRequest) =>
    analyticsPost<HuntLeadResult>("/hunts/run", body),
  paths: (body: PathsRequest) =>
    analyticsPost<PathsResult>("/paths", body),
  blastRadius: (body: BlastRadiusRequest) =>
    analyticsPost<BlastRadiusResult>("/blast-radius", body),
  containmentPlan: (body: ContainmentPlanRequest) =>
    analyticsPost<ContainmentPlanResult>("/containment/plan", body),
  containmentSimulate: (body: ContainmentSimulateRequest) =>
    analyticsPost<ContainmentSimulateResult>("/containment/simulate", body),
  alertCorrelate: (body: AlertCorrelateRequest) =>
    analyticsPost<AlertCorrelateResult>("/alerts/correlate", body),
  reportPdf: (body: ReportPdfRequest) =>
    analyticsPost<Uint8Array>("/report/pdf", body),
  copilot: (body: CopilotRequest) =>
    analyticsPost<CopilotResult>("/copilot", body),
  syntheticGenerate: (body: SyntheticRequest) =>
    analyticsPost<SyntheticResult>("/synthetic/generate", body),
};

export { AnalyticsError };
