/**
 * GraphOps Frontend API Client.
 * Handles authenticated communication with the Express backend gateway.
 */

const API_BASE = "";

function getAuthHeaders(): HeadersInit {
  const token = localStorage.getItem("graphops_token");
  return {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      ...getAuthHeaders(),
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    const errorJson = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error(errorJson.error || `Request failed with status ${res.status}`);
  }

  // Handle PDF / binary blob responses
  const contentType = res.headers.get("content-type");
  if (contentType && contentType.includes("application/pdf")) {
    const blob = await res.blob();
    return blob as unknown as T;
  }

  return res.json();
}

export const api = {
  // Auth
  login: (credentials: { email: string; password: string }) =>
    apiRequest<{ token: string; user: any }>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify(credentials),
    }),
  getMe: () => apiRequest<any>("/api/auth/me"),

  // Health
  getHealth: () => apiRequest<any>("/api/health"),

  // Ingest & Snapshots
  ingestEvents: (events: any[], label?: string) =>
    apiRequest<any>("/api/ingest", {
      method: "POST",
      body: JSON.stringify({ events, label }),
    }),
  listSnapshots: () => apiRequest<any[]>("/api/graph"),
  getSnapshotFull: (id: string) => apiRequest<any>(`/api/graph/${id}/full`),

  // Hunts
  listHuntRules: () => apiRequest<any[]>("/api/hunts"),
  runHunts: (snapshotId: string, ruleIds: string[]) =>
    apiRequest<any>("/api/hunts/run", {
      method: "POST",
      body: JSON.stringify({ snapshotId, ruleIds }),
    }),

  // Paths & Blast Radius
  getAttackPaths: (snapshotId: string, sources: string[], targets: string[]) =>
    apiRequest<any>("/api/paths", {
      method: "POST",
      body: JSON.stringify({ snapshotId, sources, targets }),
    }),
  getBlastRadius: (snapshotId: string, seeds: string[]) =>
    apiRequest<any>("/api/blast-radius", {
      method: "POST",
      body: JSON.stringify({ snapshotId, seeds }),
    }),

  // Containment
  planContainment: (incidentId: string, budget?: number) =>
    apiRequest<any>("/api/containment/plan", {
      method: "POST",
      body: JSON.stringify({ incidentId, budget }),
    }),
  simulateContainment: (incidentId: string, actions: any[]) =>
    apiRequest<any>("/api/containment/simulate", {
      method: "POST",
      body: JSON.stringify({ incidentId, actions }),
    }),
  approveContainment: (planId: string, decision: "APPROVED" | "REJECTED", note?: string) =>
    apiRequest<any>(`/api/containment/${planId}/approve`, {
      method: "PATCH",
      body: JSON.stringify({ decision, decisionNote: note || "Approved by SOC Manager" }),
    }),

  // Incidents
  listIncidents: () => apiRequest<any[]>("/api/incidents"),
  getIncident: (id: string) => apiRequest<any>(`/api/incidents/${id}`),
  createIncident: (payload: { title: string; snapshotId: string; severity?: string }) =>
    apiRequest<any>("/api/incidents", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  correlateAlerts: (snapshotId: string, alerts: any[]) =>
    apiRequest<any>("/api/alerts/correlate", {
      method: "POST",
      body: JSON.stringify({ snapshotId, alerts }),
    }),

  // Passport & PDF Report
  issuePassport: (incidentId: string) =>
    apiRequest<any>("/api/passport", {
      method: "POST",
      body: JSON.stringify({ incidentId }),
    }),
  verifyPassport: (id: string) =>
    apiRequest<any>(`/api/passport/${id}/verify`),
  downloadReportPdf: (incidentId: string) =>
    apiRequest<Blob>("/api/report", {
      method: "POST",
      body: JSON.stringify({ incidentId }),
    }),

  // Copilot & KPIs
  queryCopilot: (query: string, incidentSummary?: any) =>
    apiRequest<any>("/api/copilot", {
      method: "POST",
      body: JSON.stringify({ query, incidentSummary }),
    }),
  getKpis: () => apiRequest<any>("/api/kpi"),
};
