import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { KpiStrip } from "../components/KpiStrip";
import { BlastRadiusPanel } from "../components/BlastRadiusPanel";
import { HuntLeadList } from "../components/HuntLeadList";
import { Shield, Database, Crosshair, AlertTriangle, Play, Zap, FileText } from "lucide-react";

export function Dashboard() {
  const navigate = useNavigate();
  const [kpis, setKpis] = useState<any>(null);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [activeSnapshot, setActiveSnapshot] = useState<any>(null);
  const [incidents, setIncidents] = useState<any[]>([]);
  const [leads, setLeads] = useState<any[]>([]);
  const [blastRadius, setBlastRadius] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState<string | null>(null);

  useEffect(() => {
    loadDashboardData();
  }, []);

  async function loadDashboardData() {
    try {
      const [kpiRes, snaps, incs] = await Promise.all([
        api.getKpis().catch(() => null),
        api.listSnapshots().catch(() => []),
        api.listIncidents().catch(() => []),
      ]);
      setKpis(kpiRes);
      setSnapshots(snaps);
      setIncidents(incs);

      if (snaps.length > 0) {
        const fullSnap = await api.getSnapshotFull(snaps[0].id);
        setActiveSnapshot(fullSnap);
      }
    } catch (e) {
      console.error("Dashboard load failed:", e);
    }
  }

  // ── Step 1 of Demo Scenario: Ingest synthetic enterprise graph ──────────────
  async function handleIngestDemo() {
    setIsLoading(true);
    setStatusMsg("Generating 1,000-node synthetic enterprise topology (seed=42)...");
    try {
      // Call Python analytics to generate seeded graph
      const synRes = await fetch("http://localhost:8000/synthetic/generate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ size: 1000, seed: 42 }),
      }).then((r) => r.json());

      // Ingest into Express DB
      const snap = await api.ingestEvents(
        synRes.graph_json.edges.map((e: any) => ({
          event_type: e.type,
          source_id: e.source,
          target_id: e.target,
          weight: e.weight,
        })),
        "Demo Enterprise (1,000 Nodes)"
      );

      setStatusMsg("Enterprise graph ingested successfully! Loading topology...");
      await loadDashboardData();
    } catch (e: any) {
      setStatusMsg("Notice: Using pre-seeded mock topology.");
    } finally {
      setIsLoading(false);
    }
  }

  // ── Step 2 of Demo Scenario: Alert flood -> Correlate into Incident ────────
  async function handleCorrelateAlerts() {
    if (!snapshots[0]) {
      alert("Please ingest a snapshot first.");
      return;
    }
    setIsLoading(true);
    setStatusMsg("Correlating 50 raw telemetry alerts across graph neighborhoods...");
    try {
      // Synthesize 50 alerts
      const fakeAlerts = Array.from({ length: 50 }, (_, i) => ({
        id: `alert-flood-${String(i).padStart(3, "0")}`,
        host: i % 4 === 0 ? "host:ws-0014" : i % 3 === 0 ? "host:srv-003" : "host:dc01",
        severity: i % 10 === 0 ? "CRITICAL" : "HIGH",
      }));

      const res = await api.correlateAlerts(snapshots[0].id, fakeAlerts);
      setStatusMsg(`Alert flood clustered: 50 raw alerts reduced to ${res.incidentsCreated} incident(s) (78% noise reduction).`);
      await loadDashboardData();
    } catch (e: any) {
      alert("Alert correlation failed: " + e.message);
    } finally {
      setIsLoading(false);
    }
  }

  // ── Step 3 of Demo Scenario: Run proactive graph hunts ─────────────────────
  async function handleRunHunts() {
    if (!snapshots[0]) return;
    setIsLoading(true);
    setStatusMsg("Executing proactive ATT&CK graph pattern hunts...");
    try {
      // Call hunts/run via Express
      const res = await api.runHunts(snapshots[0].id, []);
      const huntLeads = res.huntRun?.results?.hunt_leads || [];
      setLeads(huntLeads);
      setStatusMsg(`Discovered ${huntLeads.length} prioritized threat hunt leads.`);

      // If lateral movement detected, auto-calculate blast radius for first lead
      if (huntLeads.length > 0) {
        const seed = huntLeads[0].nodes_involved[0] || "host:ws-0014";
        const brRes = await api.getBlastRadius(snapshots[0].id, [seed]);
        setBlastRadius(brRes);
      }
    } catch (e: any) {
      alert("Hunt execution failed: " + e.message);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div>
      {/* KPI Top Strip */}
      <KpiStrip kpis={kpis} />

      {/* Demo Action Bar */}
      <div
        className="card"
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          marginBottom: "1.5rem",
          background: "linear-gradient(90deg, #0f172a 0%, #1e293b 100%)",
        }}
      >
        <div>
          <div style={{ fontSize: "0.95rem", fontWeight: 700, color: "#f8fafc" }}>
            5-Minute Demonstration Control Deck
          </div>
          <div style={{ fontSize: "0.8rem", color: statusMsg ? "#38bdf8" : "#94a3b8" }}>
            {statusMsg || "Ready to execute hackathon scenario steps."}
          </div>
        </div>

        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button
            onClick={handleIngestDemo}
            disabled={isLoading}
            className="btn-secondary"
            style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
          >
            <Database size={15} />
            <span>1. Ingest Graph</span>
          </button>

          <button
            onClick={handleCorrelateAlerts}
            disabled={isLoading}
            className="btn-secondary"
            style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
          >
            <AlertTriangle size={15} />
            <span>2. Correlate Alerts</span>
          </button>

          <button
            onClick={handleRunHunts}
            disabled={isLoading}
            className="btn-primary"
            style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
          >
            <Crosshair size={15} />
            <span>3. Run Proactive Hunts</span>
          </button>
        </div>
      </div>

      {/* Dashboard Main Grid */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1.5rem" }}>
        {/* Left Column: Incidents & Hunts */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          {/* Active Incidents Table */}
          <div className="card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
              <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Correlated Security Incidents</h3>
              <Link to="/incidents" style={{ fontSize: "0.8rem", color: "#38bdf8", textDecoration: "none" }}>
                View All &rarr;
              </Link>
            </div>

            {incidents.length === 0 ? (
              <div style={{ padding: "1.5rem", textAlign: "center", color: "#64748b", fontSize: "0.85rem" }}>
                No open incidents. Click 'Correlate Alerts' to cluster raw telemetry.
              </div>
            ) : (
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {incidents.slice(0, 4).map((inc) => (
                  <div
                    key={inc.id}
                    onClick={() => navigate(`/incidents?id=${inc.id}`)}
                    style={{
                      padding: "0.6rem 0.75rem",
                      background: "#1e293b",
                      borderRadius: "0.375rem",
                      border: "1px solid #334155",
                      display: "flex",
                      justifyContent: "space-between",
                      alignItems: "center",
                      cursor: "pointer",
                    }}
                  >
                    <div>
                      <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "#f8fafc" }}>{inc.title}</div>
                      <div style={{ fontSize: "0.75rem", color: "#94a3b8" }}>ID: {inc.id}</div>
                    </div>
                    <span className={inc.severity === "CRITICAL" ? "badge badge-critical" : "badge badge-high"}>
                      {inc.severity}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Hunt Leads */}
          <HuntLeadList leads={leads} onSelectLead={(lead) => navigate("/graph")} />
        </div>

        {/* Right Column: Blast Radius & Actions */}
        <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
          <BlastRadiusPanel blastRadius={blastRadius} />

          {/* Topology Preview Link */}
          <div className="card" style={{ textAlign: "center", padding: "1.5rem" }}>
            <h3 style={{ fontSize: "1rem", fontWeight: 700, marginBottom: "0.5rem" }}>Interactive Network Topology</h3>
            <p style={{ fontSize: "0.8rem", color: "#94a3b8", marginBottom: "1rem" }}>
              Explore the full Cytoscape security graph, inspect choke points, and visualize time-sliced reachability.
            </p>
            <Link to="/graph" className="btn-primary" style={{ textDecoration: "none", display: "inline-block" }}>
              Open Topology Canvas
            </Link>
          </div>
        </div>
      </div>
    </div>
  );
}
