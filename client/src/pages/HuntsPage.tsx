import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { HuntLeadList } from "../components/HuntLeadList";
import { Crosshair, Play, CheckCircle } from "lucide-react";

export function HuntsPage() {
  const [rules, setRules] = useState<any[]>([]);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string>("");
  const [leads, setLeads] = useState<any[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const [runReceipt, setRunReceipt] = useState<string | null>(null);

  useEffect(() => {
    Promise.all([
      api.listHuntRules().catch(() => []),
      api.listSnapshots().catch(() => []),
    ]).then(([r, s]) => {
      setRules(r);
      setSnapshots(s);
      if (s.length > 0) setSelectedSnapshotId(s[0].id);
    });
  }, []);

  async function handleRunHunts() {
    if (!selectedSnapshotId) return;
    setIsLoading(true);
    setRunReceipt(null);
    try {
      const res = await api.runHunts(selectedSnapshotId, rules.map((r) => r.id));
      setLeads(res.huntRun?.results?.hunt_leads || []);
      setRunReceipt(res.evidenceReceiptId);
    } catch (e: any) {
      alert("Hunt run failed: " + e.message);
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 800 }}>Proactive ATT&CK Threat Hunting</h2>
          <p style={{ color: "#94a3b8", fontSize: "0.85rem" }}>
            Execute deterministic graph pattern detectors across lateral movement, credential abuse, and C2 beacons.
          </p>
        </div>

        <div style={{ display: "flex", gap: "0.75rem" }}>
          {snapshots.length > 0 && (
            <select
              value={selectedSnapshotId}
              onChange={(e) => setSelectedSnapshotId(e.target.value)}
              style={{
                background: "#1e293b",
                border: "1px solid #334155",
                color: "#f8fafc",
                padding: "0.4rem 0.75rem",
                borderRadius: "0.375rem",
                fontSize: "0.85rem",
              }}
            >
              {snapshots.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.label} ({s.nodeCount} nodes)
                </option>
              ))}
            </select>
          )}

          <button
            onClick={handleRunHunts}
            disabled={isLoading || !selectedSnapshotId}
            className="btn-primary"
            style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
          >
            <Play size={16} />
            <span>{isLoading ? "Executing Graph Hunts..." : "Run Active Hunt Rules"}</span>
          </button>
        </div>
      </div>

      {runReceipt && (
        <div
          style={{
            padding: "0.75rem",
            background: "rgba(16, 185, 129, 0.15)",
            border: "1px solid rgba(16, 185, 129, 0.4)",
            borderRadius: "0.375rem",
            color: "#6ee7b7",
            fontSize: "0.85rem",
            display: "flex",
            alignItems: "center",
            gap: "0.5rem",
          }}
        >
          <CheckCircle size={18} />
          <span>Cryptographic Evidence Receipt Recorded: <code>{runReceipt}</code></span>
        </div>
      )}

      {/* Leads Table */}
      <HuntLeadList leads={leads} />
    </div>
  );
}
