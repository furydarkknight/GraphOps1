import { ShieldAlert, AlertCircle, Activity, ChevronRight } from "lucide-react";

interface BlastRadiusPanelProps {
  blastRadius: any | null;
  isLoading?: boolean;
}

export function BlastRadiusPanel({ blastRadius, isLoading }: BlastRadiusPanelProps) {
  if (isLoading) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "2rem" }}>
        <div style={{ color: "#38bdf8", fontWeight: 600 }}>Computing Independent Cascade Blast Radius...</div>
      </div>
    );
  }

  if (!blastRadius) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "1.5rem", color: "#64748b" }}>
        Select a seed node to simulate forward reachability and blast radius.
      </div>
    );
  }

  const ci = blastRadius.confidence_interval || [0, 0];
  const isCjHit = blastRadius.crown_jewel_exposure;

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Activity size={18} color="#f43f5e" />
          <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Blast Radius Assessment</h3>
        </div>
        <span
          className={
            blastRadius.risk_score >= 75
              ? "badge badge-critical"
              : blastRadius.risk_score >= 50
              ? "badge badge-high"
              : "badge badge-medium"
          }
        >
          Risk: {blastRadius.risk_score} / 100
        </span>
      </div>

      {/* Metrics Row */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.75rem" }}>
        <div style={{ background: "#1e293b", padding: "0.75rem", borderRadius: "0.375rem" }}>
          <div style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Expected Assets Impacted</div>
          <div style={{ fontSize: "1.3rem", fontWeight: 700, color: "#f8fafc" }}>
            {blastRadius.expected_impacted_assets}
          </div>
          <div style={{ fontSize: "0.7rem", color: "#64748b" }}>95% CI: [{ci[0]} - {ci[1]}]</div>
        </div>

        <div style={{ background: "#1e293b", padding: "0.75rem", borderRadius: "0.375rem" }}>
          <div style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Crown Jewel Exposure</div>
          <div style={{ fontSize: "1.1rem", fontWeight: 700, color: isCjHit ? "#f87171" : "#34d399", display: "flex", alignItems: "center", gap: "0.3rem" }}>
            {isCjHit ? <ShieldAlert size={18} /> : null}
            <span>{isCjHit ? "EXPOSED (CRITICAL)" : "SECURE"}</span>
          </div>
          <div style={{ fontSize: "0.7rem", color: "#64748b" }}>
            Prob: {Math.round((blastRadius.crown_jewel_compromise_probability || 0) * 100)}%
          </div>
        </div>
      </div>

      {/* Hop layers */}
      <div>
        <h4 style={{ fontSize: "0.85rem", fontWeight: 600, color: "#cbd5e1", marginBottom: "0.5rem" }}>
          Hop-by-Hop Reachability Layers:
        </h4>
        <div style={{ display: "flex", flexDirection: "column", gap: "0.4rem", maxHeight: "180px", overflowY: "auto" }}>
          {(blastRadius.hop_layers || []).map((layer: any) => (
            <div
              key={layer.hop}
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                padding: "0.4rem 0.6rem",
                background: "#090d16",
                borderRadius: "0.25rem",
                fontSize: "0.8rem",
                borderLeft: layer.hop === 0 ? "3px solid #38bdf8" : "3px solid #f43f5e",
              }}
            >
              <span>Hop {layer.hop}: {layer.hop === 0 ? "Seed Infection" : `Layer +${layer.hop}`}</span>
              <span style={{ fontWeight: 600, color: "#94a3b8" }}>{layer.nodes?.length || 0} assets</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
