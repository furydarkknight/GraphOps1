import { Network, Zap, Target } from "lucide-react";

interface AttackPathViewProps {
  pathsData: any | null;
  onSelectPath?: (nodes: string[]) => void;
  isLoading?: boolean;
}

export function AttackPathView({ pathsData, onSelectPath, isLoading }: AttackPathViewProps) {
  if (isLoading) {
    return <div className="card" style={{ textAlign: "center", padding: "1.5rem" }}>Tracing attack paths to crown jewels...</div>;
  }

  if (!pathsData || !pathsData.paths || pathsData.paths.length === 0) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "1.5rem", color: "#64748b" }}>
        No viable attack paths discovered to registered crown jewels.
      </div>
    );
  }

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Network size={18} color="#f97316" />
          <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Attack Paths & Choke Points</h3>
        </div>
        <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{pathsData.paths.length} Top Paths</span>
      </div>

      {/* Choke points strip */}
      {pathsData.choke_points && pathsData.choke_points.length > 0 && (
        <div style={{ background: "#1e293b", padding: "0.75rem", borderRadius: "0.375rem" }}>
          <div style={{ fontSize: "0.75rem", fontWeight: 700, color: "#f87171", marginBottom: "0.4rem", display: "flex", alignItems: "center", gap: "0.3rem" }}>
            <Zap size={14} />
            <span>Structural Choke Points (Highest Traffic Convergence):</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
            {pathsData.choke_points.map((cp: any) => (
              <div key={cp.node_id} style={{ display: "flex", justifyContent: "space-between", fontSize: "0.75rem" }}>
                <span style={{ color: "#cbd5e1" }}><b>{cp.label}</b> ({cp.node_id})</span>
                <span style={{ color: "#f59e0b", fontWeight: 600 }}>Traversed by {cp.paths_count} paths</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Path List */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", maxHeight: "250px", overflowY: "auto" }}>
        {pathsData.paths.map((p: any) => (
          <div
            key={p.path_id}
            style={{
              padding: "0.6rem 0.75rem",
              background: "#090d16",
              borderRadius: "0.375rem",
              border: "1px solid #1e293b",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <div style={{ fontSize: "0.8rem", fontWeight: 600, color: "#f8fafc", marginBottom: "0.15rem" }}>
                {p.path_id}: {p.hops} hops ({p.source} &rarr; {p.target})
              </div>
              <div style={{ fontSize: "0.7rem", color: "#64748b" }}>
                Risk Score: <b style={{ color: "#ef4444" }}>{p.risk_score}</b> | Route: {p.nodes.join(" &rarr; ")}
              </div>
            </div>

            {onSelectPath && (
              <button
                onClick={() => onSelectPath(p.nodes)}
                className="btn-secondary"
                style={{ padding: "0.25rem 0.5rem", fontSize: "0.75rem" }}
              >
                Highlight
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
