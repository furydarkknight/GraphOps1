import { X, ShieldAlert, Zap, Network, Lock } from "lucide-react";

interface NodeDrawerProps {
  node: any | null;
  onClose: () => void;
  onCalculateBlastRadius: (nodeId: string) => void;
  onFindPaths: (nodeId: string) => void;
}

export function NodeDrawer({ node, onClose, onCalculateBlastRadius, onFindPaths }: NodeDrawerProps) {
  if (!node) return null;

  return (
    <div
      style={{
        position: "absolute",
        top: "1rem",
        right: "1rem",
        width: "340px",
        background: "#0f172a",
        border: "1px solid #334155",
        borderRadius: "0.5rem",
        boxShadow: "0 20px 25px -5px rgba(0, 0, 0, 0.5)",
        zIndex: 40,
        padding: "1.25rem",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "0.75rem" }}>
        <div>
          <span style={{ fontSize: "0.75rem", textTransform: "uppercase", color: "#38bdf8", fontWeight: 600 }}>
            {node.type || "Node"}
          </span>
          <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f8fafc" }}>{node.label || node.id}</h3>
        </div>
        <button
          onClick={onClose}
          style={{ background: "transparent", border: "none", color: "#94a3b8", cursor: "pointer" }}
        >
          <X size={18} />
        </button>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem", marginBottom: "1.25rem" }}>
        {node.is_crown_jewel && (
          <div
            style={{
              padding: "0.4rem 0.6rem",
              background: "rgba(220, 38, 38, 0.2)",
              border: "1px solid rgba(220, 38, 38, 0.5)",
              borderRadius: "0.375rem",
              color: "#fca5a5",
              fontSize: "0.8rem",
              fontWeight: 600,
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
          >
            <ShieldAlert size={16} />
            <span>Crown Jewel Asset (Tier-0 Target)</span>
          </div>
        )}

        <div style={{ background: "#1e293b", padding: "0.6rem", borderRadius: "0.375rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
            <span style={{ color: "#94a3b8" }}>Criticality Score:</span>
            <span style={{ fontWeight: 700, color: node.criticality >= 8 ? "#f87171" : "#38bdf8" }}>
              {node.criticality || 5} / 10
            </span>
          </div>
          <div style={{ height: "6px", background: "#334155", borderRadius: "3px", overflow: "hidden" }}>
            <div
              style={{
                height: "100%",
                width: `${(node.criticality || 5) * 10}%`,
                background: node.criticality >= 8 ? "#ef4444" : "#38bdf8",
              }}
            />
          </div>
        </div>

        <div style={{ fontSize: "0.8rem", color: "#94a3b8" }}>
          <div><b style={{ color: "#cbd5e1" }}>Node ID:</b> {node.id}</div>
          {node.properties?.ip && <div><b style={{ color: "#cbd5e1" }}>IP Address:</b> {node.properties.ip}</div>}
          {node.properties?.subnet && <div><b style={{ color: "#cbd5e1" }}>Subnet:</b> {node.properties.subnet}</div>}
        </div>
      </div>

      {/* Action shortcuts */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <button
          onClick={() => onCalculateBlastRadius(node.id)}
          className="btn-primary"
          style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", fontSize: "0.85rem" }}
        >
          <Zap size={16} />
          <span>Simulate Blast Radius</span>
        </button>
        <button
          onClick={() => onFindPaths(node.id)}
          className="btn-secondary"
          style={{ display: "flex", alignItems: "center", justifyContent: "center", gap: "0.5rem", fontSize: "0.85rem" }}
        >
          <Network size={16} />
          <span>Trace Attack Paths</span>
        </button>
      </div>
    </div>
  );
}
