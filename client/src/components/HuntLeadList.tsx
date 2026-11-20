import { useState } from "react";
import { Crosshair, ChevronDown, ChevronUp, AlertCircle, Eye } from "lucide-react";

interface HuntLeadListProps {
  leads: any[];
  onSelectLead?: (lead: any) => void;
  isLoading?: boolean;
}

export function HuntLeadList({ leads, onSelectLead, isLoading }: HuntLeadListProps) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (isLoading) {
    return <div className="card" style={{ textAlign: "center", padding: "2rem" }}>Running proactive graph hunts...</div>;
  }

  if (!leads || leads.length === 0) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "1.5rem", color: "#64748b" }}>
        No proactive hunt leads generated. Run hunts against an active snapshot.
      </div>
    );
  }

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Crosshair size={18} color="#38bdf8" />
          <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Proactive Threat Hunt Leads ({leads.length})</h3>
        </div>
        <span style={{ fontSize: "0.75rem", color: "#94a3b8" }}>Ranked by Descending Risk Score</span>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem", maxHeight: "450px", overflowY: "auto" }}>
        {leads.map((lead) => {
          const isExpanded = expandedId === lead.id;
          return (
            <div
              key={lead.id}
              style={{
                background: "#1e293b",
                border: "1px solid #334155",
                borderRadius: "0.375rem",
                padding: "0.75rem",
              }}
            >
              <div
                style={{ display: "flex", justifyContent: "space-between", alignItems: "center", cursor: "pointer" }}
                onClick={() => setExpandedId(isExpanded ? null : lead.id)}
              >
                <div>
                  <div style={{ display: "flex", alignItems: "center", gap: "0.4rem", marginBottom: "0.2rem" }}>
                    <span className="badge badge-critical" style={{ fontSize: "0.65rem" }}>
                      {lead.attack_id || "MITRE"}
                    </span>
                    <span style={{ fontSize: "0.85rem", fontWeight: 700, color: "#f8fafc" }}>
                      {lead.title}
                    </span>
                  </div>
                  <div style={{ fontSize: "0.75rem", color: "#94a3b8" }}>
                    Rule: <b style={{ color: "#cbd5e1" }}>{lead.rule_code}</b> | Tactic: {lead.tactic}
                  </div>
                </div>

                <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                  <span
                    className={
                      lead.score >= 85 ? "badge badge-critical" : lead.score >= 70 ? "badge badge-high" : "badge badge-medium"
                    }
                  >
                    Score: {lead.score}
                  </span>
                  {isExpanded ? <ChevronUp size={16} color="#94a3b8" /> : <ChevronDown size={16} color="#94a3b8" />}
                </div>
              </div>

              {isExpanded && (
                <div style={{ marginTop: "0.75rem", paddingTop: "0.75rem", borderTop: "1px solid #334155", fontSize: "0.8rem" }}>
                  <div style={{ marginBottom: "0.5rem" }}>
                    <b style={{ color: "#38bdf8" }}>Evidence:</b>
                    <p style={{ color: "#cbd5e1", marginTop: "0.2rem", lineHeight: 1.4 }}>{lead.evidence}</p>
                  </div>

                  <div style={{ marginBottom: "0.75rem" }}>
                    <b style={{ color: "#f59e0b" }}>Mitigation Suggestion:</b>
                    <p style={{ color: "#e2e8f0", marginTop: "0.2rem" }}>{lead.mitigation_suggestion}</p>
                  </div>

                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                    <span style={{ fontSize: "0.75rem", color: "#64748b" }}>
                      {lead.nodes_involved?.length || 0} nodes involved
                    </span>
                    {onSelectLead && (
                      <button
                        onClick={() => onSelectLead(lead)}
                        className="btn-primary"
                        style={{ padding: "0.3rem 0.6rem", fontSize: "0.75rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
                      >
                        <Eye size={13} />
                        <span>Inspect On Graph</span>
                      </button>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
