import { useState } from "react";
import { Lock, Play, CheckCircle, AlertOctagon, ArrowDownRight, ShieldCheck } from "lucide-react";
import { useAuth } from "../lib/auth";

interface ContainmentPanelProps {
  plan: any | null;
  onSimulate: (actions: any[]) => Promise<any>;
  onApprove: (planId: string, note: string) => Promise<void>;
  isLoading?: boolean;
}

export function ContainmentPanel({ plan, onSimulate, onApprove, isLoading }: ContainmentPanelProps) {
  const { user } = useAuth();
  const [simulationResult, setSimulationResult] = useState<any>(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [decisionNote, setDecisionNote] = useState("Approved containment actions to halt lateral progression to Domain Controller.");
  const [isApproving, setIsApproving] = useState(false);

  if (isLoading) {
    return <div className="card" style={{ textAlign: "center", padding: "2rem" }}>Generating optimized containment plan...</div>;
  }

  if (!plan) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "1.5rem", color: "#64748b" }}>
        No active containment plan. Propose containment actions from an incident.
      </div>
    );
  }

  const actions = plan.actions || [];
  const isManager = user?.role === "SOC_MANAGER";

  async function handleSimulate() {
    setIsSimulating(true);
    try {
      const res = await onSimulate(actions);
      setSimulationResult(res);
    } catch (e: any) {
      alert("Simulation failed: " + e.message);
    } finally {
      setIsSimulating(false);
    }
  }

  async function handleApprove() {
    setIsApproving(true);
    try {
      await onApprove(plan.id, decisionNote);
    } catch (e: any) {
      alert("Approval failed: " + e.message);
    } finally {
      setIsApproving(false);
    }
  }

  return (
    <div className="card" style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <Lock size={18} color="#a855f7" />
          <h3 style={{ fontSize: "1rem", fontWeight: 700 }}>Containment Optimizer & Simulator</h3>
        </div>
        <span className={plan.status === "APPROVED" ? "badge badge-low" : "badge badge-high"}>
          Status: {plan.status}
        </span>
      </div>

      {/* Actions Table */}
      <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
        <h4 style={{ fontSize: "0.85rem", fontWeight: 600, color: "#cbd5e1" }}>
          Proposed Containment Actions ({actions.length}):
        </h4>
        {actions.map((act: any, idx: number) => (
          <div
            key={idx}
            style={{
              padding: "0.6rem 0.75rem",
              background: "#1e293b",
              borderRadius: "0.375rem",
              border: "1px solid #334155",
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <div>
              <div style={{ fontSize: "0.85rem", fontWeight: 600, color: "#f8fafc" }}>
                {act.action_type || act.type} &rarr; <span style={{ color: "#38bdf8" }}>{act.target}</span>
              </div>
              <div style={{ fontSize: "0.75rem", color: "#94a3b8" }}>{act.description}</div>
            </div>
            <div style={{ textAlign: "right", fontSize: "0.75rem" }}>
              <div style={{ color: "#f59e0b" }}>Cost: {act.disruption_cost || 15}</div>
              <div style={{ color: "#10b981" }}>Benefit: +{act.expected_benefit || 40}</div>
            </div>
          </div>
        ))}
      </div>

      {/* What-if Simulator Toggle */}
      <div style={{ background: "#090d16", padding: "0.85rem", borderRadius: "0.375rem", border: "1px solid #1e293b" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.5rem" }}>
          <span style={{ fontSize: "0.85rem", fontWeight: 600, color: "#f8fafc" }}>
            What-If Simulator (Residual Blast Radius)
          </span>
          <button
            onClick={handleSimulate}
            disabled={isSimulating}
            className="btn-secondary"
            style={{ padding: "0.3rem 0.75rem", fontSize: "0.75rem", display: "flex", alignItems: "center", gap: "0.3rem" }}
          >
            <Play size={14} />
            <span>{isSimulating ? "Simulating..." : "Run What-If Simulation"}</span>
          </button>
        </div>

        {simulationResult && (
          <div style={{ marginTop: "0.75rem", paddingTop: "0.75rem", borderTop: "1px solid #1e293b" }}>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr 1fr", gap: "0.5rem", textAlign: "center" }}>
              <div style={{ background: "#1e293b", padding: "0.5rem", borderRadius: "0.25rem" }}>
                <div style={{ fontSize: "0.7rem", color: "#94a3b8" }}>Pre-Action Risk</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#f87171" }}>
                  {simulationResult.baseline_risk_score}
                </div>
              </div>
              <div style={{ background: "#1e293b", padding: "0.5rem", borderRadius: "0.25rem" }}>
                <div style={{ fontSize: "0.7rem", color: "#94a3b8" }}>Residual Risk</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#34d399" }}>
                  {simulationResult.residual_risk_score}
                </div>
              </div>
              <div style={{ background: "#1e293b", padding: "0.5rem", borderRadius: "0.25rem" }}>
                <div style={{ fontSize: "0.7rem", color: "#94a3b8" }}>Exposure Reduced</div>
                <div style={{ fontSize: "1.1rem", fontWeight: 700, color: "#38bdf8", display: "flex", alignItems: "center", justifyContent: "center", gap: "0.2rem" }}>
                  <ArrowDownRight size={16} />
                  <span>{simulationResult.risk_reduction_percentage}%</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Approval Section */}
      {plan.status !== "APPROVED" && (
        <div style={{ marginTop: "0.5rem" }}>
          {isManager ? (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
              <input
                type="text"
                value={decisionNote}
                onChange={(e) => setDecisionNote(e.target.value)}
                placeholder="Enter justification note for approval..."
                style={{
                  padding: "0.5rem",
                  background: "#1e293b",
                  border: "1px solid #475569",
                  borderRadius: "0.375rem",
                  color: "#f8fafc",
                  fontSize: "0.85rem",
                }}
              />
              <button
                onClick={handleApprove}
                disabled={isApproving}
                className="btn-primary"
                style={{
                  background: "#16a34a",
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  gap: "0.4rem",
                }}
              >
                <ShieldCheck size={18} />
                <span>{isApproving ? "Approving..." : "Approve & Execute (Simulated SOAR)"}</span>
              </button>
            </div>
          ) : (
            <div style={{ fontSize: "0.8rem", color: "#94a3b8", textAlign: "center" }}>
              Approval requires <b>SOC_MANAGER</b> credentials. Log in as Morgan Manager to execute approval.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
