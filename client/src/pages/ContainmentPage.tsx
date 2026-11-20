import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { ContainmentPanel } from "../components/ContainmentPanel";
import { Lock, Zap, ShieldCheck } from "lucide-react";

export function ContainmentPage() {
  const [searchParams] = useSearchParams();
  const incidentIdParam = searchParams.get("incidentId");

  const [incidents, setIncidents] = useState<any[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("");
  const [activePlan, setActivePlan] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [budget, setBudget] = useState(80);

  useEffect(() => {
    api.listIncidents().then((incs) => {
      setIncidents(incs);
      const targetId = incidentIdParam || (incs.length > 0 ? incs[0].id : "");
      if (targetId) {
        setSelectedIncidentId(targetId);
        loadPlanForIncident(targetId);
      }
    });
  }, [incidentIdParam]);

  async function loadPlanForIncident(incId: string) {
    setIsLoading(true);
    try {
      const inc = await api.getIncident(incId);
      if (inc.containmentPlans && inc.containmentPlans.length > 0) {
        // Fetch full plan
        const fullPlan = await apiRequestInternal(`/api/containment/${inc.containmentPlans[0].id}`);
        setActivePlan(fullPlan);
      } else {
        // Generate new plan automatically
        const newPlan = await api.planContainment(incId, budget);
        setActivePlan(newPlan.plan);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  }

  async function apiRequestInternal(path: string) {
    const token = localStorage.getItem("graphops_token");
    const res = await fetch(path, {
      headers: { Authorization: `Bearer ${token}` },
    });
    return res.json();
  }

  async function handleSimulate(actions: any[]) {
    return api.simulateContainment(selectedIncidentId, actions);
  }

  async function handleApprove(planId: string, note: string) {
    const updated = await api.approveContainment(planId, "APPROVED", note);
    setActivePlan(updated);
    alert("Containment plan approved and executed via simulated SOAR/EDR adapter!");
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h2 style={{ fontSize: "1.25rem", fontWeight: 800 }}>Blast Radius Containment Optimizer</h2>
          <p style={{ color: "#94a3b8", fontSize: "0.85rem" }}>
            Select minimal-disruption candidate actions under budget constraint and simulate what-if impact.
          </p>
        </div>

        {incidents.length > 0 && (
          <select
            value={selectedIncidentId}
            onChange={(e) => {
              setSelectedIncidentId(e.target.value);
              loadPlanForIncident(e.target.value);
            }}
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              color: "#f8fafc",
              padding: "0.4rem 0.75rem",
              borderRadius: "0.375rem",
            }}
          >
            {incidents.map((i) => (
              <option key={i.id} value={i.id}>
                {i.title} ({i.severity})
              </option>
            ))}
          </select>
        )}
      </div>

      <ContainmentPanel
        plan={activePlan}
        onSimulate={handleSimulate}
        onApprove={handleApprove}
        isLoading={isLoading}
      />
    </div>
  );
}
