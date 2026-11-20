import { useEffect, useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { api } from "../lib/api";
import { useAuth } from "../lib/auth";
import { PassportCard } from "../components/PassportCard";
import { BlastRadiusPanel } from "../components/BlastRadiusPanel";
import { AlertTriangle, Download, ShieldCheck, Clock, ArrowRight } from "lucide-react";

export function IncidentPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const incidentIdParam = searchParams.get("id");

  const [incidents, setIncidents] = useState<any[]>([]);
  const [currentIncident, setCurrentIncident] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [isIssuingPassport, setIsIssuingPassport] = useState(false);

  useEffect(() => {
    loadIncidents();
  }, [incidentIdParam]);

  async function loadIncidents() {
    setIsLoading(true);
    try {
      const list = await api.listIncidents();
      setIncidents(list);

      const targetId = incidentIdParam || (list.length > 0 ? list[0].id : null);
      if (targetId) {
        const details = await api.getIncident(targetId);
        setCurrentIncident(details);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setIsLoading(false);
    }
  }

  async function handleDownloadPdf() {
    if (!currentIncident) return;
    try {
      const blob = await api.downloadReportPdf(currentIncident.id);
      const url = window.URL.createObjectURL(blob as unknown as Blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `incident-${currentIncident.id}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (e: any) {
      alert("PDF download failed: " + e.message);
    }
  }

  async function handleIssuePassport() {
    if (!currentIncident) return;
    setIsIssuingPassport(true);
    try {
      const passport = await api.issuePassport(currentIncident.id);
      setCurrentIncident({ ...currentIncident, passport });
    } catch (e: any) {
      alert("Passport issue failed: " + e.message);
    } finally {
      setIsIssuingPassport(false);
    }
  }

  const isManager = user?.role === "SOC_MANAGER";

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
      {/* Top Selector if multiple incidents */}
      <div className="card" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <AlertTriangle size={20} color="#f59e0b" />
          <h2 style={{ fontSize: "1.2rem", fontWeight: 700 }}>Incident Triage & Response</h2>
        </div>

        {incidents.length > 0 && (
          <select
            value={currentIncident?.id || ""}
            onChange={(e) => navigate(`/incidents?id=${e.target.value}`)}
            style={{
              background: "#1e293b",
              border: "1px solid #334155",
              color: "#f8fafc",
              padding: "0.4rem 0.75rem",
              borderRadius: "0.375rem",
            }}
          >
            {incidents.map((inc) => (
              <option key={inc.id} value={inc.id}>
                {inc.title} ({inc.severity})
              </option>
            ))}
          </select>
        )}
      </div>

      {currentIncident ? (
        <div style={{ display: "grid", gridTemplateColumns: "1fr 400px", gap: "1.5rem" }}>
          {/* Main Info */}
          <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
            <div className="card">
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: "1rem" }}>
                <div>
                  <h3 style={{ fontSize: "1.2rem", fontWeight: 800 }}>{currentIncident.title}</h3>
                  <div style={{ fontSize: "0.8rem", color: "#94a3b8" }}>ID: {currentIncident.id}</div>
                </div>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <span className="badge badge-critical">{currentIncident.severity}</span>
                  <span className="badge badge-medium">{currentIncident.status}</span>
                </div>
              </div>

              {/* Action buttons */}
              <div style={{ display: "flex", gap: "0.75rem" }}>
                <button
                  onClick={() => navigate(`/containment?incidentId=${currentIncident.id}`)}
                  className="btn-primary"
                  style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem" }}
                >
                  <span>Containment Console</span>
                  <ArrowRight size={15} />
                </button>

                <button
                  onClick={handleDownloadPdf}
                  className="btn-secondary"
                  style={{ display: "flex", alignItems: "center", gap: "0.4rem", fontSize: "0.85rem" }}
                >
                  <Download size={15} />
                  <span>Download Report (PDF)</span>
                </button>

                {isManager && !currentIncident.passport && (
                  <button
                    onClick={handleIssuePassport}
                    disabled={isIssuingPassport}
                    className="btn-secondary"
                    style={{ background: "#4f46e5", borderColor: "#6366f1", fontSize: "0.85rem" }}
                  >
                    <ShieldCheck size={15} />
                    <span>{isIssuingPassport ? "Issuing..." : "Issue Release Passport"}</span>
                  </button>
                )}
              </div>
            </div>

            {/* Timeline */}
            <div className="card">
              <h4 style={{ fontSize: "0.95rem", fontWeight: 700, marginBottom: "0.75rem", display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <Clock size={16} color="#38bdf8" />
                <span>Incident Timeline & Evidence Chain</span>
              </h4>
              <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                {((currentIncident.timeline as any[]) || [
                  { ts: currentIncident.createdAt, event: "Incident created via alert clustering" },
                  { ts: new Date().toISOString(), event: "Proactive hunt confirmed lateral movement chain" },
                ]).map((t: any, idx: number) => (
                  <div
                    key={idx}
                    style={{
                      padding: "0.5rem 0.75rem",
                      background: "#1e293b",
                      borderRadius: "0.25rem",
                      borderLeft: "3px solid #38bdf8",
                      fontSize: "0.8rem",
                    }}
                  >
                    <span style={{ color: "#94a3b8", marginRight: "0.5rem" }}>{t.ts ? new Date(t.ts).toLocaleTimeString() : "Just now"}:</span>
                    <span style={{ color: "#f8fafc" }}>{t.event}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Right column: Passport & Blast Radius */}
          <div style={{ display: "flex", flexDirection: "column", gap: "1.5rem" }}>
            <PassportCard
              passport={currentIncident.passport}
              incidentId={currentIncident.id}
              onDownloadPdf={handleDownloadPdf}
            />

            <BlastRadiusPanel blastRadius={currentIncident.blastRadius} />
          </div>
        </div>
      ) : (
        <div className="card" style={{ textAlign: "center", padding: "3rem" }}>
          No incidents available. Correlate alerts on the Dashboard to initiate an incident.
        </div>
      )}
    </div>
  );
}
