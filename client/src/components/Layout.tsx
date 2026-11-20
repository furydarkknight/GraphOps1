import { ReactNode, useEffect, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { api } from "../lib/api";
import { Shield, Network, Crosshair, AlertTriangle, Lock, FileCheck, LogOut, Activity } from "lucide-react";

export function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [health, setHealth] = useState<any>(null);

  useEffect(() => {
    api.getHealth().then(setHealth).catch(() => {});
  }, []);

  const navItems = [
    { label: "SOC Dashboard", path: "/", icon: Shield },
    { label: "Topology Graph", path: "/graph", icon: Network },
    { label: "Proactive Hunts", path: "/hunts", icon: Crosshair },
    { label: "Incidents", path: "/incidents", icon: AlertTriangle },
    { label: "Containment", path: "/containment", icon: Lock },
    { label: "Verify Passport", path: "/verify", icon: FileCheck },
  ];

  const roleBadges: Record<string, { label: string; class: string }> = {
    ANALYST: { label: "SOC Analyst", class: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30" },
    RESPONDER: { label: "Incident Responder", class: "bg-amber-500/20 text-amber-400 border-amber-500/30" },
    SOC_MANAGER: { label: "SOC Manager", class: "bg-purple-500/20 text-purple-400 border-purple-500/30" },
  };

  const currentRole = user?.role || "ANALYST";
  const badge = roleBadges[currentRole] || roleBadges.ANALYST;

  return (
    <div style={{ display: "flex", flexDirection: "column", minHeight: "100vh" }}>
      {/* Top Navbar */}
      <header
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0.75rem 1.5rem",
          background: "#090d16",
          borderBottom: "1px solid #1e293b",
          position: "sticky",
          top: 0,
          zIndex: 50,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: "1.5rem" }}>
          <Link to="/" style={{ display: "flex", alignItems: "center", gap: "0.5rem", textDecoration: "none", color: "#f8fafc" }}>
            <div style={{ padding: "0.35rem", background: "#2563eb", borderRadius: "0.375rem" }}>
              <Shield size={20} color="#ffffff" />
            </div>
            <div>
              <span style={{ fontWeight: 700, fontSize: "1.1rem", letterSpacing: "-0.025em" }}>GraphOps</span>
              <span style={{ fontSize: "0.75rem", color: "#38bdf8", marginLeft: "0.35rem", fontWeight: 600 }}>SOC</span>
            </div>
          </Link>

          {/* Navigation tabs */}
          <nav style={{ display: "flex", gap: "0.25rem" }}>
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = location.pathname === item.path;
              return (
                <Link
                  key={item.path}
                  to={item.path}
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "0.4rem",
                    padding: "0.4rem 0.75rem",
                    borderRadius: "0.375rem",
                    fontSize: "0.85rem",
                    fontWeight: 500,
                    textDecoration: "none",
                    color: isActive ? "#38bdf8" : "#94a3b8",
                    background: isActive ? "rgba(56, 189, 248, 0.1)" : "transparent",
                    transition: "all 0.15s",
                  }}
                >
                  <Icon size={15} />
                  <span>{item.label}</span>
                </Link>
              );
            })}
          </nav>
        </div>

        {/* User profile & health status */}
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          {health && (
            <div
              style={{
                display: "flex",
                alignItems: "center",
                gap: "0.35rem",
                padding: "0.25rem 0.6rem",
                borderRadius: "9999px",
                background: "#1e293b",
                fontSize: "0.75rem",
                color: "#cbd5e1",
                border: "1px solid #334155",
              }}
              title={`LLM: ${health.llm_mode} | Classifier: ${health.model_mode}`}
            >
              <Activity size={12} color="#10b981" />
              <span>LLM: {health.llm_mode}</span>
              <span style={{ color: "#64748b" }}>|</span>
              <span>Model: {health.model_mode}</span>
            </div>
          )}

          {user && (
            <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
              <div style={{ textAlign: "right" }}>
                <div style={{ fontSize: "0.85rem", fontWeight: 600 }}>{user.name}</div>
                <span
                  style={{
                    fontSize: "0.7rem",
                    padding: "0.1rem 0.4rem",
                    borderRadius: "4px",
                    border: "1px solid",
                  }}
                  className={badge.class}
                >
                  {badge.label}
                </span>
              </div>
              <button
                onClick={() => { logout(); navigate("/login"); }}
                style={{
                  background: "transparent",
                  border: "none",
                  color: "#94a3b8",
                  cursor: "pointer",
                  padding: "0.35rem",
                  borderRadius: "0.25rem",
                }}
                title="Log out"
              >
                <LogOut size={18} />
              </button>
            </div>
          )}
        </div>
      </header>

      {/* Main Content Area */}
      <main style={{ flex: 1, padding: "1.5rem", maxWidth: "1600px", margin: "0 auto", width: "100%" }}>
        {children}
      </main>
    </div>
  );
}
