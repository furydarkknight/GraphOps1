import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../lib/auth";
import { Shield, KeyRound, UserCheck, Lock } from "lucide-react";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("analyst@graphops.demo");
  const [password, setPassword] = useState("analyst-demo-2026!");
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const demoAccounts = [
    { role: "SOC Analyst", email: "analyst@graphops.demo", pass: "analyst-demo-2026!", desc: "Triage alerts, explore graph topology, run proactive hunts" },
    { role: "Incident Responder", email: "responder@graphops.demo", pass: "responder-demo-2026!", desc: "Analyze blast radius, propose containment plans, simulate what-if impact" },
    { role: "SOC Manager", email: "manager@graphops.demo", pass: "manager-demo-2026!", desc: "Approve containment plans, issue HMAC incident passports, manage policy" },
  ];

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setIsLoading(true);
    try {
      await login(email, password);
      navigate("/");
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setIsLoading(false);
    }
  }

  async function pickAccount(acc: typeof demoAccounts[0]) {
    setEmail(acc.email);
    setPassword(acc.pass);
    setError(null);
    setIsLoading(true);
    try {
      await login(acc.email, acc.pass);
      navigate("/");
    } catch (err: any) {
      setError(err.message || "Login failed. Ensure backend services are running.");
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div style={{ minHeight: "80vh", display: "flex", alignItems: "center", justifyContent: "center" }}>
      <div className="card" style={{ width: "100%", maxWidth: "480px", padding: "2rem" }}>
        <div style={{ textAlign: "center", marginBottom: "1.5rem" }}>
          <div style={{ display: "inline-flex", padding: "0.75rem", background: "#2563eb", borderRadius: "0.75rem", marginBottom: "0.75rem" }}>
            <Shield size={32} color="#ffffff" />
          </div>
          <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>GraphOps SOC Platform</h2>
          <p style={{ color: "#94a3b8", fontSize: "0.85rem", marginTop: "0.25rem" }}>
            Graph Analytics for Proactive Threat Hunting & Blast Radius Containment
          </p>
        </div>

        {error && (
          <div style={{ padding: "0.6rem", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "0.375rem", color: "#f87171", fontSize: "0.85rem", marginBottom: "1rem" }}>
            {error}
          </div>
        )}

        <form onSubmit={handleLogin} style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
          <div>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, color: "#cbd5e1", marginBottom: "0.3rem" }}>
              Email Address
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              style={{ width: "100%", padding: "0.6rem", background: "#1e293b", border: "1px solid #334155", borderRadius: "0.375rem", color: "#f8fafc" }}
            />
          </div>

          <div>
            <label style={{ display: "block", fontSize: "0.8rem", fontWeight: 600, color: "#cbd5e1", marginBottom: "0.3rem" }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              style={{ width: "100%", padding: "0.6rem", background: "#1e293b", border: "1px solid #334155", borderRadius: "0.375rem", color: "#f8fafc" }}
            />
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className="btn-primary"
            style={{ width: "100%", padding: "0.75rem", marginTop: "0.5rem" }}
          >
            {isLoading ? "Authenticating..." : "Sign In to SOC Console"}
          </button>
        </form>

        {/* Demo Fast-Login Presets */}
        <div style={{ marginTop: "1.75rem", paddingTop: "1.25rem", borderTop: "1px solid #1e293b" }}>
          <div style={{ fontSize: "0.75rem", fontWeight: 700, color: "#38bdf8", textTransform: "uppercase", marginBottom: "0.75rem", letterSpacing: "0.05em", display: "flex", alignItems: "center", gap: "0.4rem" }}>
            <span>⚡ 1-Click Demo Login (Select Any Role to Enter Console):</span>
          </div>
          <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
            {demoAccounts.map((acc, idx) => (
              <div
                key={idx}
                onClick={() => pickAccount(acc)}
                style={{
                  padding: "0.6rem 0.75rem",
                  background: email === acc.email ? "#1e293b" : "#090d16",
                  border: email === acc.email ? "1px solid #38bdf8" : "1px solid #1e293b",
                  borderRadius: "0.375rem",
                  cursor: "pointer",
                  transition: "all 0.15s",
                }}
              >
                <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                  <b style={{ fontSize: "0.85rem", color: "#f8fafc" }}>{acc.role}</b>
                  <span style={{ fontSize: "0.7rem", color: "#94a3b8" }}>{acc.email}</span>
                </div>
                <div style={{ fontSize: "0.75rem", color: "#64748b", marginTop: "0.15rem" }}>{acc.desc}</div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
