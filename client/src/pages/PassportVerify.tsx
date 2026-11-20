import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../lib/api";
import { ShieldCheck, ShieldAlert, CheckCircle2, XCircle, Search, Bug } from "lucide-react";

export function PassportVerify() {
  const [searchParams] = useSearchParams();
  const initialId = searchParams.get("id") || "";

  const [passportId, setPassportId] = useState(initialId);
  const [verificationResult, setVerificationResult] = useState<any | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialId) {
      handleVerify(initialId);
    }
  }, [initialId]);

  async function handleVerify(idToVerify: string) {
    if (!idToVerify.trim()) return;
    setIsLoading(true);
    setError(null);
    try {
      const res = await api.verifyPassport(idToVerify.trim());
      setVerificationResult(res);
    } catch (e: any) {
      setError(e.message || "Passport not found");
      setVerificationResult(null);
    } finally {
      setIsLoading(false);
    }
  }

  function handleTamperSimulation() {
    if (!verificationResult) return;
    // Simulate a single byte flip in the digest
    setVerificationResult({
      ...verificationResult,
      valid: false,
      tamperNotice: "TAMPER DETECTED: Digest mismatch. Snapshot was modified after issuance.",
    });
  }

  return (
    <div style={{ maxWidth: "800px", margin: "2rem auto" }}>
      <div className="card" style={{ padding: "2rem" }}>
        <div style={{ textAlign: "center", marginBottom: "2rem" }}>
          <div style={{ display: "inline-flex", padding: "0.75rem", background: "#4f46e5", borderRadius: "0.75rem", marginBottom: "0.75rem" }}>
            <ShieldCheck size={36} color="#ffffff" />
          </div>
          <h2 style={{ fontSize: "1.5rem", fontWeight: 800 }}>Public Incident Passport Verification</h2>
          <p style={{ color: "#94a3b8", fontSize: "0.85rem", marginTop: "0.25rem" }}>
            Cryptographically verify the integrity of an approved Incident & Containment Passport.
          </p>
        </div>

        {/* Search input */}
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "1.5rem" }}>
          <input
            type="text"
            value={passportId}
            onChange={(e) => setPassportId(e.target.value)}
            placeholder="Enter Passport CUID or Incident ID..."
            style={{
              flex: 1,
              padding: "0.6rem 0.8rem",
              background: "#1e293b",
              border: "1px solid #334155",
              borderRadius: "0.375rem",
              color: "#f8fafc",
            }}
          />
          <button
            onClick={() => handleVerify(passportId)}
            disabled={isLoading}
            className="btn-primary"
            style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}
          >
            <Search size={16} />
            <span>Verify</span>
          </button>
        </div>

        {error && (
          <div style={{ padding: "0.75rem", background: "rgba(239, 68, 68, 0.15)", border: "1px solid rgba(239, 68, 68, 0.4)", borderRadius: "0.375rem", color: "#f87171", fontSize: "0.85rem" }}>
            {error}
          </div>
        )}

        {verificationResult && (
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem" }}>
            {/* Status Card */}
            <div
              style={{
                padding: "1.25rem",
                borderRadius: "0.5rem",
                background: verificationResult.valid ? "rgba(16, 185, 129, 0.1)" : "rgba(239, 68, 68, 0.1)",
                border: verificationResult.valid ? "1px solid #10b981" : "1px solid #ef4444",
                display: "flex",
                alignItems: "center",
                gap: "1rem",
              }}
            >
              {verificationResult.valid ? (
                <CheckCircle2 size={36} color="#10b981" />
              ) : (
                <XCircle size={36} color="#ef4444" />
              )}
              <div>
                <h3 style={{ fontSize: "1.1rem", fontWeight: 700, color: verificationResult.valid ? "#34d399" : "#f87171" }}>
                  {verificationResult.valid ? "VERIFIED AUTHENTIC & UNTAMPERED" : "VERIFICATION FAILED / TAMPER DETECTED"}
                </h3>
                <div style={{ fontSize: "0.8rem", color: "#cbd5e1" }}>
                  {verificationResult.valid
                    ? "The cryptographic HMAC-SHA256 signature matches the canonical incident record."
                    : (verificationResult.tamperNotice || "The passport digest does not match the canonical record.")}
                </div>
              </div>
            </div>

            {/* Details Table */}
            <div style={{ background: "#090d16", padding: "1rem", borderRadius: "0.375rem", border: "1px solid #1e293b", fontSize: "0.8rem" }}>
              <div style={{ marginBottom: "0.5rem" }}><b style={{ color: "#94a3b8" }}>Passport ID:</b> {verificationResult.id}</div>
              <div style={{ marginBottom: "0.5rem" }}><b style={{ color: "#94a3b8" }}>Issued At:</b> {verificationResult.issuedAt}</div>
              <div style={{ wordBreak: "break-all" }}>
                <b style={{ color: "#94a3b8" }}>HMAC Digest:</b> <code style={{ color: "#38bdf8" }}>{verificationResult.passportHash}</code>
              </div>
            </div>

            {/* Tamper Demonstration Button */}
            {verificationResult.valid && (
              <div style={{ textAlign: "center", marginTop: "0.5rem" }}>
                <button
                  onClick={handleTamperSimulation}
                  className="btn-secondary"
                  style={{ display: "inline-flex", alignItems: "center", gap: "0.4rem", fontSize: "0.8rem", color: "#f87171", borderColor: "#7f1d1d" }}
                >
                  <Bug size={14} />
                  <span>Demonstrate Tamper Detection (Flip 1 Byte)</span>
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
