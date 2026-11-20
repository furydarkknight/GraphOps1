import { useState } from "react";
import { FileCheck, Download, Copy, Check, ExternalLink } from "lucide-react";
import { Link } from "react-router-dom";

interface PassportCardProps {
  passport: any | null;
  incidentId: string;
  onDownloadPdf: () => void;
}

export function PassportCard({ passport, incidentId, onDownloadPdf }: PassportCardProps) {
  const [copied, setCopied] = useState(false);

  if (!passport) {
    return (
      <div className="card" style={{ textAlign: "center", padding: "1.5rem", color: "#64748b" }}>
        No passport issued yet. Incident must be contained and approved by SOC Manager.
      </div>
    );
  }

  const hash = passport.passportHash || "";

  function copyHash() {
    navigator.clipboard.writeText(hash);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div
      className="card"
      style={{
        background: "linear-gradient(135deg, #0f172a 0%, #1e1b4b 100%)",
        border: "1px solid #6366f1",
        display: "flex",
        flexDirection: "column",
        gap: "1rem",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <FileCheck size={20} color="#818cf8" />
          <h3 style={{ fontSize: "1rem", fontWeight: 700, color: "#f8fafc" }}>
            Signed Incident & Containment Passport
          </h3>
        </div>
        <span className="badge badge-low" style={{ background: "rgba(99, 102, 241, 0.2)", color: "#a5b4fc", borderColor: "#6366f1" }}>
          HMAC-SHA256 Signed
        </span>
      </div>

      <div style={{ fontSize: "0.8rem", color: "#cbd5e1" }}>
        This tamper-evident passport cryptographically binds the incident timeline, graph snapshot,
        blast radius reachability metrics, and approved containment actions.
      </div>

      {/* Signature Hash */}
      <div
        style={{
          background: "#090d16",
          padding: "0.75rem",
          borderRadius: "0.375rem",
          border: "1px solid #334155",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.7rem", color: "#94a3b8", marginBottom: "0.25rem" }}>
          <span>Passport Digest (HMAC-SHA256):</span>
          <button
            onClick={copyHash}
            style={{ background: "transparent", border: "none", color: "#38bdf8", cursor: "pointer", display: "flex", alignItems: "center", gap: "0.2rem" }}
          >
            {copied ? <Check size={12} /> : <Copy size={12} />}
            <span>{copied ? "Copied" : "Copy"}</span>
          </button>
        </div>
        <div style={{ fontFamily: "monospace", fontSize: "0.75rem", color: "#38bdf8", wordBreak: "break-all" }}>
          {hash}
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: "flex", gap: "0.75rem" }}>
        <button
          onClick={onDownloadPdf}
          className="btn-primary"
          style={{ flex: 1, display: "flex", alignItems: "center", justifyContent: "center", gap: "0.4rem", fontSize: "0.85rem" }}
        >
          <Download size={16} />
          <span>Download PDF Report</span>
        </button>

        <Link
          to={`/verify?id=${passport.id}`}
          className="btn-secondary"
          style={{
            flex: 1,
            textDecoration: "none",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            gap: "0.4rem",
            fontSize: "0.85rem",
            color: "#f8fafc",
          }}
        >
          <ExternalLink size={16} />
          <span>Public Verify</span>
        </Link>
      </div>
    </div>
  );
}
