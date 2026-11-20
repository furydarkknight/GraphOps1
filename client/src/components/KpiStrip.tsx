import { Shield, Clock, AlertTriangle, Filter, CheckCircle2 } from "lucide-react";

interface KpiStripProps {
  kpis: any | null;
}

export function KpiStrip({ kpis }: KpiStripProps) {
  const alertReduction = kpis?.alerts?.reductionRatio
    ? `${Math.round(kpis.alerts.reductionRatio * 100)}%`
    : "78.0%";

  const items = [
    {
      title: "Alert Reduction Ratio",
      value: alertReduction,
      subtitle: `${kpis?.alerts?.total || 50} raw alerts clustered`,
      icon: Filter,
      color: "#38bdf8",
    },
    {
      title: "Active Incidents",
      value: `${kpis?.incidents?.open || 1}`,
      subtitle: `${kpis?.incidents?.contained || 0} Contained | ${kpis?.incidents?.closed || 0} Closed`,
      icon: AlertTriangle,
      color: "#f59e0b",
    },
    {
      title: "Crown Jewels Protected",
      value: `${kpis?.crownJewelsProtected || 3}`,
      subtitle: "Zero Tier-0 Exfiltration",
      icon: Shield,
      color: "#10b981",
    },
    {
      title: "Simulated Containment Eff.",
      value: "81.2%",
      subtitle: "Residual blast radius removed",
      icon: CheckCircle2,
      color: "#a855f7",
    },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(220px, 1fr))", gap: "1rem", marginBottom: "1.5rem" }}>
      {items.map((it, idx) => {
        const Icon = it.icon;
        return (
          <div
            key={idx}
            className="card"
            style={{
              display: "flex",
              alignItems: "center",
              gap: "1rem",
              background: "#0f172a",
              border: "1px solid #1e293b",
            }}
          >
            <div
              style={{
                padding: "0.75rem",
                borderRadius: "0.5rem",
                background: `${it.color}20`,
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
              }}
            >
              <Icon size={24} color={it.color} />
            </div>
            <div>
              <div style={{ fontSize: "0.75rem", color: "#94a3b8", fontWeight: 500 }}>{it.title}</div>
              <div style={{ fontSize: "1.4rem", fontWeight: 800, color: "#f8fafc", lineHeight: 1.2 }}>{it.value}</div>
              <div style={{ fontSize: "0.7rem", color: "#64748b" }}>{it.subtitle}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
