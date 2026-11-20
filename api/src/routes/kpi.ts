import { Router } from "express";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRoles } from "../middleware/auth.js";
import { buildKpiInsights } from "../lib/kpi-insights.js";

export const kpiRouter = Router();

/** GET /api/kpi — SOC KPI aggregates (all roles, SOC_MANAGER sees extra detail) */
kpiRouter.get("/", requireAuth, async (req, res) => {
  const isManager = req.authUser?.role === "SOC_MANAGER";

  // Alert reduction
  const totalAlerts = await prisma.alert.count();
  const correlatedAlerts = await prisma.alert.count({ where: { incidentId: { not: null } } });
  const alertReductionRatio =
    totalAlerts > 0 ? (totalAlerts - (await prisma.incident.count())) / totalAlerts : 0;

  // Incident stats
  const [open, contained, closed] = await Promise.all([
    prisma.incident.count({ where: { status: "OPEN" } }),
    prisma.incident.count({ where: { status: "CONTAINED" } }),
    prisma.incident.count({ where: { status: "CLOSED" } }),
  ]);

  // Crown jewels protected
  const crownJewelCount = await prisma.assetNode.count({ where: { isCrownJewel: true } });

  // Basic KPI payload
  const kpi: Record<string, unknown> = {
    alerts: { total: totalAlerts, correlated: correlatedAlerts, reductionRatio: alertReductionRatio },
    incidents: { open, contained, closed, total: open + contained + closed },
    crownJewelsProtected: crownJewelCount,
    snapshotsIngested: await prisma.graphSnapshot.count(),
    huntRunsCompleted: await prisma.huntRun.count(),
  };

  if (isManager) {
    // Containment exception insights
    const plans = await prisma.containmentPlan.findMany({
      select: { id: true, exceptionReason: true, decisionNote: true, status: true },
    });
    kpi["containmentInsights"] = buildKpiInsights(
      plans.map((p) => ({
        id: p.id,
        exceptionReason: p.exceptionReason,
        decisionNote: p.decisionNote,
        status: p.status,
      })),
    );
  }

  return res.json(kpi);
});
