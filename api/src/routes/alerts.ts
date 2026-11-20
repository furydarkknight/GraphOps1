import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const alertsRouter = Router();

const CorrelateSchema = z.object({
  alerts: z.array(z.record(z.unknown())).min(1).max(10_000),
  snapshotId: z.string().cuid(),
  source: z.string().min(1).max(50).default("siem"),
});

/** POST /api/alerts/correlate — cluster raw alerts into incidents */
alertsRouter.post(
  "/correlate",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(CorrelateSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof CorrelateSchema>;

    const snapshot = await prisma.graphSnapshot.findUnique({
      where: { id: body.snapshotId },
    });
    if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });

    // Persist raw alerts first
    await prisma.alert.createMany({
      data: body.alerts.map((raw) => ({
        raw: raw as object,
        source: body.source,
      })),
    });

    let result;
    try {
      result = await analyticsClient.alertCorrelate({
        alerts: body.alerts,
        graph_json: snapshot.graphJson,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    // Create incident records for each cluster
    const clusters = result.clusters as Array<{
      id: string;
      title: string;
      severity: string;
      alert_ids: string[];
    }>;

    const createdIncidents = await Promise.all(
      clusters.map((cluster) =>
        prisma.incident.create({
          data: {
            title: cluster.title,
            snapshotId: body.snapshotId,
            severity: cluster.severity as "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            status: "OPEN",
            timeline: [{ ts: new Date().toISOString(), event: "Created from alert correlation" }] as object,
          },
        }),
      ),
    );

    return res.json({
      incidentsCreated: createdIncidents.length,
      alertReductionRatio: result.alert_reduction_ratio,
      incidents: createdIncidents.map((i) => ({ id: i.id, title: i.title, severity: i.severity })),
    });
  },
);
