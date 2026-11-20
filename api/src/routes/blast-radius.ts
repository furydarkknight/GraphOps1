import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const blastRadiusRouter = Router();

const BlastRadiusSchema = z.object({
  snapshotId: z.string().cuid(),
  seeds: z.array(z.string()).min(1).max(50),
  timeLimitHours: z.number().positive().max(720).optional().default(72),
  cascadeSeed: z.number().int().optional().default(42),
});

/** POST /api/blast-radius — compute blast radius from compromised seeds */
blastRadiusRouter.post(
  "/",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(BlastRadiusSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof BlastRadiusSchema>;

    const snapshot = await prisma.graphSnapshot.findUnique({
      where: { id: body.snapshotId },
    });
    if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });

    let result;
    try {
      result = await analyticsClient.blastRadius({
        graph_json: snapshot.graphJson,
        seeds: body.seeds,
        time_limit_hours: body.timeLimitHours,
        cascade_seed: body.cascadeSeed,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "BLAST_CALC",
        actorId: req.authUser!.id,
        payload: { snapshotId: body.snapshotId, seeds: body.seeds, riskScore: result.risk_score },
      },
    });

    return res.json(result);
  },
);
