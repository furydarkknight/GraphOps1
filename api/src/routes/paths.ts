import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const pathsRouter = Router();

const PathsSchema = z.object({
  snapshotId: z.string().cuid(),
  sources: z.array(z.string()).min(1).max(20),
  targets: z.array(z.string()).min(1).max(20),
  k: z.number().int().min(1).max(20).optional().default(5),
});

/** POST /api/paths — attack path analysis */
pathsRouter.post(
  "/",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(PathsSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof PathsSchema>;

    const snapshot = await prisma.graphSnapshot.findUnique({
      where: { id: body.snapshotId },
    });
    if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });

    try {
      const result = await analyticsClient.paths({
        graph_json: snapshot.graphJson,
        sources: body.sources,
        targets: body.targets,
        k: body.k,
      });
      return res.json(result);
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }
  },
);
