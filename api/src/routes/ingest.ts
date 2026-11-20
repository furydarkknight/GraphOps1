import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { ingestInputHash } from "../lib/evidence-receipt.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const ingestRouter = Router();

const IngestSchema = z.object({
  events: z.array(z.record(z.unknown())).min(1).max(10_000),
  label: z.string().min(1).max(200).optional(),
  windowStart: z.string().datetime().optional(),
  windowEnd: z.string().datetime().optional(),
});

/** POST /api/ingest — normalise raw events into a graph snapshot */
ingestRouter.post(
  "/",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(IngestSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof IngestSchema>;

    // Compute input hash before sending to analytics
    const inputHash = ingestInputHash(body.events);

    let result;
    try {
      result = await analyticsClient.normalise({
        events: body.events,
        label: body.label,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    const snapshot = await prisma.graphSnapshot.create({
      data: {
        label: body.label ?? `ingest-${new Date().toISOString()}`,
        nodeCount: result.node_count,
        edgeCount: result.edge_count,
        graphJson: result.graph_json as object,
        inputHash,
        windowStart: body.windowStart ? new Date(body.windowStart) : null,
        windowEnd: body.windowEnd ? new Date(body.windowEnd) : null,
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "INGEST",
        actorId: req.authUser!.id,
        targetId: snapshot.id,
        payload: {
          snapshotId: snapshot.id,
          nodeCount: snapshot.nodeCount,
          edgeCount: snapshot.edgeCount,
          inputHash,
        },
      },
    });

    return res.status(201).json(snapshot);
  },
);
