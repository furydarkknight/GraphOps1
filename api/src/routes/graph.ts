import { Router } from "express";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";

export const graphRouter = Router();

/** GET /api/graph — list graph snapshots (most recent first) */
graphRouter.get("/", requireAuth, requireMinRole("ANALYST"), async (_req, res) => {
  const snapshots = await prisma.graphSnapshot.findMany({
    orderBy: { createdAt: "desc" },
    take: 50,
    select: {
      id: true,
      label: true,
      nodeCount: true,
      edgeCount: true,
      windowStart: true,
      windowEnd: true,
      inputHash: true,
      createdAt: true,
    },
  });
  return res.json(snapshots);
});

/** GET /api/graph/:id — get a single snapshot (without the full graphJson for bandwidth) */
graphRouter.get("/:id", requireAuth, requireMinRole("ANALYST"), async (req, res) => {
  const snapshot = await prisma.graphSnapshot.findUnique({
    where: { id: String(req.params["id"] ?? "") },
    select: {
      id: true,
      label: true,
      nodeCount: true,
      edgeCount: true,
      windowStart: true,
      windowEnd: true,
      inputHash: true,
      createdAt: true,
      // Omit graphJson by default — clients that need it can request the full payload
    },
  });
  if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });
  return res.json(snapshot);
});

/** GET /api/graph/:id/full — get snapshot with full graphJson (for client rendering) */
graphRouter.get("/:id/full", requireAuth, requireMinRole("ANALYST"), async (req, res) => {
  const snapshot = await prisma.graphSnapshot.findUnique({
    where: { id: String(req.params["id"] ?? "") },
  });
  if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });
  return res.json(snapshot);
});
