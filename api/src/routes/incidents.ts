import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";

export const incidentsRouter = Router();

const CreateIncidentSchema = z.object({
  title: z.string().min(1).max(300).trim(),
  snapshotId: z.string().cuid(),
  huntRunId: z.string().cuid().optional(),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
});

const UpdateIncidentSchema = z.object({
  title: z.string().min(1).max(300).trim().optional(),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional(),
  status: z.enum(["OPEN", "TRIAGED", "CONTAINED", "CLOSED"]).optional(),
  blastRadius: z.record(z.unknown()).optional(),
  attackPaths: z.record(z.unknown()).optional(),
  timelineEntry: z
    .object({ ts: z.string(), event: z.string(), actor: z.string().optional() })
    .optional(),
});

/** GET /api/incidents */
incidentsRouter.get("/", requireAuth, requireMinRole("ANALYST"), async (_req, res) => {
  const incidents = await prisma.incident.findMany({
    orderBy: { createdAt: "desc" },
    take: 100,
    select: {
      id: true,
      title: true,
      severity: true,
      status: true,
      snapshotId: true,
      huntRunId: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  return res.json(incidents);
});

/** GET /api/incidents/:id */
incidentsRouter.get("/:id", requireAuth, requireMinRole("ANALYST"), async (req, res) => {
  const incident = await prisma.incident.findUnique({
    where: { id: String(req.params["id"] ?? "") },
    include: {
      containmentPlans: {
        orderBy: { createdAt: "desc" },
        select: { id: true, status: true, createdAt: true },
      },
      passport: { select: { id: true, passportHash: true, issuedAt: true } },
    },
  });
  if (!incident) return res.status(404).json({ error: "Incident not found." });
  return res.json(incident);
});

/** POST /api/incidents */
incidentsRouter.post(
  "/",
  requireAuth,
  requireMinRole("ANALYST"),
  validateBody(CreateIncidentSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof CreateIncidentSchema>;

    const snapshot = await prisma.graphSnapshot.findUnique({
      where: { id: body.snapshotId },
      select: { id: true },
    });
    if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });

    const incident = await prisma.incident.create({
      data: {
        title: body.title,
        snapshotId: body.snapshotId,
        huntRunId: body.huntRunId,
        severity: body.severity,
        timeline: [{ ts: new Date().toISOString(), event: "Incident created" }] as object,
      },
    });
    return res.status(201).json(incident);
  },
);

/** PATCH /api/incidents/:id */
incidentsRouter.patch(
  "/:id",
  requireAuth,
  requireMinRole("RESPONDER"),
  validateBody(UpdateIncidentSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof UpdateIncidentSchema>;
    const incidentId = (_req.params as { id: string })["id"];

    const existing = await prisma.incident.findUnique({ where: { id: incidentId } });
    if (!existing) return res.status(404).json({ error: "Incident not found." });

    // Append timeline entry if provided
    let timeline = (existing.timeline ?? []) as Array<Record<string, string>>;
    if (body.timelineEntry) {
      timeline = [...timeline, body.timelineEntry];
    }
    if (body.status && body.status !== existing.status) {
      timeline = [...timeline, { ts: new Date().toISOString(), event: `Status changed to ${body.status}` }];
    }

    const updated = await prisma.incident.update({
      where: { id: incidentId },
      data: {
        ...(body.title !== undefined && { title: body.title }),
        ...(body.severity !== undefined && { severity: body.severity }),
        ...(body.status !== undefined && { status: body.status }),
        ...(body.blastRadius !== undefined && { blastRadius: body.blastRadius as object }),
        ...(body.attackPaths !== undefined && { attackPaths: body.attackPaths as object }),
        timeline: timeline as object,
      },
    });
    return res.json(updated);
  },
);
