import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole, requireRoles } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const containmentRouter = Router();

const PlanSchema = z.object({
  incidentId: z.string().cuid(),
  budget: z.number().positive().max(1_000_000).default(100),
});

const SimulateSchema = z.object({
  incidentId: z.string().cuid(),
  actions: z.array(z.record(z.unknown())).min(1).max(50),
});

const ApproveSchema = z.object({
  decision: z.enum(["APPROVED", "REJECTED"]),
  decisionNote: z.string().min(10).max(2000).trim().optional(),
  exceptionReason: z
    .enum(["BUSINESS_CRITICAL", "RULE_INCORRECT", "ACCEPTABLE_RISK", "FALSE_POSITIVE"])
    .optional(),
});

/** POST /api/containment/plan — optimiser generates candidate actions */
containmentRouter.post(
  "/plan",
  requireAuth,
  requireMinRole("RESPONDER"),
  analyticsLimiter,
  validateBody(PlanSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof PlanSchema>;

    const incident = await prisma.incident.findUnique({
      where: { id: body.incidentId },
      include: { snapshot: true },
    });
    if (!incident) return res.status(404).json({ error: "Incident not found." });

    let analyticsResult;
    try {
      analyticsResult = await analyticsClient.containmentPlan({
        graph_json: incident.snapshot.graphJson,
        incident: { id: incident.id, severity: incident.severity, blastRadius: incident.blastRadius },
        budget: body.budget,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    const plan = await prisma.containmentPlan.create({
      data: {
        incidentId: body.incidentId,
        requestedById: req.authUser!.id,
        actions: analyticsResult.actions as object,
        status: "PENDING",
      },
    });

    return res.status(201).json({ plan, expectedReduction: analyticsResult.expected_reduction });
  },
);

/** POST /api/containment/simulate — what-if: show residual blast if actions applied */
containmentRouter.post(
  "/simulate",
  requireAuth,
  requireMinRole("RESPONDER"),
  analyticsLimiter,
  validateBody(SimulateSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof SimulateSchema>;

    const incident = await prisma.incident.findUnique({
      where: { id: body.incidentId },
      include: { snapshot: true },
    });
    if (!incident) return res.status(404).json({ error: "Incident not found." });

    // Extract seeds from stored blast radius
    const br = incident.blastRadius as { impacted_nodes?: string[] } | null;
    const seeds = br?.impacted_nodes?.slice(0, 5) ?? [];

    try {
      const result = await analyticsClient.containmentSimulate({
        graph_json: incident.snapshot.graphJson,
        seeds,
        actions: body.actions,
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

/** PATCH /api/containment/:id/approve — SOC_MANAGER approve/reject plan */
containmentRouter.patch(
  "/:id/approve",
  requireAuth,
  requireRoles("SOC_MANAGER"),
  validateBody(ApproveSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof ApproveSchema>;
    const planId = String(req.params["id"] ?? "");

    const plan = await prisma.containmentPlan.findUnique({
      where: { id: planId },
    });
    if (!plan) return res.status(404).json({ error: "Containment plan not found." });
    if (plan.status !== "PENDING" && plan.status !== "SIMULATED") {
      return res.status(409).json({ error: `Plan is already ${plan.status.toLowerCase()}.` });
    }

    const updated = await prisma.containmentPlan.update({
      where: { id: planId },
      data: {
        status: body.decision === "APPROVED" ? "APPROVED" : "REJECTED",
        decisionNote: body.decisionNote,
        exceptionReason: body.exceptionReason,
        approvedAt: body.decision === "APPROVED" ? new Date() : null,
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "CONTAINMENT_APPROVE",
        actorId: req.authUser!.id,
        targetId: planId,
        payload: { planId, decision: body.decision, decisionNote: body.decisionNote },
      },
    });

    return res.json(updated);
  },
);

/** GET /api/containment/:id — get a plan */
containmentRouter.get("/:id", requireAuth, requireMinRole("ANALYST"), async (req, res) => {
  const planId = String(req.params["id"] ?? "");
  const plan = await prisma.containmentPlan.findUnique({
    where: { id: planId },
    include: { requestedBy: { select: { id: true, name: true, role: true } } },
  });
  if (!plan) return res.status(404).json({ error: "Containment plan not found." });
  return res.json(plan);
});
