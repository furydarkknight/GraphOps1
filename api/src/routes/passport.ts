import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireRoles } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import {
  createIncidentPassport,
  verifyIncidentPassportHash,
  type IncidentPassportSnapshot,
} from "../lib/incident-passport.js";
import { sha256Json } from "../lib/evidence-receipt.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";

export const passportRouter = Router();

const IssuePassportSchema = z.object({
  incidentId: z.string().cuid(),
});

/** POST /api/passport — issue a signed incident passport (SOC_MANAGER only) */
passportRouter.post(
  "/",
  requireAuth,
  requireRoles("SOC_MANAGER"),
  analyticsLimiter,
  validateBody(IssuePassportSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof IssuePassportSchema>;

    // Check no passport exists yet
    const existing = await prisma.incidentPassport.findUnique({
      where: { incidentId: body.incidentId },
    });
    if (existing) {
      return res.status(409).json({ error: "A passport has already been issued for this incident." });
    }

    const incident = await prisma.incident.findUnique({
      where: { id: body.incidentId },
      include: {
        snapshot: { select: { id: true, inputHash: true, label: true } },
        huntRun: { select: { id: true, evidenceReceiptId: true } },
        containmentPlans: {
          where: { status: "APPROVED" },
          orderBy: { approvedAt: "desc" },
          take: 1,
          include: { requestedBy: { select: { id: true, name: true } } },
        },
      },
    });
    if (!incident) return res.status(404).json({ error: "Incident not found." });

    const approvedPlan = incident.containmentPlans[0];
    const br = incident.blastRadius as {
      risk_score?: number;
      impacted_nodes?: unknown[];
      crown_jewel_exposure?: boolean;
    } | null;

    const snapshot: IncidentPassportSnapshot = {
      schemaVersion: 1,
      incident: {
        id: incident.id,
        title: incident.title,
        severity: incident.severity,
        policyId: null,
        snapshotId: incident.snapshotId,
        snapshotInputHash: incident.snapshot.inputHash,
      },
      hunt: incident.huntRun
        ? {
            runId: incident.huntRun.id,
            configHash: incident.huntRun.evidenceReceiptId ?? "",
            resultHash: sha256Json(incident.huntRun),
          }
        : null,
      blastRadius: br
        ? {
            riskScore: br.risk_score ?? 0,
            impactedAssets: br.impacted_nodes?.length ?? 0,
            crownJewelExposure: br.crown_jewel_exposure ?? false,
          }
        : null,
      containment: approvedPlan
        ? {
            planId: approvedPlan.id,
            actions: (approvedPlan.actions as Array<{ type: string; target: string }>) ?? [],
            approvedAt: approvedPlan.approvedAt?.toISOString() ?? "",
            approvedById: req.authUser!.id,
            approvedByName: req.authUser!.name,
          }
        : null,
      approval: {
        decision: "ISSUED",
        issuedById: req.authUser!.id,
        issuedByName: req.authUser!.name,
        issuedAt: new Date().toISOString(),
      },
    };

    const signingSecret = process.env.PASSPORT_SECRET;
    if (!signingSecret || signingSecret.length < 32) {
      return res
        .status(500)
        .json({ error: "PASSPORT_SECRET is not configured. Set a strong secret." });
    }

    const { passportHash } = createIncidentPassport(snapshot, signingSecret);

    const passport = await prisma.incidentPassport.create({
      data: {
        incidentId: body.incidentId,
        issuedById: req.authUser!.id,
        passportHash,
        snapshot: snapshot as object,
        status: "ISSUED",
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "PASSPORT_ISSUE",
        actorId: req.authUser!.id,
        targetId: passport.id,
        payload: { passportId: passport.id, passportHash },
      },
    });

    return res.status(201).json(passport);
  },
);

/** GET /api/passport/:id/verify — public verification endpoint (no auth required) */
passportRouter.get("/:id/verify", async (req, res) => {
  const passport = await prisma.incidentPassport.findUnique({
    where: { id: String(req.params["id"] ?? "") },
    select: { id: true, passportHash: true, snapshot: true, status: true, issuedAt: true },
  });

  if (!passport) {
    return res.status(404).json({ valid: false, error: "Passport not found." });
  }

  if (passport.status === "REVOKED") {
    return res.json({ valid: false, reason: "REVOKED", id: passport.id, issuedAt: passport.issuedAt });
  }

  const signingSecret = process.env.PASSPORT_SECRET;
  if (!signingSecret || signingSecret.length < 32) {
    return res.status(500).json({ error: "Server is not configured for passport verification." });
  }

  const valid = verifyIncidentPassportHash(
    passport.snapshot,
    passport.passportHash,
    signingSecret,
  );

  return res.json({
    valid,
    id: passport.id,
    passportHash: passport.passportHash,
    issuedAt: passport.issuedAt,
    ...(valid ? { snapshot: passport.snapshot } : {}),
  });
});
