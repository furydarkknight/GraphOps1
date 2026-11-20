import { Router } from "express";
import { z } from "zod";
import { prisma } from "../lib/prisma.js";
import { requireAuth, requireMinRole, requireRoles } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";
import {
  createEvidenceReceiptId,
  huntConfigHash,
  sha256Json,
} from "../lib/evidence-receipt.js";

export const huntsRouter = Router();

const HuntRuleSchema = z.object({
  ruleCode: z.string().min(1).max(50).toUpperCase().trim(),
  attackId: z.string().max(20).optional(),
  tactic: z.string().max(50).optional(),
  title: z.string().min(1).max(200).trim(),
  description: z.string().min(1).max(2000).trim(),
  pattern: z.record(z.unknown()).optional(),
  severity: z.enum(["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("MEDIUM"),
  policyId: z.string().cuid(),
});

const HuntRunSchema = z.object({
  snapshotId: z.string().cuid(),
  ruleIds: z.array(z.string().cuid()).min(1),
  parameters: z.record(z.unknown()).optional().default({}),
});

/** GET /api/hunts — list hunt rules */
huntsRouter.get("/", requireAuth, requireMinRole("ANALYST"), async (_req, res) => {
  const rules = await prisma.huntRule.findMany({
    orderBy: { createdAt: "desc" },
    include: { policy: { select: { id: true, name: true } } },
  });
  return res.json(rules);
});

/** POST /api/hunts — create hunt rule (SOC_MANAGER only) */
huntsRouter.post(
  "/",
  requireAuth,
  requireRoles("SOC_MANAGER"),
  validateBody(HuntRuleSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof HuntRuleSchema>;
    const rule = await prisma.huntRule.create({ data: body as any });
    return res.status(201).json(rule);
  },
);

/** POST /api/hunts/run — run hunt against a snapshot */
huntsRouter.post(
  "/run",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(HuntRunSchema),
  async (req, res) => {
    const body = res.locals.body as z.infer<typeof HuntRunSchema>;

    // Load snapshot
    const snapshot = await prisma.graphSnapshot.findUnique({
      where: { id: body.snapshotId },
    });
    if (!snapshot) return res.status(404).json({ error: "Snapshot not found." });

    // Load rules
    const rules = await prisma.huntRule.findMany({
      where: { id: { in: body.ruleIds }, isActive: true },
    });
    if (rules.length === 0) {
      return res.status(400).json({ error: "No active rules found for the given IDs." });
    }

    // Build config hash before the analytics call
    const configHash = huntConfigHash({
      policyId: rules[0]?.policyId ?? null,
      ruleIds: body.ruleIds,
      snapshotId: body.snapshotId,
      parameters: body.parameters,
    });

    let analyticsResult;
    try {
      analyticsResult = await analyticsClient.huntsRun({
        graph_json: snapshot.graphJson,
        rules: rules.map((r) => ({
          rule_code: r.ruleCode,
          attack_id: r.attackId,
          tactic: r.tactic,
          pattern: r.pattern,
          severity: r.severity,
        })),
        parameters: body.parameters,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    const resultHash = sha256Json(analyticsResult.hunt_leads);
    const receiptId = createEvidenceReceiptId();

    // Persist receipt
    await prisma.evidenceReceipt.create({
      data: {
        id: receiptId,
        inputHash: snapshot.inputHash,
        configHash,
        resultHash,
      },
    });

    // Persist hunt run
    const huntRun = await prisma.huntRun.create({
      data: {
        snapshotId: body.snapshotId,
        analystId: req.authUser!.id,
        parameters: { ruleIds: body.ruleIds, ...body.parameters } as object,
        results: { hunt_leads: analyticsResult.hunt_leads } as object,
        evidenceReceiptId: receiptId,
      },
    });

    // Audit log
    await prisma.auditLog.create({
      data: {
        kind: "HUNT_RUN",
        actorId: req.authUser!.id,
        targetId: huntRun.id,
        payload: { huntRunId: huntRun.id, receiptId, configHash, resultHash },
      },
    });

    return res.status(201).json({
      huntRun,
      evidenceReceiptId: receiptId,
      configHash,
      resultHash,
    });
  },
);

/** GET /api/hunts/run/:id — get hunt run result */
huntsRouter.get(
  "/run/:id",
  requireAuth,
  requireMinRole("ANALYST"),
  async (req, res) => {
    const run = await prisma.huntRun.findUnique({
      where: { id: String(req.params["id"] ?? "") },
      include: { analyst: { select: { id: true, name: true } } },
    });
    if (!run) return res.status(404).json({ error: "Hunt run not found." });
    return res.json(run);
  },
);
