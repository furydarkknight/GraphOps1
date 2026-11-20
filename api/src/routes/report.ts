import { Router } from "express";
import { z } from "zod";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";
import { prisma } from "../lib/prisma.js";

export const reportRouter = Router();

const ReportSchema = z.object({
  incidentId: z.string().cuid(),
});

/** POST /api/report — generate PDF incident report */
reportRouter.post(
  "/",
  requireAuth,
  requireMinRole("RESPONDER"),
  analyticsLimiter,
  validateBody(ReportSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof ReportSchema>;

    const incident = await prisma.incident.findUnique({
      where: { id: body.incidentId },
      include: {
        containmentPlans: { where: { status: "APPROVED" }, take: 1 },
        passport: { select: { passportHash: true, issuedAt: true } },
      },
    });
    if (!incident) return res.status(404).json({ error: "Incident not found." });

    let pdfBytes: Uint8Array;
    try {
      pdfBytes = await analyticsClient.reportPdf({ incident });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    res.set({
      "Content-Type": "application/pdf",
      "Content-Disposition": `attachment; filename="incident-${body.incidentId}.pdf"`,
      "Content-Length": String(pdfBytes.byteLength),
    });
    return res.send(Buffer.from(pdfBytes));
  },
);
