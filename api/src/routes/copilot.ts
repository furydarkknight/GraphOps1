import { Router } from "express";
import { z } from "zod";
import { requireAuth, requireMinRole } from "../middleware/auth.js";
import { validateBody } from "../middleware/validate.js";
import { analyticsClient, AnalyticsError } from "../lib/analytics-client.js";
import { analyticsLimiter } from "../middleware/rate-limit.js";
import { createPiiMaskingSession } from "../lib/pii-masking.js";

export const copilotRouter = Router();

const CopilotSchema = z.object({
  query: z.string().min(1).max(2000).trim(),
  incidentId: z.string().cuid().optional(),
  incidentSummary: z.record(z.unknown()).optional(),
});

/** POST /api/copilot — PII-masked query → RAG → optional Gemini LLM narrative */
copilotRouter.post(
  "/",
  requireAuth,
  requireMinRole("ANALYST"),
  analyticsLimiter,
  validateBody(CopilotSchema),
  async (_req, res) => {
    const body = res.locals.body as z.infer<typeof CopilotSchema>;

    // Mask PII before sending to analytics / LLM
    const session = createPiiMaskingSession();
    const maskedQuery = session.mask(body.query);

    let result;
    try {
      result = await analyticsClient.copilot({
        masked_query: maskedQuery,
        incident_summary: body.incidentSummary,
      });
    } catch (err) {
      if (err instanceof AnalyticsError) {
        return res.status(502).json({ error: "Analytics service error.", detail: err.message });
      }
      throw err;
    }

    // Restore PII in narrative (the LLM should only have used placeholders)
    let narrative: string;
    try {
      narrative = session.restore(result.narrative);
    } catch {
      // If restoration fails, return the masked narrative with a warning
      narrative = `[PII placeholder restoration warning]\n\n${result.narrative}`;
    }

    return res.json({
      narrative,
      mode: result.mode,
      sources: result.sources,
      piiMaskSummary: session.summary(),
    });
  },
);
