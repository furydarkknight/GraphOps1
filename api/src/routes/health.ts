import { Router } from "express";
import { analyticsClient } from "../lib/analytics-client.js";
import { getGeminiMode } from "../lib/gemini.js";

export const healthRouter = Router();

healthRouter.get("/", async (_req, res) => {
  let analyticsStatus: { model_mode: string; llm_mode: string } | null = null;
  let analyticsReachable = false;

  try {
    const aHealth = await analyticsClient.health();
    analyticsStatus = {
      model_mode: aHealth.model_mode,
      llm_mode: aHealth.llm_mode,
    };
    analyticsReachable = true;
  } catch {
    // analytics may not be up yet during startup
  }

  return res.json({
    status: "ok",
    version: "0.1.0",
    llm_mode: getGeminiMode(),
    model_mode: analyticsStatus?.model_mode ?? "unknown",
    analytics_reachable: analyticsReachable,
    timestamp: new Date().toISOString(),
  });
});
