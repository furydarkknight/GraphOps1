import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { apiLimiter } from "./middleware/rate-limit.js";
import { requireAuth } from "./middleware/auth.js";

import { authRouter } from "./routes/auth.js";
import { healthRouter } from "./routes/health.js";
import { ingestRouter } from "./routes/ingest.js";
import { graphRouter } from "./routes/graph.js";
import { huntsRouter } from "./routes/hunts.js";
import { pathsRouter } from "./routes/paths.js";
import { blastRadiusRouter } from "./routes/blast-radius.js";
import { containmentRouter } from "./routes/containment.js";
import { incidentsRouter } from "./routes/incidents.js";
import { alertsRouter } from "./routes/alerts.js";
import { reportRouter } from "./routes/report.js";
import { passportRouter } from "./routes/passport.js";
import { copilotRouter } from "./routes/copilot.js";
import { kpiRouter } from "./routes/kpi.js";

export const app = express();

// ─── Security & parsing ───────────────────────────────────────────────────────
app.use(
  helmet({
    crossOriginResourcePolicy: { policy: "cross-origin" },
  }),
);
app.use(
  cors({
    origin: process.env.CLIENT_ORIGIN ?? "http://localhost:5173",
    credentials: true,
  }),
);
app.use(express.json({ limit: "10mb" }));
app.use(apiLimiter);

// ─── Public routes ────────────────────────────────────────────────────────────
app.use("/api/health", healthRouter);
app.use("/api/auth", authRouter);

// /api/auth/me requires auth — apply separately
app.get("/api/auth/me", requireAuth, (req, res) => {
  res.json(req.authUser);
});

// Public passport verify
app.use("/api/passport", passportRouter);

// ─── Protected routes ─────────────────────────────────────────────────────────
app.use("/api/ingest", ingestRouter);
app.use("/api/graph", graphRouter);
app.use("/api/hunts", huntsRouter);
app.use("/api/paths", pathsRouter);
app.use("/api/blast-radius", blastRadiusRouter);
app.use("/api/containment", containmentRouter);
app.use("/api/incidents", incidentsRouter);
app.use("/api/alerts", alertsRouter);
app.use("/api/report", reportRouter);
app.use("/api/copilot", copilotRouter);
app.use("/api/kpi", kpiRouter);

// ─── Static Client Frontend (Production & Monorepo) ───────────────────────────
import path from "node:path";
import fs from "node:fs";

const possibleDistPaths = [
  path.resolve(process.cwd(), "../client/dist"),
  path.resolve(process.cwd(), "client/dist"),
  path.resolve(import.meta.dirname ?? "", "../../client/dist"),
];
const clientDist = possibleDistPaths.find((p) => fs.existsSync(p));
if (clientDist) {
  app.use(express.static(clientDist));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith("/api")) return next();
    res.sendFile(path.join(clientDist, "index.html"));
  });
}

// ─── 404 handler ─────────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: "Route not found." });
});

// ─── Error handler ────────────────────────────────────────────────────────────
app.use(
  (
    err: unknown,
    _req: express.Request,
    res: express.Response,
    _next: express.NextFunction,
  ) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal server error." });
  },
);
