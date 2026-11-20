import { app } from "./index.js";

const port = Number(process.env.PORT ?? 3000);

app.listen(port, () => {
  console.log(`GraphOps API running on port ${port}`);
  console.log(`  LLM mode: ${process.env.GEMINI_API_KEY ? "gemini" : "rag_only (no GEMINI_API_KEY)"}`);
  console.log(`  Demo mode: ${process.env.DEMO_MODE === "true" ? "ENABLED" : "disabled"}`);
});
