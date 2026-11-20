import { GoogleGenAI } from "@google/genai";
import "dotenv/config";

const apiKey = process.env.GEMINI_API_KEY;
const ai = apiKey ? new GoogleGenAI({ apiKey }) : null;

export type CopilotMode = "gemini" | "rag_only";

export function getGeminiMode(): CopilotMode {
  return ai ? "gemini" : "rag_only";
}

export interface CopilotRequest {
  maskedQuery: string;
  ragContext: Array<{
    id: string;
    title: string;
    content: string;
    score: number;
    source: string;
  }>;
  incidentSummary?: {
    severity: string;
    huntLeads: number;
    blastRadiusScore?: number;
  };
}

export interface CopilotResponse {
  narrative: string;
  mode: CopilotMode;
  sources: string[];
}

const RAG_ONLY_PREFIX =
  "[No LLM — deterministic RAG only. Connect GEMINI_API_KEY for AI-generated narrative.]\n\n";

export async function runCopilot(
  req: CopilotRequest,
): Promise<CopilotResponse> {
  const sources = req.ragContext.map((r) => r.source);

  if (!ai) {
    // Deterministic fallback: surface retrieved context as plain text
    const narrative =
      RAG_ONLY_PREFIX +
      req.ragContext
        .map((r, i) => `[${i + 1}] ${r.title} (${r.source})\n${r.content.slice(0, 300)}...`)
        .join("\n\n");
    return { narrative, mode: "rag_only", sources };
  }

  const contextBlock = req.ragContext
    .map((r, i) => `[${i + 1}] ${r.title} (source: ${r.source})\n${r.content}`)
    .join("\n\n---\n\n");

  const prompt = `You are a SOC analyst copilot. Use ONLY the retrieved context below to explain the security situation. 
Cite sources using [1], [2] etc. Do NOT invent statistics, CVEs, hostnames, or IP addresses.
Every numeric claim must come from the INCIDENT SUMMARY provided, not invented.

INCIDENT SUMMARY:
${JSON.stringify(req.incidentSummary ?? {}, null, 2)}

ANALYST QUERY (PII already masked):
${req.maskedQuery}

RETRIEVED CONTEXT:
${contextBlock}

Respond in 3-5 sentences. Be direct and actionable. Label your response with the sources you used.`;

  try {
    const response = await ai.models.generateContent({
      model: process.env.GEMINI_MODEL ?? "gemini-2.0-flash-lite",
      contents: prompt,
    });
    const text = response.text ?? "";
    return { narrative: text, mode: "gemini", sources };
  } catch (err) {
    console.error("Gemini copilot call failed:", err);
    // Graceful degradation
    const narrative =
      RAG_ONLY_PREFIX +
      req.ragContext
        .map((r, i) => `[${i + 1}] ${r.title}\n${r.content.slice(0, 200)}...`)
        .join("\n\n");
    return { narrative, mode: "rag_only", sources };
  }
}
