import { randomBytes } from "node:crypto";

// ─── PII types recognised ─────────────────────────────────────────────────────
// Extended from BrandFlight (Indian-centric PII) to cover SOC-domain identifiers.

export const PII_TYPES = [
  "EMAIL",
  "IPV4",
  "IPV6",
  "HOSTNAME",
  "USERNAME",
  "API_TOKEN",
  "UUID",
  "WINDOWS_SID",
  // Legacy BrandFlight types kept for general coverage:
  "UPI_ID",
  "INDIAN_PHONE",
  "AADHAAR",
  "PAN",
  "CREDIT_CARD",
] as const;

export type PiiType = (typeof PII_TYPES)[number];

export interface PiiMatch {
  type: PiiType;
  start: number;
  end: number;
  value: string;
}

export interface PiiMaskSummary {
  masked: boolean;
  totalUniqueValues: number;
  categories: { type: PiiType; count: number }[];
}

/** Regexes ordered so more-specific patterns run first. */
const PATTERNS: { type: PiiType; re: RegExp }[] = [
  // SOC identifiers
  {
    type: "IPV6",
    re: /(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|::(?:[fF]{4}(?::0{1,4})?:)?(?:25[0-5]|(?:2[0-4]|1?\d)?\d)(?:\.(?:25[0-5]|(?:2[0-4]|1?\d)?\d)){3}/g,
  },
  {
    type: "IPV4",
    re: /\b(?:(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\.){3}(?:25[0-5]|(?:2[0-4]|1?\d)?\d)\b/g,
  },
  {
    type: "UUID",
    re: /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g,
  },
  {
    type: "WINDOWS_SID",
    re: /\bS-1-(?:\d+-)+\d+\b/g,
  },
  {
    type: "API_TOKEN",
    // Bearer/basic tokens and AWS-style keys
    re: /(?:bearer\s+|token[=:]\s*|key[=:]\s*|secret[=:]\s*)([A-Za-z0-9\-_/.+]{20,})/gi,
  },
  // Email (before general HOSTNAME with dots)
  {
    type: "EMAIL",
    re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  },
  {
    type: "HOSTNAME",
    // FQDN or internal hostname with at least one dot (e.g. host.internal, server.corp.com)
    re: /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,}[a-zA-Z]{2,}\b/g,
  },
  // Legacy
  { type: "UPI_ID", re: /\b[A-Za-z0-9.\-_]{2,256}@[A-Za-z]{2,64}\b/g },
  { type: "INDIAN_PHONE", re: /(?:\+91|0)?[6-9]\d{9}\b/g },
  { type: "AADHAAR", re: /\b\d{4}\s?\d{4}\s?\d{4}\b/g },
  { type: "PAN", re: /\b[A-Z]{5}[0-9]{4}[A-Z]\b/g },
  {
    type: "CREDIT_CARD",
    re: /\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b/g,
  },
];

/**
 * Creates a session-scoped PII masking context.
 * Call mask() before sending text to any LLM.
 * Call restore() on the returned text to put original values back.
 */
export function createPiiMaskingSession() {
  const nonce = randomBytes(4).toString("hex").toUpperCase();
  const prefix = `[[GOPII_${nonce}_`;
  const valueByToken = new Map<string, string>();
  const tokenByValue = new Map<string, string>();
  const typeByToken = new Map<string, PiiType>();
  const counterByType = new Map<PiiType, number>();

  function allocateToken(value: string, type: PiiType): string {
    const existing = tokenByValue.get(value);
    if (existing) return existing;
    const count = (counterByType.get(type) ?? 0) + 1;
    counterByType.set(type, count);
    const token = `${prefix}${type}_${String(count).padStart(4, "0")}]]`;
    valueByToken.set(token.toUpperCase(), value);
    tokenByValue.set(value, token);
    typeByToken.set(token.toUpperCase(), type);
    return token;
  }

  function findMatches(value: string): PiiMatch[] {
    const matches: PiiMatch[] = [];
    for (const { type, re } of PATTERNS) {
      re.lastIndex = 0;
      let m: RegExpExecArray | null;
      while ((m = re.exec(value)) !== null) {
        // For API_TOKEN pattern the actual token is capture group 1
        const matchValue = type === "API_TOKEN" ? (m[1] ?? m[0]) : m[0];
        const offset = type === "API_TOKEN" ? m.index + (m[0].length - matchValue.length) : m.index;
        matches.push({ type, start: offset, end: offset + matchValue.length, value: matchValue });
      }
    }
    // Sort by start; drop overlapping (keep first found)
    matches.sort((a, b) => a.start - b.start);
    const deduped: PiiMatch[] = [];
    let cursor = 0;
    for (const match of matches) {
      if (match.start >= cursor) {
        deduped.push(match);
        cursor = match.end;
      }
    }
    return deduped;
  }

  function mask(value: string): string {
    const matches = findMatches(value);
    if (matches.length === 0) return value;

    let output = "";
    let cursor = 0;
    for (const match of matches) {
      output += value.slice(cursor, match.start);
      output += allocateToken(match.value, match.type);
      cursor = match.end;
    }
    return output + value.slice(cursor);
  }

  function restore(value: string): string {
    if (!value.includes(prefix)) return value;
    const tokenRe = new RegExp(`\\[\\[GOPII_${nonce}_[A-Z0-9_]+_[0-9]{4}\\]\\]`, "gi");
    const restored = value.replace(tokenRe, (token) => {
      const original = valueByToken.get(token.toUpperCase());
      if (original === undefined) {
        throw new Error("An unknown PII placeholder was returned by the AI provider.");
      }
      return original;
    });
    if (restored.includes(prefix)) {
      throw new Error("A PII placeholder could not be safely restored.");
    }
    return restored;
  }

  function summary(): PiiMaskSummary {
    const counts = new Map<PiiType, number>();
    for (const type of typeByToken.values()) {
      counts.set(type, (counts.get(type) ?? 0) + 1);
    }
    return {
      masked: valueByToken.size > 0,
      totalUniqueValues: valueByToken.size,
      categories: PII_TYPES.flatMap((type) => {
        const count = counts.get(type) ?? 0;
        return count > 0 ? [{ type, count }] : [];
      }),
    };
  }

  return { mask, restore, summary };
}
