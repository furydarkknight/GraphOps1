// ─── WCAG contrast utilities (ported verbatim from BrandFlight) ───────────────
// Used by both server-side checks and client-side UI accessibility validation.

export type AccessibilityColorPair = {
  role: string;
  foreground: string;
  background: string;
};

const REQUIRED_ROLES = new Set([
  "BODY_TEXT",
  "HEADING",
  "CTA_TEXT",
  "CAPTION",
  "UI_ELEMENT",
]);

function hexToLinear(hex: string): number | null {
  const clean = hex.replace(/^#/, "");
  if (clean.length !== 6) return null;
  const r = parseInt(clean.slice(0, 2), 16);
  const g = parseInt(clean.slice(2, 4), 16);
  const b = parseInt(clean.slice(4, 6), 16);
  if (isNaN(r) || isNaN(g) || isNaN(b)) return null;
  const toLinear = (c: number) => {
    const s = c / 255;
    return s <= 0.04045 ? s / 12.92 : Math.pow((s + 0.055) / 1.055, 2.4);
  };
  return 0.2126 * toLinear(r) + 0.7152 * toLinear(g) + 0.0722 * toLinear(b);
}

export function contrastRatio(fg: string, bg: string): number | null {
  const l1 = hexToLinear(fg);
  const l2 = hexToLinear(bg);
  if (l1 === null || l2 === null) return null;
  const lighter = Math.max(l1, l2);
  const darker = Math.min(l1, l2);
  return Math.round(((lighter + 0.05) / (darker + 0.05)) * 1000) / 1000;
}

const MIN_CONTRAST: Record<string, number> = {
  BODY_TEXT: 4.5,
  HEADING: 4.5,
  CTA_TEXT: 4.5,
  CAPTION: 3.0,
  UI_ELEMENT: 3.0,
};

export function parseAccessibilityColorPairs(
  pairs: AccessibilityColorPair[],
): AccessibilityColorPair[] | null {
  const roles = new Set(pairs.map((p) => p.role));
  for (const r of REQUIRED_ROLES) {
    if (!roles.has(r)) return null;
  }
  for (const pair of pairs) {
    const ratio = contrastRatio(pair.foreground, pair.background);
    const min = MIN_CONTRAST[pair.role] ?? 4.5;
    if (ratio === null || ratio < min) return null;
  }
  return pairs;
}

export function recommendAccessibleForeground(
  background: string,
  candidates: string[] = ["#000000", "#FFFFFF"],
): string {
  let best = candidates[0] ?? "#000000";
  let bestRatio = -1;
  for (const c of candidates) {
    const ratio = contrastRatio(c, background) ?? 0;
    if (ratio > bestRatio) {
      bestRatio = ratio;
      best = c;
    }
  }
  return best;
}
