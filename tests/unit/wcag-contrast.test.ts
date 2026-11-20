import assert from "node:assert/strict";
import test from "node:test";
import {
  contrastRatio,
  parseAccessibilityColorPairs,
  recommendAccessibleForeground,
  type AccessibilityColorPair,
} from "../../src/lib/wcag-contrast.js";

test("contrast ratio correctly handles black, white, and gray luminance", () => {
  assert.equal(contrastRatio("#000000", "#FFFFFF"), 21);
  assert.equal(contrastRatio("#FFFFFF", "#FFFFFF"), 1);
  assert.ok(Math.abs((contrastRatio("#777777", "#FFFFFF") ?? 0) - 4.478) < 0.002);
  assert.equal(contrastRatio("invalid-hex", "#FFFFFF"), null);
});

test("validates required 5 WCAG UI roles", () => {
  const validPairs: AccessibilityColorPair[] = [
    { role: "BODY_TEXT", foreground: "#0F172A", background: "#FFFFFF" },
    { role: "HEADING", foreground: "#1E293B", background: "#F8FAFC" },
    { role: "CTA_TEXT", foreground: "#FFFFFF", background: "#2563EB" },
    { role: "CAPTION", foreground: "#475569", background: "#FFFFFF" },
    { role: "UI_ELEMENT", foreground: "#0F172A", background: "#F1F5F9" },
  ];

  const parsed = parseAccessibilityColorPairs(validPairs);
  assert.ok(parsed);
  assert.equal(parsed.length, 5);
});

test("recommendAccessibleForeground picks optimal contrast between candidates", () => {
  const fgForDark = recommendAccessibleForeground("#0F172A", ["#000000", "#FFFFFF"]);
  assert.equal(fgForDark, "#FFFFFF");

  const fgForLight = recommendAccessibleForeground("#FFFFFF", ["#000000", "#FFFFFF"]);
  assert.equal(fgForLight, "#000000");
});
