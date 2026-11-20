import assert from "node:assert/strict";
import test from "node:test";
import { createPiiMaskingSession } from "../../src/lib/pii-masking.js";

test("masks and restores common SOC entities: IPv4, IPv6, email, hostname, username, token", () => {
  const session = createPiiMaskingSession();
  const original = "Analyst john.doe@soc.internal on host-sec.internal (10.200.5.12, 2001:db8::1) executed query with token=eyJhbGciOiJIUzI1NiJ9.testsecrettoken1234567890";
  const masked = session.mask(original);

  assert.equal(masked.includes("john.doe@soc.internal"), false);
  assert.equal(masked.includes("10.200.5.12"), false);
  assert.equal(masked.includes("2001:db8::1"), false);
  assert.equal(masked.includes("host-sec.internal"), false);
  assert.equal(masked.includes("eyJhbGciOiJIUzI1NiJ9.testsecrettoken1234567890"), false);

  assert.match(masked, /\[\[GOPII_[A-F0-9]+_EMAIL_\d{4}\]\]/);
  assert.match(masked, /\[\[GOPII_[A-F0-9]+_IPV4_\d{4}\]\]/);

  // Verifies lossless restoration
  assert.equal(session.restore(masked), original);
  assert.ok(session.summary().totalUniqueValues >= 4);
});

test("reuses a token for the same sensitive value across multiple sentences", () => {
  const session = createPiiMaskingSession();
  const first = session.mask("Compromised host 192.168.1.50 accessed C2");
  const second = session.mask("Pivot occurred from 192.168.1.50 to DC-01");
  const token = first.match(/\[\[GOPII_[A-F0-9]+_IPV4_\d{4}\]\]/)?.[0];

  assert.ok(token);
  assert.equal(second.includes(token), true);
  assert.equal(session.summary().totalUniqueValues, 1);
  assert.equal(session.restore(second), "Pivot occurred from 192.168.1.50 to DC-01");
});

test("does not mask standard benign technical phrases or metrics", () => {
  const session = createPiiMaskingSession();
  const text = "Detection latency was 14ms. MTTD dropped by 35%. 42 alerts triaged in 5 minutes.";
  assert.equal(session.mask(text), text);
  assert.deepEqual(session.summary(), {
    masked: false,
    totalUniqueValues: 0,
    categories: [],
  });
});

test("fails closed when an unknown request-scoped placeholder is returned by LLM", () => {
  const session = createPiiMaskingSession();
  const masked = session.mask("User admin@corp.com logged in");
  const knownToken = masked.match(/\[\[GOPII_[A-F0-9]+_EMAIL_\d{4}\]\]/)?.[0];
  assert.ok(knownToken);
  const fakeToken = knownToken.replace("EMAIL_0001", "EMAIL_9999");

  assert.throws(
    () => session.restore(`AI hallucinates token ${fakeToken}`),
    /unknown PII placeholder/i,
  );
});
