import test from "node:test";
import assert from "node:assert/strict";
import { failoverWorthy, normalizeGeminiStatus, capacityFailure } from "../api/generate.mjs";

test("key-level failures are failover-worthy", () => {
  for (const status of [null, 401, 403, 429, 500, 503]) {
    assert.equal(failoverWorthy(status), true, String(status));
  }
});

test("request-level failures and successes are not", () => {
  for (const status of [200, 400, 404, 413]) {
    assert.equal(failoverWorthy(status), false, String(status));
  }
});

test("a 400 API_KEY_INVALID from Gemini is a key failure, not a request failure", () => {
  const dead = JSON.stringify({ error: { code: 400, status: "INVALID_ARGUMENT", details: [{ reason: "API_KEY_INVALID" }] } });
  assert.equal(normalizeGeminiStatus(400, dead), 401);
  assert.equal(failoverWorthy(normalizeGeminiStatus(400, dead)), true);
  // Other 400s (malformed request) stay 400 and still burn quota.
  const malformed = JSON.stringify({ error: { code: 400, status: "INVALID_ARGUMENT", message: "bad schema" } });
  assert.equal(normalizeGeminiStatus(400, malformed), 400);
  assert.equal(normalizeGeminiStatus(200, "{}"), 200);
  assert.equal(normalizeGeminiStatus(503, ""), 503);
});

test("model fallback engages on capacity/outage, never on auth", () => {
  for (const status of [null, 429, 500, 503]) assert.equal(capacityFailure(status), true, String(status));
  for (const status of [200, 400, 401, 403, 404]) assert.equal(capacityFailure(status), false, String(status));
});
