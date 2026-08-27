import test from "node:test";
import assert from "node:assert/strict";
import { failoverWorthy } from "../api/generate.mjs";

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
