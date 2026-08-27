import test from "node:test";
import assert from "node:assert/strict";
import handler from "../api/admin-stats.mjs";

function fakeRes() {
  const res = {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
  return res;
}

function request(authorization) {
  return { method: "GET", headers: authorization ? { authorization } : {} };
}

test("503 when ADMIN_SECRET is not configured", async () => {
  delete process.env.ADMIN_SECRET;
  const res = fakeRes();
  await handler(request("Bearer anything"), res);
  assert.equal(res.statusCode, 503);
});

test("401 on missing secret", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  const res = fakeRes();
  await handler(request(undefined), res);
  assert.equal(res.statusCode, 401);
  assert.deepEqual(res.body, { error: "unauthorized" });
});

test("401 on wrong secret", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  const res = fakeRes();
  await handler(request("Bearer nope"), res);
  assert.equal(res.statusCode, 401);
});

test("401 on same-length wrong secret (timing-safe path)", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  const res = fakeRes();
  await handler(request("Bearer topsecreX"), res);
  assert.equal(res.statusCode, 401);
});

test("404 on non-GET", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  const res = fakeRes();
  await handler({ method: "POST", headers: { authorization: "Bearer topsecret" } }, res);
  assert.equal(res.statusCode, 404);
});

test("right secret passes auth and reaches the KV layer", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  delete process.env.KV_REST_API_URL;
  delete process.env.KV_REST_API_TOKEN;
  delete process.env.UPSTASH_REDIS_REST_URL;
  delete process.env.UPSTASH_REDIS_REST_TOKEN;
  const res = fakeRes();
  await handler(request("Bearer topsecret"), res);
  // No KV configured in tests: auth succeeded, so we get 503 kv_unavailable, not 401.
  assert.equal(res.statusCode, 503);
  assert.deepEqual(res.body, { error: "kv_unavailable" });
});

test("returns aggregated numbers when KV responds", async () => {
  process.env.ADMIN_SECRET = "topsecret";
  process.env.KV_REST_API_URL = "https://kv.test";
  process.env.KV_REST_API_TOKEN = "kv-token";
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, options) => {
    assert.equal(url, "https://kv.test/pipeline");
    const commands = JSON.parse(options.body);
    assert.equal(commands.length, 4);
    const zeros = (n) => Array.from({ length: n }, () => null);
    return {
      ok: true,
      json: async () => [
        { result: [ "5", ...zeros(29) ] },
        { result: [ "1000000", ...zeros(29) ] },
        { result: [ "2000000", ...zeros(29) ] },
        { result: 7 },
      ],
    };
  };
  try {
    const res = fakeRes();
    await handler(request("Bearer topsecret"), res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.uniqueInstalls, 7);
    assert.equal(res.body.totals.actions, 5);
    assert.equal(res.body.totals.inputTokens, 1_000_000);
    assert.equal(res.body.totals.outputTokens, 2_000_000);
    // 1M in @ $0.25/MTok + 2M out @ $1.50/MTok
    assert.equal(res.body.totals.estCostUsd, 3.25);
    assert.equal(res.body.days.length, 30);
  } finally {
    globalThis.fetch = realFetch;
    delete process.env.KV_REST_API_URL;
    delete process.env.KV_REST_API_TOKEN;
  }
});
