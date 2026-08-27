// Owner-only cost dashboard data. Bearer ADMIN_SECRET protected; serves only
// the aggregate numbers generate.mjs records (per-day actions and token
// totals, unique install count) — there is nothing user-identifying to leak,
// but the secret keeps spend figures private.
//
// Env: ADMIN_SECRET (required), plus the same KV vars as generate.mjs.

import { timingSafeEqual } from "node:crypto";

// USD per million tokens for gemini-3.1-flash-lite (the pinned proxy model).
const PRICE_IN_PER_MTOK = 0.25;
const PRICE_OUT_PER_MTOK = 1.5;
const DAYS = 30;

function kvCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url, token } : null;
}

async function kvPipeline(creds, commands) {
  const resp = await fetch(`${creds.url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${creds.token}` },
    body: JSON.stringify(commands),
  });
  if (!resp.ok) throw new Error(`KV ${resp.status}`);
  return resp.json();
}

function authorized(req) {
  const secret = process.env.ADMIN_SECRET || "";
  if (!secret) return false;
  const presented = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  const a = Buffer.from(presented);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

function lastDays(count) {
  const days = [];
  const now = new Date();
  for (let i = 0; i < count; i++) {
    days.push(new Date(now.getTime() - i * 86_400_000).toISOString().slice(0, 10));
  }
  return days;
}

function costUsd(inputTokens, outputTokens) {
  const cost = (inputTokens / 1e6) * PRICE_IN_PER_MTOK + (outputTokens / 1e6) * PRICE_OUT_PER_MTOK;
  return Math.round(cost * 10_000) / 10_000;
}

export default async function handler(req, res) {
  if (req.method !== "GET") return res.status(404).json({ error: "Not found." });
  if (!process.env.ADMIN_SECRET) return res.status(503).json({ error: "not_configured" });
  if (!authorized(req)) return res.status(401).json({ error: "unauthorized" });

  const creds = kvCreds();
  if (!creds) return res.status(503).json({ error: "kv_unavailable" });

  const dates = lastDays(DAYS);
  let results;
  try {
    results = await kvPipeline(creds, [
      ["mget", ...dates.map((d) => `s:a:${d}`)],
      ["mget", ...dates.map((d) => `s:i:${d}`)],
      ["mget", ...dates.map((d) => `s:o:${d}`)],
      ["scard", "s:installs"],
    ]);
  } catch {
    return res.status(502).json({ error: "kv_error" });
  }

  const [actionsRes, inRes, outRes, installsRes] = results.map((r) => r?.result);
  const days = dates.map((date, i) => {
    const actions = Number(actionsRes?.[i]) || 0;
    const inputTokens = Number(inRes?.[i]) || 0;
    const outputTokens = Number(outRes?.[i]) || 0;
    return { date, actions, inputTokens, outputTokens, estCostUsd: costUsd(inputTokens, outputTokens) };
  });
  const totals = days.reduce(
    (acc, day) => ({
      actions: acc.actions + day.actions,
      inputTokens: acc.inputTokens + day.inputTokens,
      outputTokens: acc.outputTokens + day.outputTokens,
    }),
    { actions: 0, inputTokens: 0, outputTokens: 0 }
  );

  res.setHeader("cache-control", "no-store");
  return res.status(200).json({
    generatedAt: new Date().toISOString(),
    windowDays: DAYS,
    uniqueInstalls: Number(installsRes) || 0,
    totals: { ...totals, estCostUsd: costUsd(totals.inputTokens, totals.outputTokens) },
    days,
  });
}
