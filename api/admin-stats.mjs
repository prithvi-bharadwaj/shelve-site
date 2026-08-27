// Owner-only cost dashboard data. Bearer ADMIN_SECRET protected; serves only
// the aggregate numbers generate.mjs records (per-day actions and token
// totals, unique install count) — there is nothing user-identifying to leak,
// but the secret keeps spend figures private.
//
// Env: ADMIN_SECRET (required), plus the same KV vars as generate.mjs.

import { timingSafeEqual } from "node:crypto";

// USD per million input/output tokens by model. Days recorded with a model
// missing from this map report tokens with a null cost rather than a wrong one.
const PRICES = {
  "gemini-3.1-flash-lite": [0.25, 1.5],
  "gemini-2.5-flash-lite": [0.1, 0.4],
  "gemini-2.5-flash": [0.3, 2.5],
  "gemini-3.5-flash": [1.5, 9],
};
const DEFAULT_MODEL = "gemini-3.1-flash-lite";
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

function costUsd(inputTokens, outputTokens, model) {
  const price = PRICES[model];
  if (!price) return null;
  const cost = (inputTokens / 1e6) * price[0] + (outputTokens / 1e6) * price[1];
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
      ["mget", ...dates.map((d) => `s:mdl:${d}`)],
      ["scard", `s:u:${dates[0]}`],
      ["sunion", ...dates.slice(0, 7).map((d) => `s:u:${d}`)],
    ]);
  } catch {
    return res.status(502).json({ error: "kv_error" });
  }

  const [actionsRes, inRes, outRes, modelRes, todayRes, weekRes] = results.map((r) => r?.result);
  const days = dates.map((date, i) => {
    const actions = Number(actionsRes?.[i]) || 0;
    const inputTokens = Number(inRes?.[i]) || 0;
    const outputTokens = Number(outRes?.[i]) || 0;
    const model = modelRes?.[i] || DEFAULT_MODEL;
    return { date, actions, inputTokens, outputTokens, model, estCostUsd: costUsd(inputTokens, outputTokens, model) };
  });
  const totals = days.reduce(
    (acc, day) => ({
      actions: acc.actions + day.actions,
      inputTokens: acc.inputTokens + day.inputTokens,
      outputTokens: acc.outputTokens + day.outputTokens,
      estCostUsd: day.estCostUsd === null ? acc.estCostUsd : Math.round((acc.estCostUsd + day.estCostUsd) * 10_000) / 10_000,
    }),
    { actions: 0, inputTokens: 0, outputTokens: 0, estCostUsd: 0 }
  );

  res.setHeader("cache-control", "no-store");
  return res.status(200).json({
    generatedAt: new Date().toISOString(),
    windowDays: DAYS,
    uniqueInstallsToday: Number(todayRes) || 0,
    uniqueInstalls7d: Array.isArray(weekRes) ? weekRes.length : 0,
    totals,
    days,
  });
}
