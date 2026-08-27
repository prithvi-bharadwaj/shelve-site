// Shelve hosted-actions proxy. Assume every caller is adversarial: the URL is
// public by nature (any extension's traffic is inspectable), so safety comes
// from server-side limits, not secrecy.
//
// Privacy contract (public, mirrored in /privacy): request bodies pass through
// to Gemini and are never stored. Persisted state is per-token counters,
// entitlement flags, and aggregate daily totals (action and token counts)
// only. No URLs, titles, IPs, or request content are written.
//
// Env:
//   GEMINI_API_KEY            required, budget-capped key
//   KV_REST_API_URL/TOKEN     Upstash REST (Vercel KV). Missing KV fails
//                             CLOSED (503) — an unmetered open proxy is worse
//                             than a briefly broken free tier.
//   FREE_DAILY                free actions per day per install (default 30)
//   GLOBAL_DAILY              circuit breaker: total actions/day across all
//                             installs (default 3000) — the real cap on token
//                             farming, since per-token caps can't stop minting
//   PAID_MONTHLY              actions per month for paid tokens (default 1500)
//   ALLOW_TOKENS              comma-separated unlimited tokens (owner+friends)
//   MODEL                     pinned model (default gemini-3.1-flash-lite)
//   SPEND_MONTHLY_USD         hard stop on estimated Gemini spend per calendar
//                             month (default 10). Applies to every caller,
//                             allowlisted included — it protects the key.
//   SPEND_TOTAL_USD           lifetime hard stop on estimated spend (default
//                             100) for keys with a fixed credit balance

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";
const TOKEN_RE = /^[a-f0-9-]{36}$/;
const TTL_S = 60 * 60 * 24 * 90;
const DAY_TTL_S = 60 * 60 * 48;
const STATS_TTL_S = 60 * 60 * 24 * 35; // admin dashboard reads the last 30 days

// Sized to legitimate traffic (75 tabs + snippets), not to what a caller might
// wish for. Everything outside the whitelist is dropped.
const LIMITS = {
  bodyBytes: 96_000, // measured on the parsed body — Content-Length is a hint, not a boundary
  // Measured: typical organize prompt ~750 chars; worst legitimate case
  // (monochrome list + 2K custom instructions + many existing groups) ~4.3K.
  systemChars: 6_000,
  contentChars: 64_000, // ~16K tokens — 75 tabs with snippets fits with room
  contentTurns: 2,
  schemaBytes: 8_000, // PLAN_SCHEMA is ~1-2K; a megabyte "schema" is an attack
  maxOutputTokens: 1024,
};

// USD per million input/output tokens. token count × price-per-Mtok = micro-USD,
// so spend accumulates in KV as integer microdollars with no float drift.
const SPEND_PRICES = {
  "gemini-3.1-flash-lite": [0.25, 1.5],
  "gemini-2.5-flash-lite": [0.1, 0.4],
  "gemini-2.5-flash": [0.3, 2.5],
  "gemini-3.5-flash": [1.5, 9],
};

export function estimateMicroUsd(inputTokens, outputTokens, model) {
  const [inPrice, outPrice] = SPEND_PRICES[model] || SPEND_PRICES["gemini-3.1-flash-lite"];
  return Math.ceil(inputTokens * inPrice + outputTokens * outPrice);
}

function kvCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url, token } : null;
}

async function kv(creds, ...cmd) {
  const resp = await fetch(`${creds.url}/${cmd.map(encodeURIComponent).join("/")}`, {
    headers: { Authorization: `Bearer ${creds.token}` },
  });
  if (!resp.ok) throw new Error(`KV ${resp.status}`);
  return (await resp.json()).result;
}

// One round trip for a batch of commands (Upstash REST /pipeline).
async function kvPipeline(creds, commands) {
  const resp = await fetch(`${creds.url}/pipeline`, {
    method: "POST",
    headers: { Authorization: `Bearer ${creds.token}` },
    body: JSON.stringify(commands),
  });
  if (!resp.ok) throw new Error(`KV ${resp.status}`);
  return resp.json();
}

// Owner cost visibility, within the privacy contract above: AGGREGATE numbers
// only — per-day action and token totals, plus the set of anonymous install
// tokens (which KV already holds as counter keys). Never URLs, titles, IPs, or
// request/response content. Failures are swallowed; stats must not break
// generation.
async function recordAggregateStats(creds, token, responseText) {
  let usage;
  try {
    usage = JSON.parse(responseText)?.usageMetadata;
  } catch {
    usage = null;
  }
  const input = Number(usage?.promptTokenCount) || 0;
  const output = Number(usage?.candidatesTokenCount) || 0;
  const day = today();
  const micro = estimateMicroUsd(input, output, process.env.MODEL || "gemini-3.1-flash-lite");
  await kvPipeline(creds, [
    // Running spend estimate, read by the budget gate below and the daily
    // report. Monthly key outlives the stats window; total never expires.
    ["incrby", `s:spend:${month()}`, String(micro)],
    ["expire", `s:spend:${month()}`, String(60 * 60 * 24 * 62)],
    ["incrby", "s:spend:total", String(micro)],
    ["incr", `s:a:${day}`],
    ["expire", `s:a:${day}`, String(STATS_TTL_S)],
    ["incrby", `s:i:${day}`, String(input)],
    ["expire", `s:i:${day}`, String(STATS_TTL_S)],
    ["incrby", `s:o:${day}`, String(output)],
    ["expire", `s:o:${day}`, String(STATS_TTL_S)],
    // Per-day unique sets expire with the stats window — an attacker minting
    // fresh tokens can no longer grow storage without bound.
    ["sadd", `s:u:${day}`, token],
    ["expire", `s:u:${day}`, String(STATS_TTL_S)],
    // Day-granular model marker so the dashboard prices tokens correctly even
    // if the MODEL env changes mid-window.
    ["set", `s:mdl:${day}`, process.env.MODEL || "gemini-3.1-flash-lite"],
    ["expire", `s:mdl:${day}`, String(STATS_TTL_S)],
  ]);
}

// Atomic reserve: INCR first, judge the returned value, refund on rejection or
// upstream failure. Check-then-increment loses to concurrent bursts.
async function reserve(creds, key, limit, ttl) {
  const count = Number(await kv(creds, "incr", key));
  await kv(creds, "expire", key, String(ttl)).catch(() => undefined);
  if (count > limit) {
    await kv(creds, "decr", key).catch(() => undefined);
    return { ok: false, count };
  }
  return { ok: true, count };
}

function textOnlyParts(parts, budget) {
  const out = [];
  for (const part of Array.isArray(parts) ? parts : []) {
    if (typeof part?.text !== "string") continue; // drops inlineData/fileData/etc.
    out.push({ text: part.text.slice(0, budget.remaining) });
    budget.remaining -= out[out.length - 1].text.length;
    if (budget.remaining <= 0) break;
  }
  return out;
}

// Rebuild the request from a strict whitelist — unknown fields (tools, cached
// content, media parts, generation knobs) never reach Gemini.
function sanitizeRequest(body) {
  const budget = { remaining: LIMITS.contentChars };
  const contents = (Array.isArray(body?.contents) ? body.contents : [])
    .slice(0, LIMITS.contentTurns)
    .map((turn) => ({ role: turn?.role === "model" ? "model" : "user", parts: textOnlyParts(turn?.parts, budget) }))
    .filter((turn) => turn.parts.length > 0);
  if (!contents.length) return null;

  const sanitized = { contents };
  const systemText = body?.systemInstruction?.parts?.map((p) => (typeof p?.text === "string" ? p.text : "")).join("\n");
  if (systemText) {
    sanitized.systemInstruction = { parts: [{ text: systemText.slice(0, LIMITS.systemChars) }] };
  }
  const cfg = body?.generationConfig || {};
  const schemaOk =
    cfg.responseSchema &&
    typeof cfg.responseSchema === "object" &&
    JSON.stringify(cfg.responseSchema).length <= LIMITS.schemaBytes;
  if (cfg.responseSchema && !schemaOk) return null; // oversized schema is hostile, reject
  sanitized.generationConfig = {
    maxOutputTokens: LIMITS.maxOutputTokens,
    ...(cfg.responseMimeType === "application/json" ? { responseMimeType: "application/json" } : {}),
    ...(schemaOk ? { responseSchema: cfg.responseSchema } : {}),
  };
  return sanitized;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function month() {
  return new Date().toISOString().slice(0, 7);
}

export default async function handler(req, res) {
  res.setHeader("access-control-allow-origin", "*");
  if (req.method === "OPTIONS") {
    res.setHeader("access-control-allow-methods", "POST");
    res.setHeader("access-control-allow-headers", "authorization,content-type");
    return res.status(204).end();
  }
  if (req.method !== "POST") return res.status(404).json({ error: "Not found." });

  const token = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  if (!TOKEN_RE.test(token)) return res.status(401).json({ error: "Missing install token." });

  // Content-Length is only a fast-path hint; the real cap is measured on the
  // parsed body (chunked requests legally omit the header).
  if (Number(req.headers["content-length"] || 0) > LIMITS.bodyBytes) {
    return res.status(413).json({ error: "request_too_large" });
  }
  let bodyBytes = 0;
  try {
    bodyBytes = Buffer.byteLength(JSON.stringify(req.body ?? null), "utf8");
  } catch {
    return res.status(400).json({ error: "Invalid request body." });
  }
  if (bodyBytes > LIMITS.bodyBytes) {
    return res.status(413).json({ error: "request_too_large" });
  }

  const sanitized = sanitizeRequest(req.body);
  if (!sanitized) return res.status(400).json({ error: "Invalid request body." });

  const allowlisted = (process.env.ALLOW_TOKENS || "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean)
    .includes(token);

  const creds = kvCreds();
  if (!creds && !allowlisted) {
    // Fail closed: no metering means no service, never an open faucet.
    return res.status(503).json({ error: "metering_unavailable" });
  }

  // Budget gate: the key has a fixed credit balance, so estimated spend is a
  // hard stop for everyone, allowlisted included. Tier-neutral "capacity"
  // response — indistinguishable from the global daily breaker.
  if (creds) {
    try {
      const spend = await kvPipeline(creds, [
        ["get", `s:spend:${month()}`],
        ["get", "s:spend:total"],
      ]);
      const monthMicro = Number(spend?.[0]?.result) || 0;
      const totalMicro = Number(spend?.[1]?.result) || 0;
      const monthCapMicro = Number(process.env.SPEND_MONTHLY_USD || "10") * 1e6;
      const totalCapMicro = Number(process.env.SPEND_TOTAL_USD || "100") * 1e6;
      if (monthMicro >= monthCapMicro || totalMicro >= totalCapMicro) {
        return res.status(503).json({ error: "capacity", retryTomorrow: true });
      }
    } catch {
      return res.status(503).json({ error: "metering_unavailable" });
    }
  }

  // Entitlement tiers: allowlisted > paid (Stripe webhook sets paid:<token>) > free.
  // Reservations are atomic (INCR-then-judge) so concurrent bursts cannot slip
  // past the thresholds; failed upstream calls are refunded below.
  let tier = "unlimited";
  let limit = Infinity;
  let reservedKeys = [];
  let used = 0;
  if (!allowlisted) {
    try {
      const globalRes = await reserve(creds, `g:${today()}`, Number(process.env.GLOBAL_DAILY || "3000"), DAY_TTL_S);
      if (!globalRes.ok) return res.status(503).json({ error: "capacity", retryTomorrow: true });
      reservedKeys.push(`g:${today()}`);

      const paid = await kv(creds, "get", `paid:${token}`);
      if (paid === "active") {
        tier = "paid";
        limit = Number(process.env.PAID_MONTHLY || "1500");
        const r = await reserve(creds, `m:${token}:${month()}`, limit, TTL_S);
        if (!r.ok) {
          await kv(creds, "decr", `g:${today()}`).catch(() => undefined);
          return res.status(402).json({ error: "paid_quota_exhausted", limit });
        }
        reservedKeys.push(`m:${token}:${month()}`);
        used = r.count;
      } else {
        tier = "free";
        limit = Number(process.env.FREE_DAILY || "30");
        const r = await reserve(creds, `d:${token}:${today()}`, limit, DAY_TTL_S);
        if (!r.ok) {
          await kv(creds, "decr", `g:${today()}`).catch(() => undefined);
          return res.status(429).json({ error: "daily_limit", retryTomorrow: true });
        }
        reservedKeys.push(`d:${token}:${today()}`);
        used = r.count;
      }
    } catch {
      return res.status(503).json({ error: "metering_unavailable" });
    }
  }

  const model = process.env.MODEL || "gemini-3.1-flash-lite";
  let upstream;
  try {
    upstream = await fetch(`${GEMINI_BASE}/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(sanitized),
    });
  } catch {
    upstream = null;
  }

  // Refund reservations for failed generations — outages must not burn quota.
  if ((!upstream || !upstream.ok) && reservedKeys.length) {
    await Promise.all(reservedKeys.map((key) => kv(creds, "decr", key).catch(() => undefined)));
  }
  if (!upstream) return res.status(502).json({ error: "provider_unreachable" });

  const responseText = await upstream.text();
  // Await (don't fire-and-forget): the serverless runtime may freeze right
  // after the response is sent, dropping in-flight KV writes. But bound it —
  // best-effort telemetry must never turn a successful generation into a
  // client-visible stall.
  if (upstream.ok && creds) {
    await Promise.race([
      recordAggregateStats(creds, token, responseText).catch(() => undefined),
      new Promise((resolve) => setTimeout(resolve, 1500)),
    ]);
  }

  const remaining = tier === "unlimited" ? "unlimited" : String(Math.max(0, limit - (upstream.ok ? used : used - 1)));
  res.setHeader("x-shelve-actions-remaining", remaining);
  res.setHeader("content-type", "application/json");
  res.status(upstream.status);
  return res.send(responseText);
}
