// Shelve free-actions proxy — Vercel serverless port of worker/src/index.ts
// in the shelve repo. Lets new installs try AI actions with no API key.
//
// Privacy contract (public): request bodies pass through to Gemini and are
// never stored. Persisted state is installToken -> action count only. No
// URLs, titles, or IPs are written.
//
// Env (Vercel project settings):
//   GEMINI_API_KEY  — required, a budget-capped key
//   KV_REST_API_URL / KV_REST_API_TOKEN — Upstash/Vercel KV REST creds.
//     Missing KV fails OPEN (unmetered) so the free tier never bricks;
//     the Gemini budget cap is the backstop. A warning is logged.
//   FREE_ACTIONS    — default "25"
//   MODEL           — default "gemini-3.1-flash-lite"
//   ALLOW_TOKENS    — comma-separated install tokens with unlimited use
//                     (owner + friends)

const GEMINI_BASE = "https://generativelanguage.googleapis.com/v1beta/models";
const TOKEN_RE = /^[a-f0-9-]{36}$/;
const TTL_S = 60 * 60 * 24 * 90;

function kvCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url, token } : null;
}

async function kv(cmd) {
  const creds = kvCreds();
  if (!creds) return null;
  const resp = await fetch(`${creds.url}/${cmd.join("/")}`, {
    headers: { Authorization: `Bearer ${creds.token}` },
  });
  if (!resp.ok) throw new Error(`KV error ${resp.status}`);
  return (await resp.json()).result;
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

  const limit = Number(process.env.FREE_ACTIONS || "25");
  const allowlisted = (process.env.ALLOW_TOKENS || "")
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean)
    .includes(token);

  let used = 0;
  let metered = false;
  if (!allowlisted) {
    try {
      const stored = await kv(["get", token]);
      metered = stored !== null || kvCreds() !== null;
      used = Number(stored || "0");
    } catch (err) {
      console.warn("metering unavailable, failing open:", err.message);
    }
    if (used >= limit) {
      return res.status(402).json({ error: "free_actions_exhausted", used, limit });
    }
  }

  const model = process.env.MODEL || "gemini-3.1-flash-lite";
  const upstream = await fetch(`${GEMINI_BASE}/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(req.body),
  });

  // Count only successful generations — provider outages must not burn actions.
  if (upstream.ok && !allowlisted && metered) {
    try {
      await kv(["incr", token]);
      await kv(["expire", token, String(TTL_S)]);
    } catch (err) {
      console.warn("metering incr failed:", err.message);
    }
  }

  const remaining = allowlisted ? limit : Math.max(0, limit - used - (upstream.ok ? 1 : 0));
  res.setHeader("x-shelve-actions-remaining", String(remaining));
  res.status(upstream.status);
  res.setHeader("content-type", "application/json");
  return res.send(await upstream.text());
}
