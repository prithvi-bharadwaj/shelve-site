// Stripe webhook → server-side paid entitlements. Checkout links carry the
// install token as client_reference_id; a completed checkout marks
// paid:<token> = "active" in KV, which api/generate.mjs trusts. This is the
// paid/unpaid attribution point — entitlement lives server-side, never in the
// extension.
//
// Env: STRIPE_WEBHOOK_SECRET (whsec_...), plus the same KV vars as generate.
// Stripe setup (later, when payments go live): a Payment Link or Checkout
// Session with client_reference_id={installToken}, webhook pointed at
// /api/stripe-webhook for checkout.session.completed and
// customer.subscription.deleted.

import { createHmac, timingSafeEqual } from "node:crypto";

export const config = { api: { bodyParser: false } };

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

function verifySignature(rawBody, header, secret) {
  const parts = Object.fromEntries(header.split(",").map((kv) => kv.split("=")));
  if (!parts.t || !parts.v1) return false;
  // Reject replays older than 5 minutes.
  if (Math.abs(Date.now() / 1000 - Number(parts.t)) > 300) return false;
  const expected = createHmac("sha256", secret).update(`${parts.t}.${rawBody}`).digest("hex");
  try {
    return timingSafeEqual(Buffer.from(expected), Buffer.from(parts.v1));
  } catch {
    return false;
  }
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(404).end();
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const creds = kvCreds();
  if (!secret || !creds) return res.status(503).json({ error: "not_configured" });

  const rawBody = await readRawBody(req);
  const signature = req.headers["stripe-signature"] || "";
  if (!verifySignature(rawBody, signature, secret)) {
    return res.status(400).json({ error: "bad_signature" });
  }

  const event = JSON.parse(rawBody);
  const TOKEN_RE = /^[a-f0-9-]{36}$/;

  if (event.type === "checkout.session.completed") {
    const session = event.data?.object || {};
    const token = session.client_reference_id;
    if (TOKEN_RE.test(token || "")) {
      await kv(creds, "set", `paid:${token}`, "active");
      // Map the Stripe customer back to the token so cancellation can revoke.
      if (session.customer) await kv(creds, "set", `cust:${session.customer}`, token);
    }
  } else if (event.type === "customer.subscription.deleted") {
    const customer = event.data?.object?.customer;
    if (customer) {
      const token = await kv(creds, "get", `cust:${customer}`);
      if (token) await kv(creds, "del", `paid:${token}`);
    }
  }

  return res.status(200).json({ received: true });
}
