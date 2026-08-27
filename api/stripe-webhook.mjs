// Stripe webhook → server-side paid entitlements. Checkout links carry the
// install token as client_reference_id; a *confirmed* payment marks
// paid:<token> = "active" in KV, which api/generate.mjs trusts. This is the
// paid/unpaid attribution point — entitlement lives server-side, never in the
// extension.
//
// Env: STRIPE_WEBHOOK_SECRET (whsec_...), plus the same KV vars as generate.
// Stripe setup (when payments go live): a Payment Link or Checkout Session
// with client_reference_id={installToken}; webhook subscribed to
// checkout.session.completed, checkout.session.async_payment_succeeded,
// checkout.session.async_payment_failed, customer.subscription.updated,
// customer.subscription.deleted.

import { createHmac, timingSafeEqual } from "node:crypto";

export const config = { api: { bodyParser: false } };

const TOKEN_RE = /^[a-f0-9-]{36}$/;
const PAID_OK = new Set(["paid", "no_payment_required"]);
const SUB_OK = new Set(["active", "trialing"]);

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

// Stripe may send several v1 signatures during secret rotation — accept if ANY
// matches; keeping only the last (Object.fromEntries) drops valid events.
function verifySignature(rawBody, header, secret) {
  let timestamp = null;
  const candidates = [];
  for (const pair of header.split(",")) {
    const [key, value] = pair.split("=");
    if (key === "t") timestamp = value;
    if (key === "v1" && value) candidates.push(value);
  }
  if (!timestamp || !candidates.length) return false;
  if (Math.abs(Date.now() / 1000 - Number(timestamp)) > 300) return false; // replay guard
  const expected = createHmac("sha256", secret).update(`${timestamp}.${rawBody}`).digest("hex");
  return candidates.some((candidate) => {
    try {
      return timingSafeEqual(Buffer.from(expected), Buffer.from(candidate));
    } catch {
      return false;
    }
  });
}

async function readRawBody(req) {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks).toString("utf8");
}

async function grant(creds, token, customer) {
  if (!TOKEN_RE.test(token || "")) return;
  await kv(creds, "set", `paid:${token}`, "active");
  // Map the Stripe customer back to the token so lifecycle events can revoke.
  if (customer) await kv(creds, "set", `cust:${customer}`, token);
}

async function revokeByCustomer(creds, customer) {
  if (!customer) return;
  const token = await kv(creds, "get", `cust:${customer}`);
  if (token) await kv(creds, "del", `paid:${token}`);
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
  const object = event.data?.object || {};

  switch (event.type) {
    case "checkout.session.completed":
      // Delayed payment methods complete the session before money moves —
      // grant only when Stripe says the payment is settled.
      if (object.client_reference_id && object.customer) {
        await kv(creds, "set", `cust:${object.customer}`, object.client_reference_id);
      }
      if (PAID_OK.has(object.payment_status)) {
        await grant(creds, object.client_reference_id, object.customer);
      }
      break;
    case "checkout.session.async_payment_succeeded":
      await grant(creds, object.client_reference_id, object.customer);
      break;
    case "checkout.session.async_payment_failed":
      await revokeByCustomer(creds, object.customer);
      break;
    case "customer.subscription.updated":
      // past_due/unpaid subscriptions emit updates, not deletions — revoke on
      // any non-active status, restore if Stripe recovers the payment.
      if (SUB_OK.has(object.status)) {
        const token = await kv(creds, "get", `cust:${object.customer}`);
        if (token) await kv(creds, "set", `paid:${token}`, "active");
      } else {
        await revokeByCustomer(creds, object.customer);
      }
      break;
    case "customer.subscription.deleted":
      await revokeByCustomer(creds, object.customer);
      break;
  }

  return res.status(200).json({ received: true });
}
