// Daily usage report, mailed to the owner. Triggered by Vercel Cron (see
// vercel.json); Vercel authenticates cron invocations with
// `Authorization: Bearer ${CRON_SECRET}`. ADMIN_SECRET is also accepted so the
// report can be triggered manually (curl or the admin page).
//
// Reads the same aggregate KV keys generate.mjs writes — nothing per-user.
//
// Env: CRON_SECRET and/or ADMIN_SECRET, RESEND_API_KEY, REPORT_EMAIL,
//      REPORT_FROM (optional, default onboarding@resend.dev), plus the KV and
//      quota/spend vars documented in generate.mjs.

import { timingSafeEqual } from "node:crypto";

const PRICES = {
  "gemini-3.8-flash": [0.75, 3.75],
  "gemini-3.1-flash-lite": [0.25, 1.5],
  "gemini-2.5-flash-lite": [0.1, 0.4],
  "gemini-2.5-flash": [0.3, 2.5],
  "gemini-3.5-flash": [1.5, 9],
};

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

function secretMatches(presented, secret) {
  if (!secret) return false;
  const a = Buffer.from(presented);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

function authorized(req) {
  const presented = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
  return secretMatches(presented, process.env.CRON_SECRET) || secretMatches(presented, process.env.ADMIN_SECRET);
}

function dayString(offset) {
  return new Date(Date.now() - offset * 86_400_000).toISOString().slice(0, 10);
}

function costUsd(input, output, model) {
  const price = PRICES[model] || PRICES["gemini-3.1-flash-lite"];
  return (input / 1e6) * price[0] + (output / 1e6) * price[1];
}

const usd = (n) => `$${n.toFixed(n < 1 ? 4 : 2)}`;

export default async function handler(req, res) {
  if (req.method !== "GET") return res.status(404).json({ error: "Not found." });
  if (!authorized(req)) return res.status(401).json({ error: "unauthorized" });

  const creds = kvCreds();
  if (!creds) return res.status(503).json({ error: "kv_unavailable" });
  if (!process.env.RESEND_API_KEY || !process.env.REPORT_EMAIL) {
    return res.status(503).json({ error: "email_not_configured" });
  }

  const yday = dayString(1);
  const today = dayString(0);
  const monthKey = today.slice(0, 7);
  let results;
  try {
    results = await kvPipeline(creds, [
      ["mget", `s:a:${yday}`, `s:i:${yday}`, `s:o:${yday}`, `s:mdl:${yday}`],
      ["scard", `s:u:${yday}`],
      ["sunion", ...Array.from({ length: 7 }, (_, i) => `s:u:${dayString(i + 1)}`)],
      ["mget", `s:spend:${monthKey}`, "s:spend:total", `g:${today}`],
    ]);
  } catch {
    return res.status(502).json({ error: "kv_error" });
  }

  const [dayRes, uniqRes, weekRes, spendRes] = results.map((r) => r?.result);
  const actions = Number(dayRes?.[0]) || 0;
  const inputTokens = Number(dayRes?.[1]) || 0;
  const outputTokens = Number(dayRes?.[2]) || 0;
  const model = dayRes?.[3] || process.env.MODEL || "gemini-3.1-flash-lite";
  const uniques = Number(uniqRes) || 0;
  const uniques7d = Array.isArray(weekRes) ? weekRes.length : 0;
  const monthSpendUsd = (Number(spendRes?.[0]) || 0) / 1e6;
  const totalSpendUsd = (Number(spendRes?.[1]) || 0) / 1e6;

  const globalDaily = Number(process.env.GLOBAL_DAILY || "3000");
  const monthCap = Number(process.env.SPEND_MONTHLY_USD || "10");
  const totalCap = Number(process.env.SPEND_TOTAL_USD || "100");

  const alerts = [];
  if (actions >= globalDaily * 0.8) alerts.push(`Actions yesterday hit ${actions}/${globalDaily} of the global daily cap.`);
  if (monthSpendUsd >= monthCap * 0.8) alerts.push(`Month spend ${usd(monthSpendUsd)} is past 80% of the ${usd(monthCap)} monthly cap.`);
  if (totalSpendUsd >= totalCap * 0.8) alerts.push(`Lifetime spend ${usd(totalSpendUsd)} is past 80% of the ${usd(totalCap)} budget.`);

  const subject = `Shelve daily — ${actions} actions, ${uniques} installs, ${usd(costUsd(inputTokens, outputTokens, model))}${alerts.length ? " ⚠️" : ""}`;
  const text = [
    `Shelve usage for ${yday}`,
    ``,
    `Actions: ${actions} (global cap ${globalDaily}/day)`,
    `Active installs: ${uniques} yesterday · ${uniques7d} last 7 days`,
    `Tokens: ${inputTokens.toLocaleString()} in / ${outputTokens.toLocaleString()} out (${model})`,
    `Estimated cost: ${usd(costUsd(inputTokens, outputTokens, model))}`,
    ``,
    `Budget: ${usd(monthSpendUsd)} of ${usd(monthCap)} this month · ${usd(totalSpendUsd)} of ${usd(totalCap)} lifetime`,
    ...(alerts.length ? [``, `ALERTS:`, ...alerts.map((a) => `- ${a}`)] : []),
    ``,
    `Dashboard: https://tryshelve.com/admin`,
  ].join("\n");

  const mail = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}`, "content-type": "application/json" },
    body: JSON.stringify({
      from: process.env.REPORT_FROM || "Shelve <onboarding@resend.dev>",
      to: [process.env.REPORT_EMAIL],
      subject,
      text,
    }),
  });
  if (!mail.ok) {
    const detail = await mail.text().catch(() => "");
    return res.status(502).json({ error: "email_failed", status: mail.status, detail: detail.slice(0, 300) });
  }
  return res.status(200).json({ sent: true, day: yday, actions, alerts: alerts.length });
}
