# shelve-site

Landing page, privacy policy, and the serverless relay for [Shelve](https://github.com/prithvi-bharadwaj/shelve), deployed to [tryshelve.com](https://tryshelve.com) on Vercel.

## What's here

- `index.html`, `privacy.html`, `bye.html` — static pages. The privacy page is a public contract: the relay never stores URLs, titles, IPs, or request content, only anonymous per-token counters, entitlement flags, and aggregate daily totals. Any server change must keep it true.
- `api/generate.mjs` — the Shelve Free proxy: per-install anonymous tokens, 30 free actions/day metered in Upstash KV, strict request whitelist, fail-closed metering. Also records aggregate daily action/token tallies for cost visibility.
- `api/admin-stats.mjs` + `admin.html` — owner-only usage/cost dashboard, protected by `ADMIN_SECRET`.
- `api/stripe-webhook.mjs` — paid entitlements (`paid:<token>` in KV). **Stripe is not live yet**; nothing payment-facing is enabled.
- `api/feedback.mjs` — anonymous uninstall survey counts.

## Environment variables (Vercel)

| Var | Purpose |
| --- | --- |
| `GEMINI_API_KEY` | Budget-capped key the proxy calls Gemini with (required) |
| `KV_REST_API_URL` / `KV_REST_API_TOKEN` | Upstash KV (metering + aggregate stats); missing KV fails closed |
| `ADMIN_SECRET` | Bearer secret for `/api/admin-stats` and `admin.html` |
| `ALLOW_TOKENS` | Comma-separated install tokens with unlimited actions (owner + friends) |
| `FREE_DAILY` / `GLOBAL_DAILY` / `PAID_MONTHLY` | Quota knobs (defaults 30 / 3000 / 1500) |
| `MODEL` | Pinned Gemini model (default `gemini-3.1-flash-lite`) |
| `STRIPE_WEBHOOK_SECRET` | Webhook signature secret — unused until Stripe goes live |

## Giving a friend unlimited actions

Each Shelve install has an anonymous install code (a random UUID — it identifies nothing but the install):

1. Your friend opens Shelve **Settings → Provider** (with Shelve Free selected) and clicks **Copy my install code**.
2. They send you that code.
3. In Vercel → Project → Settings → Environment Variables, append it to `ALLOW_TOKENS` (comma-separated) and redeploy.
4. Their extension now shows "unlimited" and is never metered.

## Owner dashboard

Open [tryshelve.com/admin](https://tryshelve.com/admin), paste `ADMIN_SECRET`. Shows total/per-day actions for the last 30 days, unique installs, aggregate input/output tokens, and estimated Gemini cost. All numbers are aggregates — there is nothing per-user to see.

## Tests

```
node --test tests/*.test.mjs
```
