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
| `SPEND_MONTHLY_USD` / `SPEND_TOTAL_USD` | Hard stops on *estimated* Gemini spend (defaults 10 / 100). When either is hit the proxy returns the tier-neutral `capacity` error until the month rolls over / the cap is raised. Applies to allowlisted tokens too — it protects the key, not fairness. |
| `CRON_SECRET` | Vercel Cron auth for `/api/daily-report` (Vercel sends it automatically once set) |
| `RESEND_API_KEY` / `REPORT_EMAIL` | Resend key + destination for the daily usage email; `REPORT_FROM` optional |
| `STRIPE_WEBHOOK_SECRET` | Webhook signature secret — unused until Stripe goes live |

## Giving a friend unlimited actions

Each Shelve install has an anonymous install code (a random UUID — it identifies nothing but the install):

1. Your friend opens Shelve **Settings → Provider** (with Shelve Free selected) and clicks **Copy my install code**.
2. They send you that code.
3. In Vercel → Project → Settings → Environment Variables, append it to `ALLOW_TOKENS` (comma-separated) and redeploy.
4. Their extension now shows "unlimited" and is never metered.

## Owner dashboard

Open [tryshelve.com/admin](https://tryshelve.com/admin), paste `ADMIN_SECRET`. Shows total/per-day actions for the last 30 days, unique installs, aggregate input/output tokens, and estimated Gemini cost. All numbers are aggregates — there is nothing per-user to see.

## Daily report + budget guardrails

- `api/generate.mjs` accumulates estimated spend in KV (integer micro-USD: `s:spend:<YYYY-MM>` and `s:spend:total`) and hard-stops at `SPEND_MONTHLY_USD` / `SPEND_TOTAL_USD`. This is the budget cap for keys you can't cap at the console — estimates track Gemini's own token accounting, rounded up.
- `api/daily-report.mjs` runs daily via Vercel Cron (15:00 UTC, see `vercel.json`) and emails yesterday's actions, active installs, tokens, estimated cost, and budget position via Resend. It alerts at 80% of the global daily cap and 80% of either spend cap. Trigger manually with `curl -H "Authorization: Bearer $ADMIN_SECRET" https://tryshelve.com/api/daily-report`.
- Resend setup: create a free account at resend.com, grab an API key, set `RESEND_API_KEY` + `REPORT_EMAIL` (must be your Resend account email until you verify a domain, since the default sender is `onboarding@resend.dev`).

## Tests

```
node --test tests/*.test.mjs
```
