// Anonymous uninstall-survey counter. Stores ONLY aggregate counts per fixed
// reason key in KV (feedback:<reason>) — no free text, no IPs, no identifiers.

const REASONS = new Set(["api_key", "bad_groups", "chrome_native", "broke", "cleanup", "curious"]);

function kvCreds() {
  const url = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
  return url && token ? { url, token } : null;
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(404).end();
  const reason = req.body?.reason;
  if (!REASONS.has(reason)) return res.status(204).end();
  const creds = kvCreds();
  if (creds) {
    await Promise.all(
      [`feedback:${reason}`, "feedback:total"].map((key) =>
        fetch(`${creds.url}/incr/${key}`, { headers: { Authorization: `Bearer ${creds.token}` } }).catch(() => undefined)
      )
    );
  }
  return res.status(204).end();
}
