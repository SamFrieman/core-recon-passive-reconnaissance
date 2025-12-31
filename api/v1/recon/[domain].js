import dns from 'dns/promises';
import axios from 'axios';
import whois from 'whois-json';

export default async function handler(req, res) {
  try {
    const domain = req.query.domain || (req.url && req.url.split('/').pop());
    if (!domain) return res.status(400).json({ error: 'domain required' });

    // basic sanitization
    const sanitized = String(domain).replace(/[^a-zA-Z0-9.\-]/g, '').toLowerCase();

    const result = { target: sanitized };

    // DNS resolution
    try {
      const lookup = await dns.lookup(sanitized);
      result.ip = lookup.address;
    } catch (e) {
      result.ip = 'resolution_failed';
    }

    // Fetch headers
    try {
      const resp = await axios.get(`https://${sanitized}`, { timeout: 5000 });
      result.headers = resp.headers;
      result.status_code = resp.status;
    } catch (e) {
      try {
        const resp2 = await axios.get(`http://${sanitized}`, { timeout: 5000 });
        result.headers = resp2.headers;
        result.status_code = resp2.status;
      } catch (e2) {
        result.headers = {};
        result.status_code = 'unreachable';
      }
    }

    // WHOIS (best-effort)
    try {
      const w = await whois(sanitized, { follow: 3 });
      result.whois = w;
    } catch (e) {
      result.whois = { error: 'whois failed' };
    }

    // Minimal risk score heuristic
    let score = 0;
    const headers = result.headers || {};
    if (!headers['strict-transport-security']) score += 20;
    if (!headers['content-security-policy']) score += 15;
    if (!headers['x-frame-options']) score += 10;
    if (!headers['x-content-type-options']) score += 5;
    if ((result.status_code === 'unreachable') || result.ip === 'resolution_failed') score += 30;

    const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score > 0 ? 'LOW' : 'MINIMAL';

    result.risk = { score: Math.min(score, 100), level };

    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(200).json(result);
  } catch (err) {
    console.error(err);
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(500).json({ error: 'internal_error', detail: String(err) });
  }
}
