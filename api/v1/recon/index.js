const dns = require('dns').promises;
const axios = require('axios');
const whois = require('whois-json');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  try {
    const domain = (req.query && req.query.domain) || null;
    if (!domain) return res.status(400).json({ error: 'domain required' });

    const sanitized = String(domain).replace(/[^a-zA-Z0-9.\-]/g, '').toLowerCase();
    const result = { target: sanitized, checks: {}, now: new Date().toISOString() };

    try {
      const lookup = await dns.lookup(sanitized);
      result.ip = lookup.address;
      result.checks.dns = 'ok';
    } catch (e) {
      console.error('dns.lookup failed', e && e.message);
      result.ip = 'resolution_failed';
      result.checks.dns = 'failed';
    }

    try {
      const resp = await axios.get(`https://${sanitized}`, { timeout: 5000 });
      result.headers = resp.headers;
      result.status_code = resp.status;
      result.checks.http = 'https_ok';
    } catch (e) {
      console.error('https fetch failed', e && e.message);
      try {
        const resp2 = await axios.get(`http://${sanitized}`, { timeout: 5000 });
        result.headers = resp2.headers;
        result.status_code = resp2.status;
        result.checks.http = 'http_ok';
      } catch (e2) {
        console.error('http fetch failed', e2 && e2.message);
        result.headers = {};
        result.status_code = 'unreachable';
        result.checks.http = 'unreachable';
      }
    }

    try {
      result.whois = await whois(sanitized, { follow: 3 });
      result.checks.whois = 'ok';
    } catch (e) {
      console.error('whois failed', e && e.message);
      result.whois = { error: 'whois failed' };
      result.checks.whois = 'failed';
    }

    // simple scoring (diagnostic)
    let score = 0;
    const headers = result.headers || {};
    if (!headers['strict-transport-security']) score += 20;
    if (!headers['content-security-policy']) score += 15;
    if (!headers['x-frame-options']) score += 10;
    if (!headers['x-content-type-options']) score += 5;
    if ((result.status_code === 'unreachable') || result.ip === 'resolution_failed') score += 30;

    const level = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 30 ? 'MEDIUM' : score > 0 ? 'LOW' : 'MINIMAL';
    result.risk = { score: Math.min(score, 100), level };

    return res.status(200).json(result);
  } catch (err) {
    console.error('recon handler error', err && err.stack ? err.stack : err);
    return res.status(500).json({ error: 'internal_error', message: String(err && err.message), hint: 'check function logs for stack trace' });
  }
}
