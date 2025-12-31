const axios = require('axios');

module.exports = async function handler(req, res) {
  const domain = req.query.domain || (req.url && req.url.split('/').pop());
  if (!domain) return res.status(400).json({ error: 'domain required' });

  try {
    const base = process.env.VITE_API_URL || '/api';
    const url = `${base}/v1/recon?domain=${encodeURIComponent(domain)}`;
    const resp = await axios.get(url, { timeout: 15000 });
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(200).json({ report: resp.data });
  } catch (e) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(500).json({ error: 'report_failed', detail: String(e) });
  }
}
