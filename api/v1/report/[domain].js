import axios from 'axios';

export default async function handler(req, res) {
  const domain = req.query.domain || (req.url && req.url.split('/').pop());
  if (!domain) return res.status(400).json({ error: 'domain required' });

  const API_BASE = process.env.VERCEL ? `https://${process.env.VERCEL_URL}` : '';
  // Call our recon function internally
  try {
    const base = process.env.VITE_API_URL || '/api';
    // If running on Vercel, call internal function by path
    const url = `${base}/v1/recon/${encodeURIComponent(domain)}`;
    const resp = await axios.get(url, { timeout: 15000 });
    res.setHeader('Access-Control-Allow-Origin', '*');
    // For simplicity return the JSON as 'report'
    return res.status(200).json({ report: resp.data });
  } catch (e) {
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(500).json({ error: 'report_failed', detail: String(e) });
  }
}
