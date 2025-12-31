export default function handler(req, res) {
  // Serverless functions are stateless; return empty history placeholder
  res.setHeader('Access-Control-Allow-Origin', '*');
  return res.status(200).json({ scans: [] });
}
