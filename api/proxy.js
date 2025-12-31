export default async function handler(req, res) {
  const target = process.env.BACKEND_URL;
  if (!target) {
    res.status(500).json({ error: 'BACKEND_URL not configured' });
    return;
  }

  const url = new URL(req.url, target);
  // Forward the full incoming path (keep /api prefix) so backend routes like
  // /api/v1/... are preserved. Construct destination using the full pathname.
  const path = url.pathname; // keep leading /api
  const dest = new URL(path + url.search, target);

  const init = {
    method: req.method,
    headers: { ...req.headers },
  };

  // Vercel may set host header; ensure host is target host
  init.headers.host = dest.host;

  try {
    const body = await (async () => {
      if (req.method === 'GET' || req.method === 'HEAD') return undefined;
      const buffers = [];
      for await (const chunk of req) buffers.push(chunk);
      return Buffer.concat(buffers);
    })();

    if (body) init.body = body;

    const response = await fetch(dest.toString(), init);

    // Pass through status and headers
    res.status(response.status);
    response.headers.forEach((value, key) => {
      // Skip hop-by-hop headers
      if (['transfer-encoding', 'connection', 'keep-alive', 'upgrade', 'proxy-authenticate', 'proxy-authorization'].includes(key.toLowerCase())) return;
      res.setHeader(key, value);
    });

    const arrayBuffer = await response.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);
    res.send(buffer);
  } catch (e) {
    console.error('Proxy error', e);
    res.status(502).json({ error: 'Bad gateway', detail: String(e) });
  }
}
