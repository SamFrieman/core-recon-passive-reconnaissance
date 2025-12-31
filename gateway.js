const express = require('express');
const { createProxyMiddleware } = require('http-proxy-middleware');

const app = express();
const PORT = process.env.PORT || 3000;

// Define service ports here if you want defaults. The services started by start-all.js
// will each receive their PORT env var and should listen on it.
const SERVICE_MAPPINGS = [
  // Example mapping:
  // { prefix: '/frontend', port: process.env.FRONTEND_PORT || 3001 },
  // { prefix: '/api', port: process.env.API_PORT || 3002 }
];

// Add proxies based on SERVICE_MAPPINGS
for (const m of SERVICE_MAPPINGS) {
  app.use(m.prefix, createProxyMiddleware({
    target: `http://localhost:${m.port}`,
    changeOrigin: true,
    pathRewrite: { [`^${m.prefix}`]: '' },
    ws: true
  }));
}

app.get('/', (req, res) => {
  res.send('Gateway running. Configure SERVICE_MAPPINGS in gateway.js for your services.');
});

app.listen(PORT, () => console.log(`Gateway listening on ${PORT}`));