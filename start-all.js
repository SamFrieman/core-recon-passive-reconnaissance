#!/usr/bin/env node
/**
 * Cross-platform launcher to start multiple services and a gateway.
 *
 * Edit the `services` array to match your repo (set cwd and cmd for each service).
 * The launcher sets PORT in each service's environment to the configured port.
 *
 * Usage: node start-all.js
 */

const { spawn } = require('child_process');
const path = require('path');

const services = [
  // Example entries — edit these to match your repo's services.
  // {
  //   name: 'frontend',
  //   cwd: path.join(__dirname, 'services', 'frontend'),
  //   port: 3001,
  //   // cmd is any shell command that starts the service and respects PORT env var.
  //   // e.g. 'npm run start' or 'python -m uvicorn app:app --host 0.0.0.0 --port $PORT'
  //   cmd: 'npm run start'
  // },
  // {
  //   name: 'api',
  //   cwd: path.join(__dirname, 'services', 'api'),
  //   port: 3002,
  //   cmd: 'python -m uvicorn app:app --host 0.0.0.0 --port $PORT'
  // }
];

// If you prefer autodiscovery, set services here programmatically or fill in above.

if (services.length === 0) {
  console.error('No services configured in start-all.js. Edit the services array to add your services.');
  process.exit(1);
}

const children = [];

function spawnService(svc) {
  console.log(`Starting ${svc.name} in ${svc.cwd} on port ${svc.port}`);
  // Use shell so compound commands and typical npm/python command strings work cross-platform.
  const env = Object.assign({}, process.env, { PORT: String(svc.port) });

  const child = spawn(svc.cmd, {
    shell: true,
    cwd: svc.cwd,
    env,
    stdio: ['ignore', 'pipe', 'pipe']
  });

  child.stdout.on('data', (d) => {
    process.stdout.write(`[${svc.name}] ${d}`);
  });
  child.stderr.on('data', (d) => {
    process.stderr.write(`[${svc.name}] ${d}`);
  });
  child.on('exit', (code, sig) => {
    console.log(`${svc.name} exited with code ${code} signal ${sig}`);
  });

  children.push(child);
  return child;
}

function killChildren() {
  console.log('Shutting down child services...');
  for (const c of children) {
    try {
      c.kill('SIGTERM');
    } catch (e) { /* ignore */ }
  }
}

process.on('SIGINT', () => {
  killChildren();
  process.exit();
});
process.on('SIGTERM', () => {
  killChildren();
  process.exit();
});

// Start all services
for (const svc of services) {
  spawnService(svc);
}

// Start gateway in foreground (so this node process remains alive).
// Gateway should bind to process.env.PORT (provided by host).
const gatewayCmd = 'node gateway.js';
console.log('Starting gateway with:', gatewayCmd);
const gateway = spawn(gatewayCmd, { shell: true, stdio: 'inherit', env: process.env });

// When gateway exits, shut down children and exit with same code.
gateway.on('exit', (code, sig) => {
  console.log(`Gateway exited with code ${code} signal ${sig}`);
  killChildren();
  process.exit(code === null ? 0 : code);
});