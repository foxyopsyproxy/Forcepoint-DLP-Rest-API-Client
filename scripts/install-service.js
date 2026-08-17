const path = require('path');
const { Service } = require('node-windows');

const svc = new Service({
  name: 'DLP Protector Client',
  description:
    'Web client for scanning files against Forcepoint DLP Protector via the Inspection REST API.',
  script: path.join(__dirname, '..', 'server.js'),
  workingDirectory: path.join(__dirname, '..'),
});

svc.on('install', () => {
  console.log('Service installed. Starting it now...');
  svc.start();
});

svc.on('start', () => {
  console.log('Service started. Check services.msc for "DLP Protector Client".');
});

svc.on('alreadyinstalled', () => {
  console.log('Service is already installed. Use "npm run service:uninstall" first to reinstall.');
});

svc.on('error', (err) => {
  console.error('Service install error:', err);
});

console.log('Installing Windows service "DLP Protector Client" (requires an elevated/Administrator prompt)...');
svc.install();
