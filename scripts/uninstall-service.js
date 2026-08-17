const path = require('path');
const { Service } = require('node-windows');

const svc = new Service({
  name: 'DLP Protector Client',
  script: path.join(__dirname, '..', 'server.js'),
});

svc.on('uninstall', () => {
  console.log('Service uninstalled.');
});

svc.on('error', (err) => {
  console.error('Service uninstall error:', err);
});

console.log('Uninstalling Windows service "DLP Protector Client" (requires an elevated/Administrator prompt)...');
svc.uninstall();
