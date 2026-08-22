/**
 * Verifies (and optionally installs) the CA certificate used to authenticate a
 * Protector's Inspection API over HTTPS.
 *
 * Why this exists: the pinned CA in certs/ was originally taken from the appliance's
 * own TLS handshake, which is trust-on-first-use - if that one connection had been
 * intercepted, the wrong CA would have been pinned and every scan afterwards would
 * still look "verified". Comparing it against an authoritative copy of ca.cer from
 * the DLP management server retires that assumption.
 *
 * Handles both PEM (-----BEGIN CERTIFICATE-----) and DER/binary .cer files, so no
 * OpenSSL is needed to inspect or convert what the manager hands you.
 *
 * Usage:
 *   node scripts/verify-protector-ca.js
 *       Show the currently pinned CA (subject, validity, SHA-256) and what the
 *       Protector presents live, and say whether they agree.
 *
 *   node scripts/verify-protector-ca.js <path-to-ca.cer>
 *       Also compare that file against the pinned CA. Exit code 0 = match.
 *
 *   node scripts/verify-protector-ca.js <path-to-ca.cer> --install
 *       On a mismatch, replace the pinned CA with that file (converting DER->PEM
 *       if needed). Requires a service restart afterwards to take effect.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const tls = require('tls');

const PINNED_PATH = path.join(__dirname, '..', 'certs', 'protector-ca.crt');

function fail(msg) {
  console.error('ERROR: ' + msg);
  process.exit(2);
}

// Accepts PEM or raw DER and always returns { pem, der }. A .cer straight out of
// Windows/AD CS is frequently DER, which Node's `ca` option will not parse.
function normalizeCert(buffer) {
  const asText = buffer.toString('latin1');
  if (asText.includes('-----BEGIN CERTIFICATE-----')) {
    const body = asText.split('-----BEGIN CERTIFICATE-----')[1].split('-----END CERTIFICATE-----')[0];
    return { pem: buffer.toString('utf8'), der: Buffer.from(body.replace(/\s+/g, ''), 'base64') };
  }
  const b64 = buffer.toString('base64').match(/.{1,64}/g).join('\n');
  return { pem: `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`, der: buffer };
}

function describe(der, label) {
  const x = new crypto.X509Certificate(der);
  const sha = crypto.createHash('sha256').update(der).digest('hex').match(/../g).join(':').toUpperCase();
  const now = new Date();
  const expires = new Date(x.validTo);
  const daysLeft = Math.round((expires - now) / 86400000);
  console.log(`\n${label}`);
  console.log('  subject   : ' + x.subject.replace(/\n/g, ' '));
  console.log('  issuer    : ' + x.issuer.replace(/\n/g, ' '));
  console.log('  selfSigned: ' + (x.subject === x.issuer));
  console.log('  is CA     : ' + x.ca);
  console.log('  valid     : ' + x.validFrom + '  ->  ' + x.validTo + `  (${daysLeft} days left)`);
  console.log('  SHA-256   : ' + sha);
  if (daysLeft < 0) console.log('  !! EXPIRED - HTTPS scans will fail with CERT_HAS_EXPIRED');
  else if (daysLeft < 90) console.log(`  !! expires in ${daysLeft} days - refresh the pinned copy`);
  return sha;
}

// What the appliance actually presents right now, for comparison. Verification is
// deliberately off here: the point is to observe the chain, not to trust it.
function fetchLiveRootCa(host, port) {
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, rejectUnauthorized: false, timeout: 8000 }, () => {
      let cert = socket.getPeerCertificate(true);
      const seen = new Set();
      while (cert && cert.issuerCertificate && cert.issuerCertificate !== cert && !seen.has(cert.fingerprint256)) {
        seen.add(cert.fingerprint256);
        cert = cert.issuerCertificate;
      }
      socket.destroy();
      resolve(cert && cert.raw ? cert.raw : null);
    });
    socket.on('error', (err) => { console.log(`  (could not reach ${host}:${port} - ${err.code || err.message})`); resolve(null); });
    socket.on('timeout', () => { socket.destroy(); console.log(`  (timed out reaching ${host}:${port})`); resolve(null); });
  });
}

(async () => {
  const args = process.argv.slice(2);
  const install = args.includes('--install');
  const candidatePath = args.find((a) => !a.startsWith('--'));

  if (!fs.existsSync(PINNED_PATH)) fail(`no pinned CA at ${PINNED_PATH}`);
  const pinned = normalizeCert(fs.readFileSync(PINNED_PATH));
  const pinnedSha = describe(pinned.der, `PINNED  (${path.relative(process.cwd(), PINNED_PATH)})`);

  // Compare against the live appliance, using the same Protector this app is configured for.
  let config;
  try { config = require('../src/config'); } catch (err) { /* .env may be absent; skip live check */ }
  if (config) {
    for (const p of config.protectors) {
      const der = await fetchLiveRootCa(p.host, p.httpsPort || 8443);
      if (!der) continue;
      const sha = describe(der, `LIVE    (${p.name} over https)`);
      console.log('  matches pinned: ' + (sha === pinnedSha ? 'YES' : 'NO  <-- this Protector needs a different CA'));
    }
  }

  if (!candidatePath) {
    console.log('\nTo retire the trust-on-first-use assumption, obtain ca.cer from the DLP');
    console.log('management server and compare it:');
    console.log('  node scripts/verify-protector-ca.js <path-to-ca.cer>');
    return;
  }

  if (!fs.existsSync(candidatePath)) fail(`file not found: ${candidatePath}`);
  const candidate = normalizeCert(fs.readFileSync(candidatePath));
  const candidateSha = describe(candidate.der, `CANDIDATE (${candidatePath})`);

  console.log('');
  if (candidateSha === pinnedSha) {
    console.log('RESULT: MATCH - the pinned CA is authentic. Nothing to change.');
    process.exit(0);
  }

  console.log('RESULT: MISMATCH - the pinned CA differs from the authoritative copy.');
  if (!install) {
    console.log('Re-run with --install to replace the pinned copy, then restart the service.');
    process.exit(1);
  }
  fs.copyFileSync(PINNED_PATH, PINNED_PATH + '.bak');
  fs.writeFileSync(PINNED_PATH, candidate.pem);
  console.log(`Installed. Previous copy saved as ${path.basename(PINNED_PATH)}.bak`);
  console.log('Restart the service for it to take effect:  Restart-Service "dlpprotectorclient.exe"');
  process.exit(0);
})();
