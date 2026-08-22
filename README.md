# DLP Protector Client

A web application (Node.js + Express, frontend with no build step) for checking files against
Forcepoint DLP Protector via the Inspection REST API (v4.0). The frontend uploads a file to the
backend, and only the backend talks to the Protector — the browser is never exposed to the
Protector's address, port, or token.

> For developers: [DEVELOPER.md](DEVELOPER.md) has a detailed technical guide — both this app's
> own Web API and the exact request format sent to the Protector itself (including a few
> undocumented gotchas discovered during the integration).

## Installation

```bash
npm install
```

## Connection setup (.env)

Edit `.env` and fill in the details:

```bash
cp .env.example .env
```

| Variable | Description |
|---|---|
| `PROTECTOR_HOST` | Hostname/IP of the Protector |
| `PROTECTOR_PROTOCOL` | `http` or `https` |
| `PROTECTOR_PORT` | Port (default: 8080 for http, 8443 for https) |
| `PROTECTOR_TOKEN` | Optional Bearer token — if empty, the header is omitted entirely |
| `PROTECTOR_CA_CERT_PATH` | Path to a CA certificate file (PEM), for HTTPS with a self-signed cert |
| `PROTECTOR_TLS_REJECT_UNAUTHORIZED` | `true`/`false` — whether to validate the Protector's TLS cert (false = equivalent to `curl -k`) |
| `MAX_FILE_SIZE_MB` | Maximum file size (default: 30) |
| `REQUEST_TIMEOUT_MS` | Timeout for the request to the Protector (default: 30000) |
| `DESTINATION_HTTP_URL` | Sent as `destinations[0].http_request_url` — required by some Protector deployments for policy/URL-category resolution |
| `DESTINATION_HTTP_HOSTNAME` | Sent as `destinations[0].http_request_url_hostname` (the hostname portion of the URL above) |
| `PORT` | The port this local server listens on |
| `LOG_FILE_PATH` | Path to the request log file (JSON lines) |

### Sending to more than one Protector

If you have multiple Forcepoint Protector appliances (e.g. production + staging, or one per
customer environment), replace the plain `PROTECTOR_*` vars above with numbered ones —
`PROTECTOR_1_HOST`, `PROTECTOR_1_PORT`, `PROTECTOR_1_PROTOCOL`, etc. (same field names, just
prefixed with a number), repeated for `PROTECTOR_2_*`, `PROTECTOR_3_*`, and so on. Add
`PROTECTOR_1_NAME=Production` (etc.) to give each one a friendly label, and set
`PROTECTOR_DEFAULT=1` to say which one is used when a scan doesn't specify one.

```bash
PROTECTOR_1_NAME=Production
PROTECTOR_1_HOST=10.20.4.10
PROTECTOR_1_PORT=8080
PROTECTOR_1_PROTOCOL=http

PROTECTOR_2_NAME=Staging
PROTECTOR_2_HOST=10.20.5.10
PROTECTOR_2_PORT=8080
PROTECTOR_2_PROTOCOL=http

PROTECTOR_DEFAULT=1
```

Once configured, a "Send to Protector" picker appears on the Scan screen (with a live
reachable/unreachable indicator per Protector), and every past scan in History/Verdict Detail
shows which one it went to. As always, the browser only ever sees each Protector's id and the
name you gave it here — never its host, port, or token.

If only the plain `PROTECTOR_HOST` (no number) is set, that's still supported unchanged as a
single Protector — you don't need to migrate an existing `.env` to start using this app.

## Settings screen

Clicking the ⚙️ button in the top-right of the UI opens a Settings screen where you can change,
at runtime (no server restart needed), only the following parameters — ones that can't break the
connection to the Protector:

- `MAX_FILE_SIZE_MB`, `REQUEST_TIMEOUT_MS`
- **Source** (sent as the `source` object in the Inspection Request, used by the Protector to
  match a policy's Source condition — by network/IP or computer name):
  `source.host_ips` (empty = auto-detect from the request's IP),
  `source.host_name` (empty = auto-detect from the machine running the app)
- **Destination**: `destinations[0].http_request_url`, `destinations[0].http_request_url_hostname`

Values are saved to `data/settings.json` (created automatically, not in git) and override the
`.env` defaults until changed again. The Protector's own connection details
(`PROTECTOR_HOST/PORT/PROTOCOL/TOKEN`, etc.) **cannot** be changed from this screen and stay in
`.env` only, so a typo there can't take the service down.

### Note on HTTPS with a self-signed certificate

There are two ways to support a self-signed certificate against the Protector:

1. **Recommended** — set `PROTECTOR_CA_CERT_PATH` to the CA file's path (PEM). The certificate
   will be validated against it.
2. **Less recommended (equivalent to `curl -k`)** — set
   `PROTECTOR_TLS_REJECT_UNAUTHORIZED=false` to skip certificate validation entirely. Use this
   only in test environments.

## Running

```bash
npm start
```

The server listens on `http://localhost:3000` (or whatever port `PORT` is set to). Open that
address in a browser, drag a file (or click to choose one), and click "Send for Scanning".

`GET /api/health` reports whether the server is up and whether the Protector is currently
reachable — useful for monitoring or for the Windows Service setup below.

## Serving the app over HTTPS

By default the app serves plain HTTP. To serve the UI and API over TLS instead — using a
certificate signed by your own internal root CA — put the PEM certificate and private key
somewhere the service account can read (`certs/` is gitignored for this purpose) and set:

```bash
SERVER_HTTPS_ENABLED=true
SERVER_TLS_CERT_PATH=./certs/server.crt
SERVER_TLS_KEY_PATH=./certs/server.key
```

The app then listens **with TLS on `PORT`** and opens no plaintext port at all. Restart the
app (or the Windows Service) after changing these. On startup it logs `https://…` rather than
`http://…`, which is the quickest way to confirm TLS is actually active.

**The certificate must carry a Subject Alternative Name for every hostname or IP people
actually type.** Modern browsers ignore the Common Name completely — a cert issued only as
`CN=dlp-client` will still throw a name-mismatch warning. Include each name you use, e.g.
`DNS:dlp-client.local` plus `IP:10.0.0.10` if the app is also reached by address.

Requesting a cert from your CA with the right SAN — generate a key and CSR, then hand the CSR
to your CA:

```bash
openssl req -newkey rsa:2048 -nodes -keyout certs/server.key -out certs/server.csr -subj "/CN=dlp-client.local" -addext "subjectAltName=DNS:dlp-client.local,IP:10.0.0.10"
```

Other options:

| Variable | Purpose |
| --- | --- |
| `SERVER_TLS_CA_PATH` | Intermediate/chain bundle to present alongside the certificate. Only needed if your CA issues via intermediates and you haven't appended them to the cert file (leaf first, then intermediates). |
| `SERVER_TLS_PASSPHRASE` | Only if the private key file is encrypted. |
| `HTTP_REDIRECT_PORT` | Runs a tiny plaintext listener on this port that does nothing but `301` to the `https://` URL, so old `http://` bookmarks still work. Leave empty for HTTPS only. |

Any of these paths being wrong stops the app at startup with an explicit message, rather than
letting it boot and then fail every connection.

Two things to check on the host once HTTPS is on: the firewall must allow the port, and every
client machine must trust your root CA (usually already true via domain policy — otherwise the
browser shows an untrusted-issuer warning even though the certificate itself is valid).

## Installing as a Windows Service (services.msc)

run it as a Windows Service (shows up in `services.msc`,
starts automatically with the machine, and restarts itself if it crashes) — the project ships
with built-in support via the [`node-windows`](https://www.npmjs.com/package/node-windows)
package.

### Steps on the target machine

1. **Copy the whole project folder** to the target machine (including `package.json`,
   `server.js`, `src/`, `public/`, `scripts/`). You do **not** need to copy `node_modules/`,
   `.env`, `logs/`, `data/`, or `daemon/` — these are regenerated on each machine.
2. Make sure [Node.js](https://nodejs.org/) is installed on the target machine.
3. Install dependencies:
   ```bash
   npm install
   ```
4. Set up `.env` (see "Connection setup" above) with that environment's Protector details.
5. **Open a command prompt as Administrator** ("Run as administrator") — registering a Windows
   service requires elevated permissions — and from the project folder, run:
   ```bash
   npm run service:install
   ```
   The service ("DLP Protector Client") will be created and started automatically. You can
   confirm it in `services.msc` or with:
   ```powershell
   Get-Service -Name "DLP Protector Client"
   ```
6. The service is configured for automatic startup with the machine and will restart itself up
   to 3 times if it crashes.

### Removing the service

Also requires an elevated (Administrator) command prompt:

```bash
npm run service:uninstall
```

### Troubleshooting

Installing the service creates a `daemon/` folder (not in git) with a wrapper executable and log
files (`*.out.log`, `*.err.log`, `*.wrapper.log`) — useful if the service doesn't come up as
expected. The app's own runtime logs (scans, resolution, response times) continue to be written
as usual to `logs/requests.log.jsonl` per `LOG_FILE_PATH`.

## Project structure

```
server.js                # Express app + endpoints GET /api/health, GET /api/protectors, POST /api/scan, GET /api/history[/:id], GET/POST /api/settings
src/config.js            # Loads configuration from .env (Protector connection)
src/settingsStore.js     # Safe runtime settings editable via the UI, saved in data/settings.json
src/protectorClient.js   # Builds and sends the Inspection API request to the Protector
src/logger.js            # JSON-lines log for every request
src/historyStore.js      # Reads requests.log.jsonl back for the History/Verdict Detail screens
public/index.html        # UI - Scan / History / Verdict Detail / Settings screens, no build step
public/docs.html          # Internal API docs (all endpoints, with interactive "Try it out" panels)
scripts/install-service.js    # Registers as a Windows Service (services.msc) - requires Administrator
scripts/uninstall-service.js  # Removes the Windows Service
postman/                 # Postman collection + testing instructions (both against the app and directly against the Protector)
logs/requests.log.jsonl  # Created automatically - runtime log (timestamp, filename, size, resolution, elapsedMs)
data/settings.json       # Created automatically - settings saved via the Settings screen
daemon/                  # Created automatically by node-windows when the service is installed - not in git
```

## Testing with Postman

See [`postman/README.md`](postman/README.md) — includes a ready-made Postman collection for
testing the app's own API, plus instructions and example files for testing the Protector
**directly** (bypassing the app), including the special file-part "wrapping" discovered during
the integration.

For a quicker option with no Postman setup at all, the in-app docs at `/docs` (the
"Documentation" button in the UI) include an interactive "Try it out" panel under **Direct to
Protector** — write your own raw metadata JSON, pick a file, and send it straight to the
Protector from the browser (still routed through this app's backend, so the Protector's
host/port/token stay hidden).

## Security

- All actual communication with the Protector (address, port, token) happens exclusively from
  the backend via `.env` — never exposed to the frontend/browser.
- The uploaded file is processed entirely in memory (Multer memory storage) and is never written
  to disk at any point.
- There's validation on the maximum file size (`MAX_FILE_SIZE_MB`) before actually sending it to
  the Protector.
