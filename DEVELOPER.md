# Developer Guide — DLP Protector Client

This document is for developers working on the code or debugging the integration with
Forcepoint DLP Protector. It covers two separate things:

1. **How to work with this app's own Web API** (our backend) — for integration, testing, or
   extending the UI.
2. **How to work directly with the Protector** (Forcepoint Inspection REST API v4.0) — for
   debugging, building new features, or understanding exactly what our backend sends under the
   hood.

For basic install/run, `.env`, the Settings screen, and deploying as a Windows Service, see
[README.md](README.md). This document focuses on the technical details of the protocols
themselves.

---

## 1. Architecture

```
Browser (public/index.html)
      │  fetch() — JSON / multipart
      ▼
Backend (server.js, Express)
      │  src/protectorClient.js
      ▼
Forcepoint DLP Protector — Inspection REST API v4.0
```

Key principle: **the browser never talks to the Protector directly**. Every request goes through
the backend, so the Protector's address/port/token are never exposed to the frontend.

Key files:

| File | Role |
|---|---|
| `server.js` | Express routes: `POST /api/scan`, `GET/POST /api/settings`, `GET /docs` |
| `src/config.js` | Protector connection config from `.env` (host/port/protocol/token/TLS) |
| `src/settingsStore.js` | Runtime settings editable via the UI (saved in `data/settings.json`) |
| `src/protectorClient.js` | **Builds the actual request to the Protector** and sends it — see section 3 |
| `src/logger.js` | JSON-lines log for every scan |

---

## 2. Working with this app's Web API

This is our backend's own internal API (not the Protector's). Identical interactive
documentation also exists inside the app itself at `/docs` (the "Documentation" button in the
UI).

### `POST /api/scan`

Scans a file against the Protector and returns the result.

**Body**: `multipart/form-data` with a single field `file` (the file to scan).

**Example response (200)**:
```json
{
  "globalMessageId": "bfdfb88a-1d7a-4eba-9f24-7c6beb571d7d",
  "resolution": "MATCHED",
  "violations": [
    {
      "policyId": "29017",
      "policyName": "BulwarxTestKeyWord",
      "rules": [
        { "ruleId": "rule_29017", "ruleName": "BulwarxTestKeyWord", "severity": "MEDIUM", "matches": 1 }
      ]
    }
  ],
  "actions": ["Block"],
  "maxNumberOfMatches": 1,
  "elapsedMs": 80,
  "fileName": "file.txt",
  "fileSizeBytes": 73
}
```

**Error codes**: `400` (no file sent), `413` (exceeds max size), `502` (Protector unavailable/
error), `504` (timeout).

### `GET /api/settings`

Returns the settings state in two shapes:
- `fields` — the raw per-field state: `{ enabled: boolean, value: ... }` (what the UI shows/edits)
- `effective` — the values that will actually be sent on the next request (when `enabled: false`,
  falls back to the `.env` default or auto-detection)

### `POST /api/settings`

Updates one or more fields. Send only the fields you want to change, in `{ enabled, value }`
form:

```json
{ "hostIps": { "enabled": true, "value": "10.20.4.51" } }
```

Available fields: `maxFileSizeMb`, `requestTimeoutMs` (in milliseconds!), `hostIps`, `hostName`,
`destinationHttpUrl`, `destinationHttpHostname`.

---

## 3. Working directly with the Protector (Inspection API v4.0)

This is the part that actually matters for anyone debugging integration issues or building a new
client. The details here are based on what actually works against our environment (not just the
official docs — a few things in the docs turned out to be inaccurate or under-specified in
practice).

### Endpoint

```
POST http://<PROTECTOR_HOST>:<PROTECTOR_PORT>/inspection/v4.0
```

Default HTTP port: 8080. **The official docs state HTTPS is not supported on this REST API** —
HTTP only.

### Headers

```
Content-Type: multipart/form-data; boundary=<...>
Authorization: Bearer <token>   (optional — if present)
```

### Body — 2 parts (multipart/form-data)

**Part 1 — `metadata`** (JSON, `Content-Type: application/json`):

```json
{
  "context": {
    "global_message_id": "<uuid>",
    "client_name": "CUSTOM_APPLICATION",
    "data_channel": "HTTP",
    "activity_type": "UPLOAD",
    "occurred_message_timestamp_utc_ms": 1755374400000
  },
  "contentDescriptors": [
    { "id": "0", "name": "file.txt", "item_type": "FILE", "size_bytes": 436 }
  ],
  "source": {
    "host_ips": ["10.20.4.51"],
    "host_name": "MY-HOST"
  },
  "destinations": [
    {
      "destination_type": "WEB_APPLICATION",
      "http_request_url": "https://dlp-client.local/upload",
      "http_request_url_hostname": "dlp-client.local",
      "http_request_method": "POST"
    }
  ]
}
```

**Part 2 — `"0"`** (the field name = the `id` defined in `contentDescriptors`), with
`Content-Type: application/http`. **This is the least intuitive part — see the explanation
right below.**

### ⚠️ The critical discovery: the file's "HTTP wrap"

The official docs say the file part needs `Content-Type: application/http`, "regardless of the
file's actual type" — but that's **not just the Content-Type label**. The content (bytes) of that
part must be a **synthetic HTTP transaction** — a header block followed by a nested multipart
body containing the actual file — exactly like what a real network proxy would have captured
"on the wire" during a web file upload.

**If you send the file's raw bytes** (the intuitive thing to do), the request is still accepted
(`HTTP 200`, `resolution: MATCHED`), but it will **always report 0 matches**, regardless of
content — the DLP engine simply has nothing to scan, because it tries to parse the bytes as HTTP
headers and silently fails. This is exactly the bug we found after a lot of trial and error in
this session.

Our implementation (`buildHttpWrappedUpload` in `src/protectorClient.js`):

```js
function buildHttpWrappedUpload(fileBuffer, fileName) {
  const nestedBoundary = `----WebKitFormBoundary${crypto.randomBytes(16).toString('hex')}`;
  const mimeType = guessMimeType(fileName); // by file extension

  const nestedBody = Buffer.concat([
    Buffer.from(
      `--${nestedBoundary}\r\n` +
      `Content-Disposition: form-data; name="file"; filename="${fileName}"\r\n` +
      `Content-Type: ${mimeType}\r\n\r\n`
    ),
    fileBuffer,
    Buffer.from(`\r\n--${nestedBoundary}--\r\n`),
  ]);

  const httpHeaders =
    `Accept: application/json\r\n` +
    `Content-Type: multipart/form-data; boundary=${nestedBoundary}\r\n\r\n`;

  return Buffer.concat([Buffer.from(httpHeaders), nestedBody]);
}
```

**Important**: `size_bytes` in `contentDescriptors` must be the length of the buffer **after**
wrapping (not the original file's size).

### Critical `context` fields

| Field | Correct value | Note |
|---|---|---|
| `client_name` | `CUSTOM_APPLICATION` | **Not** `FORCEPOINT_WEB`! Using `FORCEPOINT_WEB` classifies the traffic as "Web Security Cloud Services" in the Traffic Log — a different channel from "Network" — and a policy scoped to the Network channel never evaluates it at all, even though the request "succeeds" technically (200, but 0 matches). This was the reason traffic looked fine but policy never fired. |
| `data_channel` | `HTTP` | For API Protector, `HTTPS` is also valid, but `HTTP` is what actually got classified as "Network" in our environment |
| `activity_type` | `UPLOAD` | The only one supported for HTTP/HTTPS channels |

### `source` — testing a policy's Source condition

A DLP policy can condition on Network/IP or Computer/hostname. In our app, each field is only
sent **if it was actually configured** in Settings — both aren't sent together unless both are
intentionally enabled:

```js
const source = {};
if (settings.hostIps) source.host_ips = settings.hostIps.split(',').map((ip) => ip.trim());
if (settings.hostName) source.host_name = settings.hostName;
if (!source.host_ips && !source.host_name) {
  // Default: auto-detect both
  source.host_ips = [clientIp || '127.0.0.1'];
  source.host_name = os.hostname();
}
```

We tested directly against the Protector: sending a `source` with **only** `host_ips` or
**only** `host_name` (without the other at all) is accepted without error — even though the
official docs list `host_ips` as "required". In practice, this isn't strictly enforced.

### Response

```json
{
  "global_message_id": "...",
  "resolution": "MATCHED" | "UNMATCHED",
  "cpe_transaction_info": { "id": "..." },
  "violations": [{ "policy_id": "...", "policy_name": "...", "violated_rules": [...] }],
  "actions": [{ "action_type": "Permit" | "Block" | "Quarantine" | ... }],
  "max_number_of_matches": 0
}
```

`resolution: "MATCHED"` with `max_number_of_matches: 0` and `violations: [null]` is the default
fallback-rule response when there's no real policy match — not a sign of a problem, unless you
were expecting a real match.

---

## 4. Testing/simulating with Postman or curl

See [`postman/README.md`](postman/README.md) — includes:
- A ready-made Postman collection for testing our own Web API (`postman/DLP-Client.postman_collection.json`)
- **Verified** example files for testing the Protector directly, including the pre-built "wrap"
  (`postman/direct-to-protector-examples/`)

A full working curl example (from the Postman README):

```bash
curl -X POST \
  -F "metadata=@metadata-example.json;type=application/json" \
  -F "0=@wrapped-content.http;type=application/http" \
  http://<PROTECTOR_HOST>:8080/inspection/v4.0
```

---

## 5. Common troubleshooting

| Symptom | Likely cause |
|---|---|
| `ECONNREFUSED` / `ENOTFOUND` | `.env` points to the wrong host/port, or the Protector isn't reachable on the network |
| `400` with `"JSON parse error"` | The `metadata` JSON is syntactically invalid |
| `400` with an empty schema (`global_message_id: null`, etc.) | The Protector received and parsed the request, but the inspection engine itself failed — usually a field that's actually required in practice (even if not marked "required" in the docs) is missing |
| `200`, `MATCHED`, but **always** `max_number_of_matches: 0` regardless of content | The file part was sent as raw bytes instead of "wrapped" in the synthetic HTTP envelope — see section 3 |
| Traffic Log shows the traffic under "Web Security Cloud Services" instead of "Network" | `client_name` was set to `FORCEPOINT_WEB` instead of `CUSTOM_APPLICATION` |
| Source shows both IP and hostname together even though you only wanted one | Both fields are enabled (`enabled: true`) in Settings at the same time — turn off the one you don't want |
