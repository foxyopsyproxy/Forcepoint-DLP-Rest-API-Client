# Testing with Postman

There are two different things you might want to test, and they use different requests:

1. **This app's own API** (`POST /api/scan`, `GET/POST /api/settings`) — the easy, normal way to
   test the app end-to-end.
2. **The Forcepoint Protector's Inspection API directly** — bypasses this app entirely, useful for
   debugging the Protector/policy side in isolation.

## 1. Testing this app's API

Import [`DLP-Client.postman_collection.json`](DLP-Client.postman_collection.json) into Postman
(Import → File). It has 3 requests, using a `baseUrl` collection variable (defaults to
`http://localhost:3000`):

- **Scan file** — `POST /api/scan`. Open the `file` form-data field and pick a local file, then Send.
- **Get settings** — `GET /api/settings`.
- **Update settings** — `POST /api/settings` with an example JSON body (edit as needed — see
  the field list in the main [README](../README.md#מסך-הגדרות-settings)).

This is the same request the app's own frontend sends — nothing special to configure.

## 2. Testing the Protector directly

This is **not** a simple JSON request — see [`src/protectorClient.js`](../src/protectorClient.js)
for the exact logic this app uses. In short, a POST to
`http://<PROTECTOR_HOST>:<PROTECTOR_PORT>/inspection/v4.0` needs **two** `multipart/form-data`
parts:

- `metadata` — a JSON document (`context`, `contentDescriptors`, `source`, `destinations`)
- `0` — the file part, **but its `Content-Type` must be `application/http`, and its actual bytes
  must be a synthetic captured-HTTP-transaction** (an HTTP header block followed by a nested
  `multipart/form-data` body containing the real file) — not the raw file bytes. This was the
  hard-won discovery from getting the real integration working; sending plain file bytes here
  silently produces zero matches no matter what the content is.

To make this easy to reproduce in Postman without hand-building that envelope, this folder
includes ready-made, verified-working example files in
[`direct-to-protector-examples/`](direct-to-protector-examples/):

| File | What it is |
|---|---|
| `sample-file.txt` | The "real" file content being tested |
| `wrapped-content.http` | `sample-file.txt` already wrapped in the required HTTP envelope |
| `metadata-example.json` | The matching metadata JSON (size_bytes already matches `wrapped-content.http`) |

### Postman setup

1. New request, `POST` to `http://<PROTECTOR_HOST>:<PROTECTOR_PORT>/inspection/v4.0`
   (e.g. `http://<PROTECTOR_HOST>:8080/inspection/v4.0`).
2. Body → `form-data`:
   - Key `metadata`, type **File**, select `metadata-example.json`. Click the key's "..." menu
     (or the Content-Type column, depending on your Postman version) and set Content-Type to
     `application/json`.
   - Key `0`, type **File**, select `wrapped-content.http`. Set its Content-Type to
     `application/http`.
3. Send. A working response looks like:
   ```json
   {
     "global_message_id": "11111111-1111-1111-1111-111111111111",
     "resolution": "MATCHED",
     "cpe_transaction_info": { "id": "..." },
     "violations": [null],
     "actions": [{ "action_type": "Permit" }],
     "max_number_of_matches": 0
   }
   ```
   (`0` matches here because the sample content is generic — swap in your own policy's trigger
   keyword to test a real match.)

### Testing your own file/keyword instead

Swap in your own content and regenerate the wrapped envelope — the wrapping can't be typed by
hand in Postman since it needs exact `\r\n` line endings and a random boundary string. From the
project root, with Node installed:

```bash
node -e "
const fs = require('fs');
const crypto = require('crypto');
const fileBuffer = fs.readFileSync('YOUR_FILE_HERE');
const boundary = '----WebKitFormBoundary' + crypto.randomBytes(16).toString('hex');
const body = Buffer.concat([
  Buffer.from('--' + boundary + '\r\nContent-Disposition: form-data; name=\"file\"; filename=\"YOUR_FILE_HERE\"\r\nContent-Type: application/octet-stream\r\n\r\n'),
  fileBuffer,
  Buffer.from('\r\n--' + boundary + '--\r\n'),
]);
const wrapped = Buffer.concat([Buffer.from('Accept: application/json\r\nContent-Type: multipart/form-data; boundary=' + boundary + '\r\n\r\n'), body]);
fs.writeFileSync('wrapped-content.http', wrapped);
console.log('size_bytes:', wrapped.length);
"
```

Update `size_bytes` in `metadata-example.json` to match the printed value, and `global_message_id`
to a fresh UUID (not required to be unique for testing, but keeps request IDs distinguishable in
the Protector's Traffic Log).
