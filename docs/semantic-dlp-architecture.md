# Semantic AI DLP — Architecture (Milestone 1: Shadow Mode)

## 1. Current scan architecture (as of this milestone)

Backend: Node/Express (`server.js`), no framework beyond `express`+`multer`. Frontend:
single-file vanilla HTML/JS (`public/index.html`), no build step, no framework.
History/analytics are backed by SQLite via `node:sqlite` (`src/db.js`, `src/historyStore.js`).

There are three routes that talk to Forcepoint:

- `POST /api/scan` — the primary path. `multer.memoryStorage()` puts the uploaded
  file's raw bytes in `req.file.buffer` (never written to disk). `server.js` generates
  a `requestId` (`crypto.randomUUID()`) *before* contacting Forcepoint, then calls
  `scanOrchestrator.startScan({...})` (`src/scanOrchestrator.js`), which starts both
  `forcepointScanner.scan(...)` (`src/forcepointScanner.js`, a thin pass-through to
  `inspectFileWithFailover` in `src/protectorClient.js`) and the Semantic AI analysis
  together under that one `requestId`, sent to Forcepoint as `global_message_id`. The
  Forcepoint response (policy/rule names, severity, match counts, resolution) is
  reshaped into a JSON response, recorded via `historyStore.recordScanEvent()`,
  published over SSE (`src/eventBus.js`), and optionally triggers a webhook
  (`src/webhookNotifier.js`) on BLOCK.
- `POST /api/sanitize` — the Key Phrase Redaction workflow (`src/sanitizationService.js`):
  inspect → if MATCHED, locally redact configured phrases → re-inspect → only ever
  return content Forcepoint has verified clean. Takes `content` as a JSON **string**
  (the frontend already reads the file client-side via `File.text()` before sending).
- `POST /api/protector/raw` — a raw dev passthrough used only by `docs.html`'s "Try it
  out" panel. Bypasses this app's own metadata construction entirely.

`src/config.js` centralizes all `.env` parsing (`parseBool`/`parseIntEnv` helpers,
one config object). `src/settingsStore.js` holds runtime-editable settings
(`data/settings.json`), separate from `.env`-only connection details.

## 2. Where the original content is available

For `/api/scan`, the **raw, unmodified upload bytes** are in `req.file.buffer` at the
top of the route handler — before `inspectFileWithFailover` is ever called, and
regardless of whether Forcepoint later matches anything. This is exactly the
"Original Input" the mission requires: Semantic AI must not depend on Forcepoint
detecting something first, and here it doesn't need to — the bytes are already in
hand.

For `/api/sanitize`, the original text is already a plain JS string (`content` in the
request body) before Forcepoint is ever called.

## 3. Integration point selected — and why

**Milestone 1 wires Semantic AI into `POST /api/scan` only.**

Reasons:
- It is the primary, general-purpose scan path (the one the Scan Home page uses for
  every file, of every type, redact-mode or not) — the natural place for a
  general-purpose semantic classifier.
- `req.file.buffer` is already available at the very top of the handler, so Forcepoint
  and Semantic AI can be started **in parallel** (`Promise.allSettled`-style; see §5)
  with no restructuring of the existing Forcepoint call.
- `/api/sanitize` is a narrower, already-complex workflow (two sequential Forcepoint
  calls plus local redaction) whose content is always plain text by construction;
  adding a second independent analysis path there is a reasonable *future* extension,
  not required for Milestone 1's shadow-mode goal, and folding it in now would mean
  touching more of a working file than necessary.
- `/api/protector/raw` is an intentionally raw, bypass-everything dev tool. Wiring
  anything else into it would work against its actual purpose.

This is documented explicitly as a **scope decision**, not an oversight — see §8.

## 4. Existing components reused as-is (no modification)

- `src/protectorClient.js` — untouched. Forcepoint's call path is unaffected.
- `src/historyStore.js` / `src/db.js` — untouched (see §8: AI results are not
  persisted to History in this milestone).
- `src/eventBus.js` / SSE — untouched.
- `src/webhookNotifier.js` — untouched (shadow mode never triggers enforcement, so
  there is nothing new to alert on).
- `src/config.js`'s `parseBool`/`parseIntEnv` helpers — reused for the new env vars.
- The `requestId` / Forcepoint `global_message_id` already generated in `/api/scan` —
  reused directly as the Semantic AI correlation id (`scan_id`). No second UUID scheme.
- The existing factory-function + injectable-dependencies pattern used throughout
  `src/*.js` (`createSanitizationService({...})`, `createKeyPhraseStore({...})`) —
  followed by every new module below, for the same testability reasons.
- The existing "never log content, only safe metadata" pattern already implemented
  and tested in `sanitizationService.js`'s `emitLog()` — followed exactly.

## 5. New components

| File | Purpose |
|---|---|
| `src/contentExtractor.js` | Bytes → normalized UTF-8 text, or `EXTRACTION_FAILED`. Milestone 1 supports plain text / CSV / JSON (anything that decodes as clean UTF-8); PDF/DOCX/XLSX/PPTX are explicitly deferred (see §8) since this app has no existing binary-document parser to reuse and none is added here. |
| `src/ollamaProvider.js` | Thin HTTP client for a local Ollama server (`/api/generate`, structured JSON output via Ollama's `format` schema param, `think:false`). Uses Node's built-in `fetch` — no new npm dependency (this machine's corporate proxy blocks `npm install`; already established in this project's `server.js` gzip comment). Model/base URL/timeout are all config-driven, never hardcoded. |
| `src/semanticPolicyStore.js` | Loads `config/semantic-dlp-policy.yaml` once at boot. Ships a small hand-rolled parser for this file's one fixed shape (flat map of `CATEGORY: {description: >-block-scalar}`) rather than adding a `js-yaml` dependency — same "no npm install available" constraint as above. |
| `src/semanticScanner.js` | The orchestrator: `createSemanticScanner({provider, policy, config}).scan(text, context) -> SemanticResult`. Owns chunking, prompt assembly, calling the provider, schema validation, evidence validation, aggregation, and **all failure isolation** — this function is designed to never throw. |
| `config/semantic-dlp-policy.yaml` | The semantic policy: sensitivity levels + categories, each with a natural-language definition. Not a keyword list. |
| `prompts/semantic-dlp-v1.txt` | Versioned prompt template, with explicit prompt-injection-resistance instructions (the analyzed content is untrusted data, never instructions). |
| `src/forcepointScanner.js` | Pure pass-through wrapper around `protectorClient.inspectFileWithFailover`, named so Forcepoint can be referred to as a `Scanner` sibling to `SemanticScanner`. Forwards arguments and resolve/reject behavior unchanged — zero behavior risk to the one code path that has stayed stable through every change so far. |
| `src/scanOrchestrator.js` | `startScan({...})` starts `forcepointScanner.scan(...)` and the Semantic AI analysis together under one `scan_id`, returning both promises without awaiting or catching either — `server.js`'s existing `try`/`catch`/`httpStatus` branching around the Forcepoint call needed zero changes to work with this in place. |
| `src/decisionEngine.js` | Shadow-mode-only: `decide({aiClassification, transactionContext})` returns what a theoretical enforcement decision *would* be, keeping content sensitivity separate from transmission risk. Never applied to an actual scan's outcome — only logged (see §9). |
| `src/aiMetrics.js` | In-process observability counters (`ai_requests_total`, per-classification counts, `forcepoint_ai_agreement_total`/`disagreement_total`, latency/input-size averages). Resets on restart by design — a shadow-mode visibility aid, not a durable metrics system. Exposed read-only at `GET /api/ai-metrics`. |

## 6. Existing components modified

- `src/config.js` — additive `config.semanticAi = {...}` block (new env vars only;
  nothing existing changed).
- `server.js` — in `POST /api/scan`: build `AI_DLP_ENABLED`-gated call to
  `semanticScanner.scan(...)` that starts **alongside** `inspectFileWithFailover(...)`
  (not after it, and not gated on its result), attaches `aiAnalysis` to whichever
  response path is taken (success / Forcepoint HTTP error / catch-block error) as an
  **additive field**. No existing field is renamed, removed, or reshaped.
- `public/index.html` — `renderDetail()` grows one new, clearly-labeled "Semantic AI
  Analysis (Shadow Mode)" section, rendered only when `entry.aiAnalysis` is present.
  Nothing else in the page changes.
- `.env.example` — new documented section for the `AI_*`/`OLLAMA_*` variables.

## 7. Semantic AI flow (Milestone 1)

```
req.file.buffer (already in hand for Forcepoint)
        |
        v
contentExtractor.extractText(buffer, fileName)
   -> { status: 'OK', text }  or  { status: 'EXTRACTION_FAILED' }
        |
        v
semanticScanner.scan(text, { scanId: requestId, fileName })
   1. AI_DLP_ENABLED=false -> status DISABLED, return immediately
   2. extraction failed -> status EXTRACTION_FAILED, return immediately
   3. content longer than AI_MAX_CONTENT_SIZE -> truncated, noted in result
   4. split into chunks (paragraph-boundary-aware, AI_CHUNK_SIZE/AI_CHUNK_OVERLAP)
   5. classify each chunk SEQUENTIALLY (concurrency = 1) via ollamaProvider
        - each call wrapped: Ollama unreachable -> MODEL_UNAVAILABLE
                              timeout            -> TIMEOUT
                              bad/non-schema JSON -> INVALID_RESPONSE
        - a single chunk failure does not necessarily fail the whole scan; see
          semanticScanner.js for exactly how per-chunk failures fold into aggregation
   6. validate each chunk's evidence[].quote against that chunk's own normalized text;
      discard any quote that doesn't appear verbatim
   7. aggregate chunk classifications: highest severity wins
      (RESTRICTED > CONFIDENTIAL > INTERNAL > PUBLIC); any chunk-level
      failure/uncertainty anywhere -> whole-document UNCERTAIN
   8. status COMPLETED, with classification/categories/confidence/reason/evidence
        |
        v
Attached to the /api/scan response as an additive `aiAnalysis` field
        |
        v
Forcepoint's own result is completely unaffected either way (shadow mode)
```

Forcepoint and Semantic AI are started as two independent operations on the same
input; neither's outcome is required for the other to run or to be reported.

## 8. Backward compatibility & explicit scope decisions

- **Additive only.** `aiAnalysis` is a new, optional field on the existing `/api/scan`
  response. Every existing field keeps its exact name, type, and meaning. A client
  that doesn't know about `aiAnalysis` sees no behavior change.
- **No enforcement.** `AI_DLP_MODE` only supports `shadow` in this milestone (see
  `src/semanticScanner.js`); nothing reads `aiAnalysis.classification` to change a
  scan's resolution, actions, or HTTP status.
- **AI results are not persisted to SQLite history in this milestone.** They are
  returned live in the `/api/scan` response and rendered once in the UI for that
  scan, then gone (not visible again from History/Verdict Detail after a page
  reload). This was a deliberate choice to avoid a database schema migration —
  explicitly called out as "large speculative infrastructure" to avoid — for a
  shadow-mode proof of concept. Persisting AI results (new `ai_analysis` columns /
  table, mirroring `scan_violations`) is natural future work once the classifier's
  output is trusted enough to be worth keeping long-term, and is **not** built here.
- **Document format support is deliberately narrow.** This app has zero existing
  binary-document parsers (`package.json` has no PDF/DOCX/XLSX library, and none is
  added here). Milestone 1's `contentExtractor` handles anything that decodes as
  clean UTF-8 text (plain text, CSV, JSON, and similar). Genuine binary formats
  (PDF/DOCX/XLSX/PPTX) resolve to `EXTRACTION_FAILED` — Forcepoint's own scan of that
  file is completely unaffected.
- **`/api/sanitize` and `/api/protector/raw` are untouched** in this milestone (§3).
- **The AI call is awaited before `/api/scan` responds - synchronously, not via
  `PROCESSING` + a later push.** `AI_STATUS.PROCESSING` exists in the status enum,
  but Milestone 1 never actually returns it: `server.js` starts Forcepoint and
  Semantic AI in parallel, but still waits for both before sending one combined
  response, matching the "Combined Result" shape in the spec literally. A real
  measurement on this project's dev machine (Windows 11, 16GB RAM, 4 vCPU, no GPU,
  qwen3:4b) showed 34s-157s for a single classification call — meaning a scan that
  normally returns in well under a second can take well over a minute once
  `AI_DLP_ENABLED=true`. This only affects scans while the feature is explicitly
  turned on (the default is off, with zero behavior change). Delivering the AI
  result asynchronously - respond immediately with `aiAnalysis.status: 'PROCESSING'`,
  then push the completed result over the existing SSE bus (`src/eventBus.js`) once
  ready - would fix this, but was deliberately left out of Milestone 1 as exactly
  the kind of "build it because it'll be needed eventually" infrastructure the spec
  asks to avoid; it is a natural, well-scoped Milestone 2 candidate.
- **No new npm dependencies.** This machine's corporate proxy blocks `npm install`
  (already a known constraint in this project). Ollama is called via Node's built-in
  `fetch`; the YAML policy file is parsed by a small hand-rolled parser scoped to its
  one fixed shape, not a general YAML parser.

## 9. Decision Engine & Observability (shadow mode only)

Added after Milestone 1's initial rollout, still shadow-only — enforcement stays
disabled everywhere.

- **`src/decisionEngine.js`** keeps *content sensitivity* (the AI's classification)
  separate from *transmission risk* (channel/destination context) as two distinct
  inputs to one small decision table, rather than folding enforcement logic into the
  LLM prompt. `decide({aiClassification, transactionContext})` returns a
  `theoreticalDecision` (`BLOCK`/`ALLOW`/`UNCERTAIN`) and a `reason`. This app does
  not model a real destination/user/device pipeline (it is a scan-a-file tool, not a
  network DLP gateway) — the one real signal passed today is `dataChannel`, already
  sent to Forcepoint. `server.js` computes this after every `/api/scan` response and
  only **logs** it (`console.log`, `theoretical_decision` + reason); nothing reads it
  to change a scan's actual outcome.
- **`src/aiMetrics.js`** is a small in-process counter set (`ai_requests_total`,
  per-classification counts, `forcepoint_ai_agreement_total`/`disagreement_total`,
  average latency/input size), reset on restart — a shadow-mode visibility aid, not a
  durable metrics store (Prometheus/a time-series DB would be exactly the kind of
  infrastructure this feature doesn't need yet). Exposed read-only at
  `GET /api/ai-metrics`; updated from every `/api/scan` response branch (success,
  Forcepoint HTTP error, and the catch-block error path), since the AI classification
  can complete independently of whichever way Forcepoint's own call resolves.
  "Agreement" is a heuristic (Forcepoint matched + AI CONFIDENTIAL/RESTRICTED, or
  Forcepoint clean + AI PUBLIC/INTERNAL); a **disagreement** where Forcepoint found
  nothing but the AI rated the content CONFIDENTIAL/RESTRICTED is exactly the
  "traditional DLP missed this" signal this whole feature exists to surface.
- **`src/scanOrchestrator.js` + `src/forcepointScanner.js`** formalize the
  Forcepoint/Semantic-AI relationship as the `ScanOrchestrator` coordinating two
  `Scanner`-shaped engines, matching the intended architecture, without changing any
  resolve/reject/httpStatus behavior `server.js`'s existing branching depends on —
  see their own header comments for exactly how each preserves that.
- **Deliberately not built**: an async `AiJobQueue` (the AI call is still awaited
  synchronously — see §8) and a formal precision/recall evaluation harness (a small
  labeled dataset and manual comparison script exist — `test/fixtures/semantic-eval-dataset.js`,
  `scripts/run-semantic-eval.js` — but not a `tests/evaluation/` metrics framework).
  Both remain reasonable next steps once the current shadow-mode data is reviewed.
