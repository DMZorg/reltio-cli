# Output And Automation Contract

## Streams

- stdout contains successful data only.
- stderr contains errors, warnings, and diagnostics only.
- JSON is the finite-command default regardless of TTY state.
- Scans default to JSONL and never mix a final JSON document into the event stream.
- `--output raw` is accepted only for `api request`, typed entity get/by-crosswalk/search/history/matches, and explicitly acknowledged token disclosure. It emits the upstream body or token material after active credentials, bounded common encodings of active credentials, and credential-shaped JSON response fields are redacted. For `auth token --show`, only the selected access token's exact bytes are exempted; cumulative guards for distinct refresh tokens, client secrets, environment values, and prior cache generations remain active for the disclosed bytes and generated errors. Upstream bytes remain byte-identical when no redaction is needed; structured redaction may reserialize JSON. Raw upstream response bodies must be redirected and are refused on terminal stdout. Dry-run plans are structured data and reject raw output.
- `--output yaml` uses JSON-compatible YAML 1.2 flow syntax. This keeps arbitrary-precision JSON number tokens intact instead of exposing serializer-private tags or silently narrowing them.

`--fields` is implemented by `entity get`, `entity search`, and `entity scan`; every other command fails with `fields_unsupported` rather than silently returning an unnarrowed payload. `--max-response-bytes` must be greater than zero, and dry runs validate and report the same limit that a live request would use. `--quiet` suppresses non-error stderr narration but never removes security information from structured `meta.warnings`.

Finite commands apply `--timeout` as one absolute wall-clock budget across target resolution, authentication, bounded local request-body input, local locks and commits, final token-cache guard acquisition, request retries, response-body reads, and output. No error-rendering path starts a fresh post-deadline budget. Every stdout/stderr record is prepared before a final exclusive token-cache snapshot lease is acquired, revalidated against that lease, and emitted by a bounded-chunk writer that retains the lease through the last flush attempt. A concurrent writer therefore cannot install credential material between final validation and physical emission. SIGINT is armed before argument-error or help output and publishes its source and timestamp in the same sticky cancellation event; the fixed deadline and first published cancellation determine control precedence, so a later SIGINT cannot rewrite an earlier timeout. The output thread publishes a completion stamp immediately after its final flush attempt; a successful stamp before both deadline and cancellation is authoritative regardless of later scheduler polling, while earlier control cannot become success. A blocked inherited sink that crosses the deadline or SIGINT makes the process exit nonzero or `130` and releases its lease on process termination. An indivisible operating-system write can leave a prefix that is unterminated or complete-looking after control has fired, so structured consumers must require both a complete newline-terminated record and zero exit status. Raw consumers must always use the exit status because raw bytes intentionally have no framing terminator. Once deadline or cancellation has ended the budget, stderr is intentionally omitted unless an authoritative diagnostic can finish within the original budget.

## Success Envelope

```json
{
  "schema_version": 1,
  "ok": true,
  "data": {},
  "meta": {
    "command": "entity.get",
    "cli_version": "0.1.0-alpha.1",
    "profile": "dev",
    "environment": "dev",
    "tenant": "ExampleTenant",
    "service": "data",
    "request_id": null,
    "elapsed_ms": 12,
    "pagination": null,
    "warnings": [],
    "practice_coverage": "reviewed",
    "practice_ids": [],
    "consistency": "consistent",
    "http_status": 200,
    "attempts": 1,
    "auth_source": "environment"
  }
}
```

Typed upstream entity data remains lossless under `data`; arbitrary-precision JSON numbers are preserved and active credentials are replaced if a server echoes their literal bytes or a bounded percent-, form-, or JSON-encoded representation. Byte-oriented replacement uses `[REDACTED]` only when that marker neither contains an active credential nor exceeds any active credential's byte length; otherwise it uses an empty string, so replacing repeated short credentials cannot amplify the response. Values that remain decodable after two successive JSON-escape, percent, or form operations are redacted conservatively even when no active credential has yet appeared. An encoded value larger than 1 MiB is redacted without allocating full-size canonical variants.

Compact and pretty JSON spellings are checked after semantic redaction so escaping cannot recreate a credential; affected fragments are redacted, and an irreducible whole-document match is replaced with a safe scalar or refused. Generated key/header suffixes are re-sanitized and collision exhaustion is refused rather than overwriting unrelated data. The exact final JSON, JSONL, YAML, table, and guarded raw bytes are checked again after combining data with generated envelope, header, and metadata fields. Every physical output path, including help, parse errors, warnings, finite results, scan batches, summaries, and diagnostics, acquires or reuses an exclusive final lease that includes final, displaced, malformed, temporary, and recognized orphaned local token-cache images. Cache enumeration completes before selected-cache decoding; an incomplete enumeration installs a deny-all guard. Successful provider parsing retains every bounded response string as protected material for the originating command, including extension and credential-process metadata values. Inspection includes renderer-synthesized trailing newlines and canonical encodings that begin in the rendered bytes and complete across that newline boundary. All stderr records in one invocation share a bounded tail, so separately safe warning and final-error records cannot synthesize a credential across their physical boundary. Streaming scan stdout is likewise guarded as one logical byte sequence: every physically accepted byte advances a bounded tail large enough for the maximum supported credential and two canonicalization layers, and the next batch is validated against that tail and the final cache-lease guard. Refusal before a physical write does not advance the tail; any partial-write or flush failure poisons the context so later output is suppressed. If generated output would reproduce protected material, stdout is omitted with `credential_output_refused`; stderr uses the positional emergency document below to retain every context field that can be represented safely, with a context-checked safe scalar as the last resort.

State-changing login guard-checks its exact success bytes, including warning metadata, before changing cache or profile state. It rejects candidates inside the local expiry-skew window, stages each imported bearer under a fresh immutable generation key while retaining every pre-commit generation, then compare-and-swaps the profile pointer; a pre-commit profile failure removes the unreferenced candidate under the same exclusive lock. A committed transition away from an imported bearer persists its exact key as non-secret cleanup intent, removes it under exclusive cache maintenance, and clears that intent. Profile removal uses the same set-valued `pending_imported_bearer_cleanups` transaction. A crash therefore leaves either the original profile pointing to its usable bearer, an unused staged candidate, or a committed profile state with durable forward-cleanup intent. The next invocation completes pending cleanup, reports `imported_bearer_cleanup_recovered`, and requires the requested command to be replayed. Ordinary profile-removal cache failure restores the removed profile when every bearer preimage was verified intact. Physical sink failures, including broken pipes, are never reported as success. When one occurs after login or profile-removal commit, the error reports `local_state_committed: true` and `safe_to_replay: false`. JSON, JSONL, and YAML API warnings appear only in success metadata, never as preceding prose; raw/table warning narration is guard-checked. Response-dependent search-boundary warnings are written before raw/table success output. Raw mutation dry runs remain available, but sending is refused before authentication or network I/O until `mutation_audit_v1` can represent every required result field. Login does not write separate pre-success warning prose before stdout, so a later stdout failure still leaves stderr as one structured error document when the original budget and a safe final diagnostic lease remain available.

Broad diagnostic heuristics are never applied to successful entity values or non-JSON text. An explicit non-JSON content type is honored even when text begins with `{` or `[`. Raw structured responses additionally redact credential-shaped response fields such as `access_token` and `refresh_token`; if safe JSON reserialization would exceed the original body or still match an active credential, raw output emits an empty body.

JSON responses with duplicate object keys, more than 64 nested arrays/objects, or more than 100,000 structural complexity units are refused rather than emitted through an ambiguous or excessively large in-memory representation. Consumers must ignore unknown metadata fields and unknown upstream payload fields.

Final encoded matching is fixed-memory relative to response size. It scans merged windows around encoding metacharacters, padded by the maximum two-layer source expansion for the longest active credential; a maximum-size credential conservatively expands the window to the whole response. This preserves cross-field detection without repeatedly decoding an otherwise ordinary maximum-size document.

Table output refuses response shapes with more than 256 distinct columns or more than 100,000 row-column cells. The renderer discovers bounded columns and widths in one pass and writes rows in a second pass; it does not allocate a dense cell matrix. Use JSON, JSONL, or YAML when a sparse or wide upstream shape exceeds those human-output limits.

## Scan Events

```json
{"schema_version":1,"type":"item","data":{},"meta":{"sequence":1,"cursor":null,"consistency":"eventual"}}
{"schema_version":1,"type":"checkpoint","data":null,"meta":{"sequence":100,"cursor":"cursor-value","returned":100,"pages":1,"expires_at":"2026-08-10T13:00:00Z","resume_file":"organizations.resume.json","resume":{"schema_version":2,"endpoint_id":"entity.scan","profile":"dev","environment":"dev","tenant":"ExampleTenant","filter_hash":"filter-sha256","query_hash":"query-sha256","page_size":100,"data_service_url":"https://dev.reltio.com/reltio/api/ExampleTenant/","cursor":"cursor-value","sequence":100,"acquired_at":"2026-08-10T12:00:00Z","last_read_at":"2026-08-10T12:00:00Z","expires_at":"2026-08-10T13:00:00Z","exhausted":false,"cli_version":"0.1.0-alpha.1"}}}
{"schema_version":1,"type":"summary","data":null,"meta":{"returned":100,"pages":2,"exhausted":true}}
```

A stream is complete only when a newline-terminated `summary` event is observed and the process exits zero. Each bounded response page is serialized into one JSONL batch, revalidated under a short exclusive final cache lease, physically flushed, and only then allowed to advance its resume file. That lease is released before the next continuation can authenticate or refresh a token. If an HTTP, parsing, output, timeout, or signal failure occurs, no false summary is emitted. Cancellation is checked before every page, page batch, checkpoint batch, and summary. Direct and buffered sink failures both use `output_write_failed`; returned counters and resume state do not advance until the page flush succeeds. `--max-pages` and `--max-items` bound work in the current invocation, not the cumulative sequence loaded from a resume file. Resume lock/read/write operations run on bounded named threads with the same chronological control arbitration; a checkpoint write that started but did not finish before control reports unknown commit state and unsafe replay. A durability error after rename preserves `local_state_committed: true`. The checkpoint's `meta.resume` object contains the complete target, route, query, and exact CLI-version identity required to resume safely; any mismatch fails with `resume_context_mismatch` before network I/O. Persisted progress requires a cursor, an incrementable sequence, coherent timestamps, and an expiry equal to the conservative request-start timestamp in `last_read_at` plus the registry TTL. A response that would consume the reserved maximum sequence is rejected before item output or checkpoint advancement. Resume paths must be valid UTF-8 and are rejected before authentication or network I/O otherwise. Every continuation's authentication, send, body read, and retry chain is bounded by the earlier of the overall scan deadline and cursor expiry, so no retry begins after the cursor lifetime. `data` remains `null` so event payload semantics stay stable.

Cursor-bearing continuations are state-advancing and never enter automatic transport or 401 replay paths; their registry replay classification is resolved from `conditional` to `unsafe` before dispatch.

Scan stdout is not transactionally bound to the resume file. `safe_to_replay` is true only when a fresh scan is still at sequence zero and the CLI proves no bytes were emitted; a first-batch credential refusal with `output_omitted: true` satisfies that condition, but a resumed scan does not. Every other scan failure includes `artifact_reconciliation`: compare complete JSONL `meta.sequence` values with the last known checkpoint, inspect unknown checkpoint commits, and truncate or de-duplicate before continuing. Resume into a new output part. Reusing shell `>` truncates an earlier artifact before the CLI can inspect it, while blind `>>` can duplicate a page when output flushed before checkpoint commit.

## Doctor Results

`doctor` emits a success envelope only when every check has status `pass`. Any `warn` or `fail` status emits no stdout, returns `doctor_unhealthy` on stderr with the report under `error.details` in its ordinary structured form, and exits nonzero. Config loading, permission inspection, target resolution, auth setup, practice loading, client construction, and online failures are captured as checks rather than escaping the diagnostic contract; checks that depend on an unavailable prerequisite are not fabricated. Online failures preserve their HTTP status and request ID. Credential collisions still use the guarded fallback rules below. The command schema reports dynamic consistency because offline diagnostics make no indexed request while `doctor --online` performs an eventually consistent reviewed search.

## Error Envelope

The final error is one compact JSON document on stderr for structured output modes. Guarded warning or progress records may precede it on separate lines. See [Errors](errors.md). If every supported diagnostic representation plus its required line terminator would reproduce a protected credential, the final record is intentionally omitted rather than leaking the credential.

If an active credential conflicts with a normal error-envelope label, value, or boolean, the CLI uses this positional emergency document rather than changing field names or JSON types:

```json
["reltio_guarded_failure","credential_output_refused","safety",0,200,"request-id",1,0,1,-1,"success_response_received_completion_unknown",-1]
```

The fields are marker, error code, category, retryable, HTTP status, request ID, remote response received, replay safe, remote request completed, remote operation completed, remote operation state, and local state committed. Boolean state uses `1` for yes, `0` for no, and `-1` for unknown. A code, category, status, request ID, or state that itself reproduces a credential is `null`. `local state committed` is field index `11`; it reports whether the local commit point was crossed, not whether post-commit directory durability was confirmed. This emergency shape is used when the ordinary structured error is unsafe by itself or in combination with prior stderr records, including for local errors; a scalar is the last resort when no context-bearing representation is safe. Every physically accepted stderr byte updates the shared guard context immediately. A partial write or failed flush makes that context uncertain and suppresses later records rather than risking a cross-record credential.

## Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Complete success |
| `1` | Runtime, network, or API failure |
| `2` | Invalid usage, input, or local validation |
| `3` | Profile, target, credential, or authentication failure |
| `4` | Resource not found |
| `5` | Conflict or refused safety policy |
| `6` | Partial batch failure (reserved) |
| `7` | Timeout; remote outcome may require verification |
| `8` | Local or remote cancellation |
| `130` | SIGINT observed; cancellation details are emitted when they can be represented safely |
