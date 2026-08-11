# Reltio CLI Operations

## Raw Requests

```bash
reltio --profile dev api request GET /entities/00009qz --service data
```

The command resolves paths under a named service and selected tenant, injects bearer auth, rejects protected headers and URL credentials, and never follows redirects with authorization. Reviewed endpoints inherit registered limits and retry behavior. Partially reviewed paths enforce matched catalog guards but retain conservative retry behavior. Reads with no endpoint-specific match proceed with an unknown-coverage warning and no automatic retries.

Data, tasks, and physical-configuration defaults are tenant-scoped. Jobs requests require the selected tenant as the first relative path segment. MCP tool calls require the exact selected tenant at `params.arguments.tenant_id`. Workflow, RDM, and DTSS raw requests require an explicit service URL template ending in `/{tenant}`; the CLI fails rather than guessing a tenant position. Raw auth requests are disabled in favor of typed auth providers.

An unreviewed mutation requires `--allow-unreviewed-endpoint --yes`; production, overridden, and profile-less targets also require `--confirm-tenant <exact-id>`. Run with `--dry-run` first to inspect the sanitized URL, body hash, safety tier, and replay policy. Structured-mode warnings appear only in success metadata. Raw/table warning narration is completed before the network request, so a warning-sink failure sends nothing. A stdout failure or broken pipe after a successful mutation response returns `output_write_failed` with response, request-ID, completion-uncertainty, and `safe_to_replay: false` context.

## Practices And Diagnostics

```bash
reltio api practices check --strict
reltio api practices show HTTP-RETRY-001
reltio api practices show AUTH-TOKEN-REISSUE-001
reltio --profile prod doctor
reltio --profile prod doctor --online
```

The strict practice check verifies the upstream review lock, emits endpoint-level practice/test coverage, and enforces the 14-day release-review freshness rule. Documentation drift never changes runtime behavior automatically; endpoint metadata, practice dispositions, implementation, and tests must change together. Without Multi Token Support, agents must not assume that explicit login extends a repeated client-credentials token: the CLI preserves the original acquisition time and expiry when token bytes are unchanged. `doctor` exits `0` only when every check passes; warning and failure reports use guarded `doctor_unhealthy` diagnostics with every safely representable completed check under `error.details`.
