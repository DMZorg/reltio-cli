# Reltio CLI Operations

## Raw Requests

```bash
reltio --profile dev api request GET /entities/00009qz --service data
```

The command resolves paths under a named service and selected tenant, injects bearer auth, rejects protected headers and URL credentials, and never follows redirects with authorization. Put query parameters in repeated `--query key=value` arguments; request paths and absolute request URLs reject embedded queries and fragments so endpoint preflights cannot be bypassed. Reviewed endpoints inherit registered limits and retry behavior. Partially reviewed paths enforce matched catalog guards but retain conservative retry behavior. Reads with no endpoint-specific match proceed with an unknown-coverage warning and no automatic retries.

Data, tasks, and physical-configuration defaults are tenant-scoped. Jobs requests require the selected tenant as the first relative path segment. MCP tool calls require the exact selected tenant at `params.arguments.tenant_id`. Workflow, RDM, and DTSS raw requests require an explicit service URL template ending in `/{tenant}`; the CLI fails rather than guessing a tenant position. Raw auth requests are disabled in favor of typed auth providers.

An unreviewed mutation dry run requires `--allow-unreviewed-endpoint --yes`; production, overridden, and profile-less targets also require `--confirm-tenant <exact-id>`. The plan exposes the sanitized URL, body hash, safety tier, and replay policy without sending a request. This alpha refuses every actual raw mutation with `mutation_audit_unavailable` until `mutation_audit_v1` has result-generation tests; confirmation flags never bypass that gate.

## Practices And Diagnostics

```bash
reltio api practices check --strict
reltio api practices check --release-ready
reltio api practices show HTTP-RETRY-001
reltio api practices show AUTH-TOKEN-REISSUE-001
reltio --profile prod doctor
reltio --profile prod doctor --online
```

The strict practice check verifies the upstream review lock, emits endpoint-level practice/test coverage and release blockers, and enforces the 14-day release-review freshness rule. `--release-ready` also fails on any missing PRD command, operation-specific implementation evidence, approved endpoint binding, capability evidence, MVP acceptance scenario, or per-field/per-result audit contract; failure is expected in this incomplete alpha. Stable release automation accepts only an exact stable tag and passes `--expected-release <MAJOR.MINOR.PATCH>`, which must match the tag, manifest, and default-feature built package after all attributed tests execute and their Cargo harnesses prove discoverability. This product-MVP check does not replace platform, packaging, signing, provenance, or pilot gates. Documentation drift never changes runtime behavior automatically; endpoint metadata, practice dispositions, implementation, and tests must change together. Without Multi Token Support, agents must not assume that explicit login extends a repeated client-credentials token: the CLI preserves the original acquisition time and expiry when token bytes are unchanged. `doctor` exits `0` only when every check passes; warning and failure reports use guarded `doctor_unhealthy` diagnostics with every safely representable completed check under `error.details`.
