# Reltio CLI Agent Guide

This guide matches `reltio` version `0.1.0-alpha.1`.

## Contract

- Use a named profile or provide environment and tenant explicitly. Never infer a tenant from a token.
- Finite commands return a versioned JSON envelope by default. Cursor scans emit JSONL item, checkpoint, and summary events.
- Treat stdout as data. Diagnostics, progress, and warnings are written to stderr.
- Inspect failures by `error.code`, `error.retryable`, `error.http_status`, and `error.hint`; do not parse prose alone. If the document is a positional `reltio_guarded_failure` array, follow the output-contract field order instead.
- A scan is successful only if it emits a final `summary` event. Persist checkpoint events or use `--resume-file`.
- Resume files require the exact CLI version, target, route, normalized query, and page size that created them.
- Direct `entity get` and `entity by-crosswalk` are consistent. Entity history and stored potential-match consistency are unknown; indexed `entity search` and `entity scan` are eventually consistent.
- Never put client secrets or bearer tokens in command arguments. Use environment injection, hidden input, stdin flags, an owner-only secret file, or a credential process.
- Do not retry a mutation merely because it failed. The CLI retries only operations registered as replay-safe.

## Bootstrap

```bash
reltio profile add dev --environment dev --tenant ExampleTenant
reltio --profile dev auth login --method client-credentials --client-id example-client
reltio --profile dev auth check
reltio --profile dev entity get entities/00009qz
```

For headless execution, set `RELTIO_CLIENT_SECRET` or `RELTIO_ACCESS_TOKEN`. Environment auth overrides are reported in metadata.

## Discovery

```bash
reltio command schema entity.get
reltio api practices list
reltio api practices show ENTITY-SEARCH-BOUNDARY-001
reltio skills get reltio-data
reltio --profile dev doctor
```

Use `api request` only when a typed command does not exist. Partially reviewed paths enforce every catalog rule matched by method, service, and path while retaining conservative retry behavior. Reads with no endpoint-specific match report unknown practice coverage and receive no automatic retries. Mutation dry runs require all dedicated acknowledgements, but actual raw mutations are disabled until the audit-result contract is implemented; prefer adding a reviewed typed operation.

`doctor` exits `0` only when every check passes. On any warning or failure, read the guarded `doctor_unhealthy` report from `error.details.checks` when safely representable; otherwise follow the general guarded-error fallback contract.

## Recovery

- Exit `2`: fix local arguments or input.
- Exit `3`: inspect `auth status`, `auth check`, profile, environment, and tenant.
- Exit `4`: verify the resource URI and tenant.
- Exit `5`: resolve a safety or concurrency conflict; do not blindly add confirmation flags.
- Exit `7`: the local wait timed out. A remote task or request outcome may still need verification.

For a failed `auth login`, inspect `error.details.local_state_committed` in the ordinary envelope or field index `11` in a positional `reltio_guarded_failure` array. When it is `true`/`1`, the profile and cache crossed their local commit points despite a later failure; run `auth status` and do not replay the login automatically. If stderr is empty because even a newline would reproduce a credential, treat the result as non-replayable and inspect `auth status`.
