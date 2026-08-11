# Structured Errors

```json
{
  "schema_version": 1,
  "ok": false,
  "error": {
    "code": "auth_insufficient_permissions",
    "category": "authentication",
    "message": "The credential cannot access the selected tenant operation",
    "retryable": false,
    "http_status": 403,
    "request_id": "request-id",
    "details": {},
    "hint": "Check tenant roles, scopes, policy, and IP allowlisting.",
    "suggested_commands": [],
    "docs_url": "https://github.com/aiadjacent/reltio-cli/blob/main/docs/errors.md"
  }
}
```

Error codes are stable lowercase identifiers. `retryable` reflects CLI replay policy, not only the HTTP status.

When an active credential equals a normal error field name, value, boolean spelling, or the required trailing newline, the CLI does not rename fields or change JSON types. It instead uses the positional `reltio_guarded_failure` emergency document defined in the [output contract](output-contract.md). Local errors preserve code, category, retryability, and local commit state at index `11`; remote failures additionally preserve HTTP status, request ID, response receipt, replay safety, and mutation completion state whenever each value is safe to emit. Stderr is empty only when no supported newline-terminated representation is safe.

## Common Codes

| Code | Meaning | Recovery |
| --- | --- | --- |
| `profile_not_found` | Selected profile is absent | `reltio profile list` |
| `environment_unresolved` | No environment could be resolved | Set `--environment`, `RELTIO_ENVIRONMENT`, or profile value |
| `tenant_unresolved` | No tenant could be resolved | Set `--tenant`, `RELTIO_TENANT`, or profile value |
| `auth_unconfigured` | No provider or supplied token exists | Run `auth login` or inject a token |
| `client_secret_missing` | A client token must be acquired but no secret source exists | Inject or securely configure the secret |
| `invalid_refresh_token` | A provider returned an empty or line-broken refresh token | Repair the provider; the token and local login state were rejected |
| `auth_token_expiry_too_soon` | A provider or imported token is already unusable within the local skew window | Acquire a token with more than five seconds of remaining lifetime; no cache preimage was replaced |
| `token_cache_invalid` | A local cache image is malformed or uses an unknown schema | Run `reltio auth logout`, verify cache permissions, then authenticate again |
| `auth_invalid_token` | Reltio returned `401` after any one-time safe reacquisition | Replace or repair credentials |
| `auth_insufficient_permissions` | Reltio returned `403` | Check roles, scopes, tenant, policy, and IP allowlisting |
| `resource_not_found` | Reltio returned `404` | Verify URI, tenant, and environment |
| `entity_search_boundary_exceeded` | `offset + max` exceeds 10,000 | Use `entity scan` |
| `query_filter_too_long` | Entity filter would be silently truncated by Reltio | Simplify the filter or use another workflow |
| `invalid_query_value` | A reviewed query parameter has an empty, malformed, or undocumented value | Use the exact endpoint parameter contract; for Get Entity, use documented lowercase fields |
| `invalid_entity_option` | An entity option is malformed or unsupported for that operation | Use an option documented for the selected Entity API operation |
| `invalid_resume_file_path` | Resume path cannot be represented safely in checkpoint metadata | Use a valid UTF-8 local path |
| `resume_file_invalid` | Resume progress or timestamps are inconsistent, or sequence capacity is exhausted | Use an unmodified checkpoint from the original scan or start a new file |
| `resume_context_mismatch` | Resume identity differs from current scan | Use the exact CLI version and original arguments, or start a new file |
| `resume_cursor_expired` | Saved cursor is beyond conservative lifetime | Start a new scan |
| `protected_header_refused` | Raw request attempted to override a security-controlled header | Remove the header |
| `dry_run_raw_output_unsupported` | Raw output cannot represent a structured dry-run plan | Use JSON or YAML output |
| `redirect_refused` | Server returned a redirect | Verify the configured service URL; auth was not forwarded |
| `unreviewed_mutation_refused` | Raw mutation lacks reviewed endpoint policy | Add reviewed typed support or use all dedicated acknowledgements after review |
| `api_internal_error` | Reltio returned `500`, which is not retried | Validate the request and contact support if persistent |
| `api_response_redaction_failed` | A response could not be represented without risking credential disclosure or silent field loss | Retain the request ID, narrow the response, and contact support; do not request raw output to bypass the refusal |
| `credential_output_refused` | Final rendered output would reproduce an active credential through generated envelope or formatting bytes | Treat stdout as omitted; inspect the guarded error and never replay a mutation unless it explicitly says replay is safe |
| `auth_login_commit_conflict` | The selected profile changed while login was acquiring credentials | Inspect the winning profile and retry deliberately; this login restored its candidate cache image |
| `auth_login_rollback_failed` | Profile persistence failed and candidate-cache restoration could not be verified | Do not retry; inspect `auth status` and local cache state |
| `profile_remove_cache_prepare_failed` | Imported-bearer cleanup could not be prepared before profile removal | Correct cache permissions and retry; no profile/cache deletion committed |
| `profile_remove_cache_failed` | Imported-bearer deletion failed and its exact preimage remains | Correct cache permissions and retry the profile removal |
| `profile_remove_cache_rollback_failed` | Imported-bearer deletion failed and exact rollback could not be verified | Do not retry; inspect the profile and run `auth logout` after correcting local storage |
| `profile_remove_config_failed` | Configuration removal failed and the bearer preimage was restored | Correct configuration storage and retry |
| `profile_remove_config_commit_uncertain` | Profile/cache deletion committed but configuration durability was not fully confirmed | Inspect `profile list`; do not blindly replay |
| `profile_remove_rollback_failed` | Profile removal did not commit and bearer restoration could not be verified | Do not retry; inspect the profile and run `auth logout` |
| `doctor_unhealthy` | One or more diagnostic checks warned or failed | Inspect `error.details.checks`, correct every non-pass check, and rerun `doctor` |
| `output_write_failed` | A physical output sink failed after rendering | Inspect commit-state details; never replay when `local_state_committed` is true |
| `request_timeout` | Overall local timeout expired | Verify the remote outcome before repeating an ambiguous operation |

`doctor_unhealthy` preserves the category, HTTP status, request ID, and retryability of the first concrete failed check. A warning-only report uses category `internal` and exit `1`. Its ordinary structured form carries the bounded diagnostic report, including every check completed before an unrecoverable prerequisite failure, under `error.details`; irreducible credential collisions use the guarded fallback contract. Unhealthy diagnostics never use a success envelope or exit `0`.

Reltio response bodies are bounded and redacted before inclusion in error details. HTML and unambiguously non-JSON responses are represented as bounded text rather than parser errors. A body identified as JSON but too deep, duplicate-keyed, structurally excessive, malformed, or impossible to serialize without recreating a credential is omitted from diagnostics because safe representation cannot be proven; only body-free metadata is emitted. An API error body over 64 KiB is likewise omitted with `response_body_truncated: true`; its HTTP status, request ID, retry ceiling, and status-specific error code remain authoritative. An oversized OAuth error body uses the same marker, retains the token endpoint's status-specific policy, and denies output for the originating command because the uninspected bytes may contain provider secrets.
