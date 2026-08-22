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
| `storage_path_conflict` | Config, cache, or state locations overlap after platform-safe normalization and physical alias comparison | Assign separate non-nested local locations; Unix compares no-follow device/inode ancestor chains and missing ASCII suffixes case-insensitively, while Windows resolves fixed-drive handle aliases and rejects `~` storage components |
| `storage_path_comparison_ambiguous` | Distinct non-ASCII missing Unix storage components cannot be proven isolated | Use identical parent spelling and distinct ASCII names for config, cache, and state storage |
| `auth_unconfigured` | No provider or supplied token exists | Run `auth login` or inject a token |
| `client_secret_missing` | A client token must be acquired but no secret source exists | Inject or securely configure the secret |
| `invalid_refresh_token` | A provider returned an empty or line-broken refresh token | Repair the provider; the token and local login state were rejected |
| `auth_token_expiry_too_soon` | A provider or imported token is already unusable within the local skew window | Acquire a token with more than five seconds of remaining lifetime; no cache preimage was replaced |
| `token_cache_invalid` | A local cache image is malformed or uses an unknown schema | Run `reltio auth logout`, verify cache permissions, then authenticate again |
| `bearer_cache_migration_required` | A bearer profile predates exact config-and-route-scoped cache ownership | Run `reltio auth logout`, then authenticate again or remove the now-deconfigured profile |
| `bearer_cache_identity_mismatch` | Stored bearer ownership does not match the selected config and route | Authenticate explicitly for the current target; do not reuse the mismatched generation |
| `auth_login_cache_generation_conflict` | A fresh imported-bearer generation collided with an existing or active exact cache key | Retry deliberately; no candidate cache or profile state was committed |
| `auth_invalid_token` | Reltio returned `401` after any one-time safe reacquisition | Replace or repair credentials |
| `auth_insufficient_permissions` | Reltio returned `403` | Check roles, scopes, tenant, policy, and IP allowlisting |
| `resource_not_found` | Reltio returned `404` | Verify URI, tenant, and environment |
| `entity_search_boundary_exceeded` | `offset + max` exceeds 10,000 | Use `entity scan` |
| `query_filter_too_long` | Entity filter would be silently truncated by Reltio | Simplify the filter or use another workflow |
| `invalid_query_value` | A reviewed query parameter has an empty, malformed, or undocumented value | Use the exact endpoint parameter contract; for Get Entity, use documented lowercase fields |
| `invalid_entity_option` | An entity option is malformed or unsupported for that operation | Use an option documented for the selected Entity API operation |
| `invalid_scan_option` | An entity scan option is outside the conservative source-bounded allowlist | Use `sendHidden`, `searchByOv`, `ovOnly`, or `nonOvOnly`; live-tenant applicability to `/entities/_scan` remains unverified |
| `scan_option_conflict` | `ovOnly` and `nonOvOnly` were requested together | Select exactly one operational-value response mode |
| `unverified_scan_options_refused` | Scan options were supplied without acknowledging that their schema belongs to a conflicting route | Pilot the option in a non-production tenant, then repeat with `--allow-unverified-scan-options` |
| `scan_option_acknowledgement_inapplicable` | `--allow-unverified-scan-options` was used without scan options on exact `POST /entities/_scan` | Remove the acknowledgement or use it only with a nonempty reviewed scan-option query |
| `invalid_resume_file_path` | Resume path cannot be represented safely in checkpoint metadata | Use a valid UTF-8 local path |
| `resume_file_invalid` | Resume progress or timestamps are inconsistent, or sequence capacity is exhausted | Use an unmodified checkpoint from the original scan or start a new file |
| `resume_context_mismatch` | Resume identity differs from current scan | Use the exact CLI version and original arguments, or start a new file |
| `resume_cursor_expired` | Saved cursor is beyond conservative lifetime | Start a new scan |
| `protected_header_refused` | Raw request attempted to override a security-controlled header | Remove the header |
| `dry_run_raw_output_unsupported` | Raw output cannot represent a structured dry-run plan | Use JSON or YAML output |
| `raw_force_match_refused` | Raw potential-match retrieval requested server-side recalculation through `forceMatch=true` | Remove `forceMatch` and read stored direct matches; use a reviewed future mutation workflow for recalculation |
| `redirect_refused` | Server returned a redirect | Verify the configured service URL; auth was not forwarded |
| `unreviewed_mutation_refused` | Raw mutation lacks reviewed endpoint policy or its planning acknowledgements | Add reviewed typed support or use all dedicated acknowledgements for a dry run |
| `unverified_scan_route_refused` | `/entities/v2/_scan` or a query/trailing-slash alias conflicts with the currently documented `/entities/_scan` route and has no live-tenant verification | Use `/entities/_scan` or typed `entity scan`; the refusal runs before body input, and the v2 route must be verified before registration |
| `scan_response_route_mismatch` | A canonical `/entities/_scan` request returned the conflicting v2 `entities` collection, including a response that also contains `objects` | Do not treat the page as exhaustion; verify the tenant route contract before retrying |
| `mutation_audit_unavailable` | A raw mutation would execute without the required versioned audit-result contract | Use `--dry-run`; implement and evidence `mutation_audit_v1` before sending a mutation |
| `api_internal_error` | Reltio returned `500`, which is not retried | Validate the request and contact support if persistent |
| `api_response_redaction_failed` | A response could not be represented without risking credential disclosure or silent field loss | Retain the request ID, narrow the response, and contact support; do not request raw output to bypass the refusal |
| `credential_output_refused` | Final rendered output would reproduce an active credential through generated envelope or formatting bytes | Treat stdout as omitted; inspect the guarded error and never replay a mutation unless it explicitly says replay is safe |
| `auth_login_commit_conflict` | The selected profile changed while login was acquiring credentials | Inspect the winning profile and retry deliberately; this login restored its candidate cache image |
| `auth_login_rollback_failed` | Profile persistence failed and candidate-cache restoration could not be verified | Do not retry; inspect `auth status` and local cache state |
| `profile_remove_cache_prepare_failed` | Imported-bearer cleanup could not be prepared before profile removal | Correct cache permissions and retry; no profile/cache deletion committed |
| `profile_remove_cache_failed` | Bearer deletion failed, its exact preimage remained, and the removed profile was restored | Correct cache permissions and retry the profile removal |
| `profile_remove_rollback_failed` | Bearer cleanup failed and exact profile restoration could not be completed | Inspect profile, cleanup-marker, and cache state; do not blindly replay |
| `profile_remove_cache_state_uncertain` | The profile was removed with durable cleanup intent, but bearer cleanup could not be verified | Do not recreate the profile; rerun any command to invoke recovery, then inspect the reported state |
| `profile_remove_config_failed` | Configuration removal failed before bearer deletion | Correct configuration storage and retry; the profile and bearer remain |
| `profile_remove_config_commit_uncertain` | Profile removal and cleanup-marker durability could not be fully confirmed; bearer deletion was not attempted | Inspect the config and authentication state; do not blindly replay |
| `profile_remove_cleanup_state_failed` | Profile and bearer were removed, but clearing the cleanup marker failed or was durability-uncertain | Rerun a command to finish idempotent recovery; honor `cleanup_pending` and `safe_to_replay` |
| `imported_bearer_cleanup_recovered` | Startup completed one or more interrupted profile-removal or auth-transition bearer cleanups and deliberately did not run the requested command | Review `recovered_profiles`, then replay the requested command |
| `imported_bearer_cleanup_failed` | Startup or a committed auth transition could not finish exact imported-bearer deletion | Correct cache storage, then rerun; the durable marker remains |
| `imported_bearer_cleanup_state_failed` | Bearer cleanup completed but its durable marker could not be cleared, or config state failed before deletion | Inspect `local_cache_committed` and `cleanup_pending`, correct config storage, and rerun recovery |
| `pending_bearer_cleanup_invalid` | Durable bearer-cleanup intent has an empty or malformed exact-key set | Repair the owner-private config from a trusted backup before continuing |
| `pending_bearer_cleanup_conflict` | An active profile references a cache key that is also pending deletion | Do not authenticate or delete; inspect the profile and durable cleanup state |
| `doctor_unhealthy` | One or more diagnostic checks warned or failed | Inspect `error.details.checks`, correct every non-pass check, and rerun `doctor` |
| `output_write_failed` | A physical output sink failed after rendering | Inspect commit-state details; never replay when `local_state_committed` is true |
| `credential_process_containment_failed` | A Windows credential broker could not be safely assigned/resumed in its kill-on-close Job | Repair local Windows process policy; inspect `credential_process_started` and `safe_to_replay` because a post-resume anomaly may have executed broker code |
| `credential_process_cleanup_failed` | A credential broker root exited, but process-tree cleanup could not be confirmed | Terminate any remaining broker processes and inspect host policy before a deliberate retry; broker side effects are unknown and replay is unsafe |
| `hidden_input_unavailable` | Interactive hidden input has no native Windows console | Use `--secret-stdin` or `--secret-file` |
| `hidden_input_cleanup_failed` | Unix or Windows could not clear abandoned credential input or restore terminal state after a controlled failure | Treat the terminal as unsafe for further secret input and open a fresh terminal |
| `auth_timeout` | The shared command deadline expired during credential acquisition, auth locking, broker execution, or token replay | Inspect commit-state details and retry only when `safe_to_replay` permits it |
| `config_timeout` | The shared command deadline expired while waiting for or committing local configuration | Inspect `local_state_committed`; do not blindly replay a committed or uncertain operation |
| `request_timeout` | Overall local timeout expired | Verify the remote outcome before repeating an ambiguous operation |
| `request_canceled` | SIGINT or another cancellation source interrupted local work or an in-flight request | Inspect local/remote completion and `safe_to_replay`; SIGINT exits `130` and never becomes success |
| `api_rate_limited` | Reltio returned `429`; automatic retries reached their ceiling or the next delay could not fit the command deadline | Honor `Retry-After`; when `retry_budget_exhausted` is true, retain the HTTP status and request ID and expect the unread body to be omitted |
| `retry_budget_exhausted` | A replay-safe transport failure had no HTTP response and the next retry delay could not fit the command deadline | Retry later; no triggering HTTP response exists to report |
| `release_operations_incomplete` | The product-MVP gate found missing PRD operations, operation-specific implementation evidence, exact endpoint bindings, capabilities, acceptance scenarios, or contract evidence/runtime support | Inspect `error.details.blockers`; do not publish or tag the target stable release, and run the separate platform/distribution gates |
| `invalid_expected_release` | `--expected-release` is not a stable `MAJOR.MINOR.PATCH` value | Pass the exact stable tag version without prerelease/build metadata |
| `release_version_mismatch` | The expected tag version, PRD-bound manifest target, and built CLI package version differ | Update all three together before creating or publishing a stable tag |

`doctor_unhealthy` preserves the category, HTTP status, request ID, and retryability of the first concrete failed check. A warning-only report uses category `internal` and exit `1`. Its ordinary structured form carries the bounded diagnostic report, including every check completed before an unrecoverable prerequisite failure, under `error.details`; irreducible credential collisions use the guarded fallback contract. Unhealthy diagnostics never use a success envelope or exit `0`.

Reltio response bodies are bounded and redacted before inclusion in error details. HTML and unambiguously non-JSON responses are represented as bounded text rather than parser errors. A body identified as JSON but too deep, duplicate-keyed, structurally excessive, malformed, or impossible to serialize without recreating a credential is omitted from diagnostics because safe representation cannot be proven; only body-free metadata is emitted. An API error body over 64 KiB is likewise omitted with `response_body_truncated: true`; its HTTP status, request ID, retry ceiling, and status-specific error code remain authoritative. An oversized OAuth error body uses the same marker, retains the token endpoint's status-specific policy, and denies output for the originating command because the uninspected bytes may contain provider secrets.
