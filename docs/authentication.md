# Authentication

## Provider Matrix

| Provider | Best for | Secret source | Persisted material |
| --- | --- | --- | --- |
| Supplied bearer | One process or managed injection | `RELTIO_ACCESS_TOKEN` | None |
| Imported bearer | Deliberate short-lived local use | `--token-stdin` | Access token cache |
| Client credentials | CI, agents, integrations | Environment, owner-only file, hidden prompt, or stdin | Access token cache; never the client secret |
| Credential process | Vaults, brokers, workload identity | Direct executable invocation | Access token cache until declared expiry |

Authorization code/SSO is required by the product contract but is not included in this alpha. Use a supplied bearer or a credential process for user-delegated pilot workflows until the SSO callback and registration matrix is complete.

## Client Credentials

The CLI uses the reviewed request shape:

```http
POST https://auth.reltio.com/oauth/token
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

Credentials are never sent in a URL. The retired `/services/oauth/token` endpoint is not used. One credential pair per application is recommended.

Interactive hidden input is bounded by the same command deadline and 1 MiB local limit as stdin input. Unix opens the controlling terminal, polls nonblocking input, flushes an abandoned partial line while echo remains disabled, and then restores its exact termios state. Native Windows input consumes low-level console key records without changing shared console modes or leaving a blocking read behind; cancellation, timeout, invalid UTF-16, and oversize input clear abandoned console records before returning. Current automated Windows evidence covers synthetic key-record parsing only. Native console open/wait/read/flush behavior, timeout and cancellation cleanup, and post-failure console reuse remain pilot-gated. A redirected or non-native Windows console must use `--secret-stdin` or `--secret-file`.

Client secrets, access tokens, refresh tokens, authentication responses, and credential-process responses are limited to 1 MiB. Before a provider response is parsed, every JSON string value is collected with duplicate object keys preserved; malformed or truncated JSON installs a deny-all output guard. After successful parsing, that complete response guard remains attached for the originating command, so OAuth extension values and credential-process metadata cannot be reproduced by later generated or upstream output. Access and refresh tokens must be nonempty and contain no line breaks. On `auth login`, explicit `--client-id`, `--secret-stdin`, and `--secret-file` inputs take precedence over conflicting environment values for that invocation; `--secret-stdin` and `--secret-file` are mutually exclusive because authenticating from one source while persisting another is unsafe. Profile and target validation precede one-shot stdin consumption. All captured environment secrets still protect final output. Provider options that do not apply to the selected method are rejected rather than ignored.

```bash
# Environment-injected secret
RELTIO_CLIENT_SECRET="$SECRET" \
  reltio --profile dev auth login \
  --method client-credentials \
  --client-id example-client

# Owner-only secret file; the profile stores only its path
chmod 600 /secure/path/reltio-client-secret
reltio --profile dev auth login \
  --method client-credentials \
  --client-id example-client \
  --secret-file /secure/path/reltio-client-secret
```

## Credential Process

The executable is run directly without a shell. Arguments retain exact boundaries. The executable path must be absolute and identify an owner-private file in a mutation-safe local directory. On Unix it must be owner-executable with no group or other permissions, typically mode `0700`; the CLI refuses shebang scripts and starts the executable in a separate process group. Timeout or cancellation terminates and reaps that group so ordinary child processes cannot outlive the broker. Before every spawn the CLI rebuilds the inherited environment from the same filtered snapshot used in the cache identity: `PATH`, Reltio secret variables, dynamic-loader families such as `LD_*` and `DYLD_*`, shell startup hooks, and managed-runtime profiler/startup families are omitted. On Windows the path must end in `.exe` (case-insensitive); extensionless names and shell scripts are refused so Windows cannot select a different file. The Windows broker must be a self-contained PE in a dedicated directory containing no sibling DLLs, `.local` directory, SxS tree, or other entries. That directory must deny untrusted file/subdirectory creation. The validated executable and ancestor handles exclude data-write, append, and delete sharing and remain open until process creation returns. Before spawn the CLI restores the default DLL search order and registry-controlled Safe DLL Search Mode; the broker is created suspended, assigned to a kill-on-close Job Object, resumed only after assignment, and started in its private directory. If containment cannot be established, the process is terminated and authentication fails closed; a post-spawn containment anomaly is conservatively non-replayable because execution may have started. Timeout, cancellation, or an early CLI exit closes the Job Object and terminates its process tree. A cleanup failure is deny-all and non-replayable because broker side effects are unknown. Native Windows test source currently covers successful suspended assignment/resume and Job-handle-close termination of a child and grandchild. Timeout, cancellation, root-exit, early-CLI-exit, containment-failure, and cleanup-failure paths do not yet have native runtime evidence.

```bash
chmod 700 /secure/bin/company-auth
reltio --profile dev auth login \
  --method credential-process \
  --credential-process /secure/bin/company-auth \
  --credential-process-arg reltio-token \
  --credential-process-arg=--environment \
  --credential-process-arg dev
```

Stdout must contain only this strict JSON contract:

```json
{
  "access_token": "opaque-token",
  "expires_at": "2026-08-08T12:00:00Z",
  "metadata": {}
}
```

`expires_in` may be supplied instead of `expires_at`. `refresh_token` is accepted only when nonempty, line-break-free, and within the 1 MiB response bound. It is not persisted or used in this alpha; it remains protected by the output guard for the complete acquisition, request, and rendering lifetime. Unknown top-level fields are rejected.

## Cache And Concurrency

Token cache keys include provider and the complete identity inputs controlled by that provider. Client credentials include token URL and client ID. Imported bearer keys include the normalized config scope, profile, complete resolved route, and a fresh non-secret generation nonce; the exact derived key and nonce are persisted as profile metadata. Credential-process keys include config scope, complete route, exact argument boundaries, and a digest of the exact filtered environment snapshot passed to the child. Changes to those represented inputs invalidate the cache, but executable contents and external vault, cloud-profile, or broker state are not observable; after those change, run `auth logout` before relying on a new broker principal. Files and directories are owner-only on Unix. A cross-process file lock ensures concurrent CLI processes recheck the cache after acquiring the lock, preventing token-request storms. Tokens are reused until expiry; provider and imported candidates that are not usable beyond the five-second local skew window are rejected before any cache preimage is replaced. Cache version and provider identity are validated before use. A profile created by the earlier profile-only bearer-key format fails with `bearer_cache_migration_required`; run `auth logout` to remove the ambiguous global cache and deconfigure imported-bearer profiles before logging in again.

Every finite command computes one absolute deadline from `--timeout`. Authentication acquisition, token-endpoint requests and bounded replay, credential-process execution, bounded local request-body input, rate and maintenance locks, cache work, configuration locks, the tenant request, final output-lease acquisition, and bounded-chunk output all consume the remaining portion of that same budget; no stage or diagnostic receives a fresh timeout. Exact compensation after a partially applied local cache plan remains mandatory, but it does not authorize further forward work. SIGINT is armed before parsing and independently cancels input, lock waits, process waits, retry sleeps, requests, response reads, and output admission/emission. A first SIGINT requests graceful cleanup; a second drops a still-running command future so Rust containment guards run without `process::exit`, while the first control event remains authoritative for timeout and exit classification. A cancellation check precedes each controlled local commit. A command whose output thread publishes its completion stamp immediately after the final flush and before cancellation or deadline activation wins the final control race; otherwise control cannot become success. A blocked inherited sink can leave a stdout prefix that may be unterminated or complete-looking, so automation always requires both valid complete framing and zero exit status. Stderr is intentionally absent when the deadline or cancellation has already ended the budget and no authoritative diagnostic lease is held.

Login validates the selected profile before consuming one-shot secret stdin, acquires a usable candidate token without persisting it, then takes the exclusive cache-maintenance lock. While that lock is held, it guards every local token-cache generation plus prior profile secret and every environment/profile HTTP Basic combination, verifies that the fresh imported-bearer generation path is absent, and prepares the exact success document, including any warning metadata. Candidate usability is checked again immediately before installation. It durably stages the immutable candidate generation before compare-and-swapping the selected profile pointer. A cache failure restores and verifies every touched preimage. A profile failure before its commit point removes the staged candidate while readers remain blocked; a concurrent winning profile's credentials are added to the error guard. A profile write that crossed its commit point is not rolled back and reports committed state with any durability uncertainty.

Before the profile commit, the old profile still points to its usable cache generation while the fresh candidate exists only under a distinct key. A process death in that interval can leave an unused owner-only candidate until expiry or `auth logout`, but cannot replace the active generation; login never claims atomic orphan removal after process termination. When a committed auth or route transition retires an imported bearer, the same profile commit persists its exact key in `pending_imported_bearer_cleanups`. The command then removes that generation under the exclusive maintenance lock and clears the marker; a crash leaves durable forward-cleanup intent. A command that resolved the retired profile before this transition may therefore fail closed and must resolve the current profile again rather than reuse stale identity. A deterministic rendering refusal changes no state. A physical stdout failure after both commits cannot be preflighted, so the error reports `local_state_committed: true` and tells callers not to replay login. Login emits no separate pre-success warning bytes, preserving one structured stderr document when the remaining budget permits it.

`profile remove` uses the same cache-maintenance-before-config lock order. It guards and snapshots the profile's active imported-bearer key together with every already-pending retired key, then preflights success output before mutation. A profile without an imported bearer or pending retired bearer is removed without creating an empty cleanup marker. Otherwise, the command atomically removes the profile/current selection while unioning all keys into `pending_imported_bearer_cleanups`, deletes them under the held cache plan, and atomically clears the non-secret marker. A crash leaves either profile plus bearer or removed profile plus durable forward-cleanup intent. The next invocation completes pending cleanup, returns `imported_bearer_cleanup_recovered` without starting the requested command, and asks the caller to replay. If ordinary bearer deletion fails while its exact preimage remains, the CLI restores the removed profile using a bounded mandatory compensation budget even when the original command deadline or cancellation caused the cache failure. The same marker mechanism cleans bearers retired by successful provider and route transitions.

Reltio's documented default token lifetime is 60 minutes and token endpoint limit is 10 requests per second. Without Multi Token Support, an early token request may return the existing token with its original validity, so normal commands do not refresh speculatively. When explicit login receives the same token bytes already in cache, the CLI preserves the original acquisition time and caps the new expiry at the cached expiry instead of falsely extending that token's lifetime. If Reltio rejects a token and the provider reissues that same token, the CLI records that refresh generation and stops with `auth_token_unchanged`; concurrent and later processes do not create a repeated token-request/replay loop.

`auth status` reports `environment_override: true` and emits a warning when `RELTIO_CLIENT_ID`, `RELTIO_CLIENT_SECRET`, or `RELTIO_ACCESS_TOKEN` changes the selected profile credential source.

Reltio's token-specific guidance says not to retry authentication token failures except the `429` multi-token rate-limit case. The CLI therefore makes one attempt for transport failures and non-`429` responses. It may replay a `429` once within the authentication deadline; `--no-retry` disables that replay as well as the one-time safe `401` refresh used for tenant API requests. An oversized `429` diagnostic body is omitted rather than allowed to suppress the replay. Because its uninspected provider bytes cannot be proven safe, the originating command receives a deny-all output guard even if the replay acquires a usable token; a later invocation may use the safely cached token normally.

## Disclosure And Logout

```bash
reltio --profile dev auth token --show --output raw > /secure/consumer-input
reltio --profile dev auth logout
```

`auth token` requires `--show` and refuses terminal stdout without `--yes`. Intentional disclosure exempts only the selected access token's exact bytes; distinct refresh tokens, client secrets, every final or orphaned cache generation, and environment credentials remain active guards for raw and structured output, including generated write errors. Every command and pre-parse help/error path includes local cache generations in its final-byte guard. Malformed generations are guarded without ending enumeration; an unreadable recognized generation denies all output because its contents cannot be proven safe. `auth logout` guards every deletion candidate before removing any and retains the exclusive cache-maintenance lease while clearing pending bearer-cleanup markers and deconfiguring imported-bearer profiles. A concurrent login therefore either commits before logout clears it or loses its profile compare-and-swap after logout; successful logout cannot strand that login's token. Cleanup failures report the number already removed plus `local_state_committed` and idempotent replay safety when those fields are representable. If an unusually short opaque credential collides with every context-bearing error representation, the general output contract intentionally permits only a safe scalar or empty stderr rather than disclosing it. This alpha does not claim remote token revocation. Environment variables belong to the invoking process and cannot be cleared by the CLI.
