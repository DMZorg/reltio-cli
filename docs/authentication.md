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

The executable is run directly without a shell. Arguments retain exact boundaries. The executable path must be absolute and identify an owner-private file in a mutation-safe local directory. On Unix it must be owner-executable with no group or other permissions, typically mode `0700`. On Windows the path must end in `.exe` (case-insensitive); extensionless names and shell scripts are refused so Windows cannot select a different file. The Windows broker must be a self-contained PE in a dedicated directory containing no sibling DLLs, `.local` directory, SxS tree, or other entries. That directory must deny untrusted file/subdirectory creation. The validated executable and ancestor handles exclude data-write, append, and delete sharing and remain open until process creation returns. Before spawn the CLI restores the default DLL search order and registry-controlled Safe DLL Search Mode; the broker starts in its private directory without an inherited `PATH`. This prevents path search, caller working-directory, app-local dependency planting, link, extension probing, or cross-user replacement from selecting broker code.

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

Token cache keys include provider, auth URL, and identity. Files and directories are owner-only on Unix. A cross-process file lock ensures concurrent CLI processes recheck the cache after acquiring the lock, preventing token-request storms. Tokens are reused until expiry; provider and imported candidates that are not usable beyond the five-second local skew window are rejected before any cache preimage is replaced. Cache version and provider identity are validated before use.

Login validates the selected profile before consuming one-shot secret stdin, acquires a usable candidate token without persisting it, then takes the exclusive cache-maintenance lock. While that lock is held, it guards every local token-cache generation plus prior profile secret and HTTP Basic material, snapshots the candidate cache path byte-for-byte, and prepares the exact success document, including any warning metadata. Candidate usability is checked again immediately before installation. It durably stages the candidate cache before compare-and-swapping the selected profile. A cache failure restores and verifies every touched preimage. A profile failure before its commit point removes or restores the staged candidate while readers remain blocked; a concurrent winning profile's credentials are added to the error guard. A profile write that crossed its commit point is not rolled back and reports committed state with any durability uncertainty.

Displaced cache generations are deliberately retained during login and profile update. This keeps an old profile snapshot usable for a command that resolved it before the profile commit and prevents a process death between cache and profile commit from deleting the old provider's credential. If the process dies in that interval, the old profile and old cache remain coherent while an unused candidate token may remain until expiry or `auth logout`; login never claims atomic rollback after process termination. After a successful profile commit, both the selected profile and its candidate cache are usable. A deterministic rendering refusal changes no state. A physical stdout failure after both commits cannot be preflighted, so the error reports `local_state_committed: true` and tells callers not to replay login. Login emits no separate pre-success warning bytes, preserving one structured stderr document if stdout later fails.

`profile remove` uses the same cache-maintenance-before-config lock order. It guards and snapshots the profile's imported bearer, preflights success output, stages cache deletion, and only then removes the profile and current-profile selection. A configuration failure before commit restores and verifies the exact bearer preimage while readers remain blocked. A failure after the configuration commit point keeps the coherent deletion and reports both profile/cache commit state; an unverified rollback reports `safe_to_replay: false` and directs recovery through `auth logout`.

Reltio's documented default token lifetime is 60 minutes and token endpoint limit is 10 requests per second. Without Multi Token Support, an early token request may return the existing token with its original validity, so normal commands do not refresh speculatively. When explicit login receives the same token bytes already in cache, the CLI preserves the original acquisition time and caps the new expiry at the cached expiry instead of falsely extending that token's lifetime. If Reltio rejects a token and the provider reissues that same token, the CLI records that refresh generation and stops with `auth_token_unchanged`; concurrent and later processes do not create a repeated token-request/replay loop.

`auth status` reports `environment_override: true` and emits a warning when `RELTIO_CLIENT_ID`, `RELTIO_CLIENT_SECRET`, or `RELTIO_ACCESS_TOKEN` changes the selected profile credential source.

Reltio's token-specific guidance says not to retry authentication token failures except the `429` multi-token rate-limit case. The CLI therefore makes one attempt for transport failures and non-`429` responses. It may replay a `429` once within the authentication deadline; `--no-retry` disables that replay as well as the one-time safe `401` refresh used for tenant API requests. An oversized `429` diagnostic body is omitted rather than allowed to suppress the replay. Because its uninspected provider bytes cannot be proven safe, the originating command receives a deny-all output guard even if the replay acquires a usable token; a later invocation may use the safely cached token normally.

## Disclosure And Logout

```bash
reltio --profile dev auth token --show --output raw > /secure/consumer-input
reltio --profile dev auth logout
```

`auth token` requires `--show` and refuses terminal stdout without `--yes`. Intentional disclosure exempts only the selected access token's exact bytes; distinct refresh tokens, client secrets, every final or orphaned cache generation, and environment credentials remain active guards for raw and structured output, including generated write errors. Every command and pre-parse help/error path includes local cache generations in its final-byte guard. Malformed generations are guarded without ending enumeration; an unreadable recognized generation denies all output because its contents cannot be proven safe. `auth logout` guards every deletion candidate before removing any, and cleanup failures report the number already removed plus `local_state_committed` and idempotent replay safety when those fields are representable. If an unusually short opaque credential collides with every context-bearing error representation, the general output contract intentionally permits only a safe scalar or empty stderr rather than disclosing it. This alpha does not claim remote token revocation. Environment variables belong to the invoking process and cannot be cleared by the CLI.
