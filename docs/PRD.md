# Reltio CLI Product Requirements Document

| Field | Value |
| --- | --- |
| Product | `reltio` — an agent-native Rust CLI for Reltio public APIs |
| Repository | `aiadjacent/reltio-cli` |
| Status | Proposed product contract |
| PRD version | 0.1 |
| Date | 2026-08-08 |
| Initial release target | `v0.1.0` |

## 1. Executive summary

`reltio` will be a production-grade command-line interface for managing Reltio data and platform operations. It will be equally usable by people, shell scripts, CI jobs, and AI agents, with an explicit bias toward stable machine-readable contracts.

The product is more than a collection of HTTP aliases. Reltio exposes many public API families across different hosts, uses multiple OAuth flows, operates in a multi-environment and multi-tenant model, has both synchronous and asynchronous operations, and includes high-impact actions such as deletes, merges, unmerges, bulk jobs, and business-configuration replacement. The CLI must make the common path easy without hiding the identity, tenant, consistency, or safety context of an operation.

The first useful release will provide:

- profile and environment management;
- robust authentication for humans and headless agents;
- typed commands for core entity, relation, configuration, and task workflows;
- JSON-first output, stable structured errors, pagination, and asynchronous job waiting;
- mutation safeguards appropriate for production master data;
- a controlled raw-request escape hatch for immediate access to public endpoints that do not yet have typed commands;
- embedded, version-matched guidance that agents can retrieve from the binary.

The long-run goal is broad typed coverage of Reltio's public APIs without sacrificing a coherent command vocabulary or backwards-compatible automation contract.

## 2. Product context

### 2.1 Problem

Using Reltio APIs directly requires users and agents to repeatedly solve the same infrastructure problems:

- determine the correct service host and tenant-scoped path;
- obtain, cache, refresh, and protect OAuth tokens;
- handle client credentials, SSO/authorization code, supplied bearer tokens, and corporate credential brokers;
- avoid token-request storms and expiry races across concurrent processes;
- build filters, cursors, offset pagination, and bulk input correctly;
- poll task and export state without wasteful or brittle scripts;
- preserve JSON fidelity while still making output readable for people;
- understand which reads are immediately consistent and which depend on an eventually consistent index;
- protect the correct tenant when running destructive or high-impact operations;
- turn inconsistent HTTP failures into actionable, stable errors;
- keep automation current as Reltio adds endpoints and capabilities.

The result today is duplicated glue code, secrets in shell history, accidental tenant mistakes, one-off scripts with ambiguous retry behavior, and excessive context use by agents trying to rediscover commands and response shapes.

### 2.2 Opportunity

A single native binary can centralize those concerns and provide a trustworthy operational layer over Reltio. Humans gain discoverable commands, guided setup, readable views, and guardrails. Agents gain deterministic JSON, schemas, documented exit codes, version-matched instructions, and commands that compose without prompts.

The product complements rather than replaces Reltio's MCP offerings. Reltio's MCP servers are useful for governed tool invocation. This CLI targets terminal, shell, CI, local data engineering, incident response, configuration-as-code, and agent harnesses that work most reliably through processes and files.

### 2.3 Research observations that shape this PRD

- Reltio's public developer surface spans entity, relation, interaction, reference data, load/export, integration, workflow, system administration, statistics, validation, and hierarchy APIs.
- Service URLs differ by API family. Data, tasks, physical configuration, jobs/export, workflow, RDM, DTSS, and authentication cannot be treated as one base URL with one prefix.
- Reltio documents client credentials, password, and authorization-code access. SSO users need an authorization-code path; MFA can introduce a state-token and OTP exchange.
- Access tokens commonly expire after one hour. Refresh tokens commonly expire after 28 days. Reltio advises caching tokens and documents a token endpoint limit of 10 requests per second.
- Client-credential access tokens come from a centralized auth service and are not tenant-specific at issuance, while tenant API calls still enforce tenant permissions and IP allowlists.
- Entity and relation scans use cursors, while some searches use offsets. Cursor lifetimes and endpoint limits make pagination an application concern, not just a flag.
- Reltio exposes both consistent and eventually consistent reads. An immediate object read and an indexed search can legitimately disagree after a write.
- Tenant business-configuration updates require special care: editable L3/no-inheritance configuration should be used for changes, validation should precede apply, and an inherited/effective configuration must not be written back as if it were L3.
- Long-running services expose task states that need normalized polling, timeout, and terminal-state handling.
- The Kagi CLI demonstrates useful agent-native patterns: JSON-first output, profiles, guided auth, structured errors, shell completion, an embedded agent guide, and a raw/structured workflow surface.

## 3. Vision and product principles

### 3.1 Vision

Make Reltio data and platform operations safe, legible, and composable from any terminal or agent runtime.

### 3.2 Principles

1. **Machine contracts are product APIs.** Command names, JSON fields, exit codes, and stderr behavior are versioned interfaces, not incidental output.
2. **Context must always be visible.** The selected profile, environment, tenant, service, and auth source must be inspectable and included in operation metadata where safe.
3. **Safe by default, explicit when dangerous.** High-impact operations require deliberate acknowledgement. Non-interactive use remains possible through deterministic flags rather than prompts.
4. **Never trade correctness for a pretty abstraction.** Reltio-specific concepts such as crosswalks, operational values, merges, cursor scans, L3 configuration, and eventual consistency remain visible where they affect outcomes.
5. **Easy common paths, complete escape hatch.** Typed commands optimize frequent work; `api request` provides controlled access to the rest of the public surface.
6. **Auth is infrastructure.** Credentials are resolved, cached, refreshed, redacted, and diagnosed centrally. Individual commands never invent their own auth behavior.
7. **Stdout is data; stderr is narration.** Progress, prompts, and diagnostics never corrupt structured output.
8. **Agents should not guess.** The binary exposes version-matched skills, command metadata, examples, and error recovery hints.
9. **No silent production surprises.** Mutation retries, target expansion, fallback auth, default tenants, and pagination must be explicit and observable.
10. **No telemetry by default.** Master-data operations are sensitive. The CLI does not transmit product analytics unless a future opt-in design is separately approved.

## 4. Goals and non-goals

### 4.1 Goals

- Reduce initial authenticated setup to one guided workflow for a human and a documented environment/profile workflow for an agent.
- Make common entity, relation, configuration, task, import, and export operations possible without hand-authoring HTTP requests.
- Offer a stable, JSON-first contract across all commands.
- Support multiple Reltio environments and tenants without copying configuration or credentials.
- Handle token reuse, expiry, concurrency, and auth diagnostics correctly.
- Make bulk retrieval and asynchronous tasks resumable and observable.
- Prevent common wrong-tenant, inherited-configuration, ambiguous-update, and accidental-delete failures.
- Provide immediate public API reach through a safe raw request command.
- Establish an architecture that can expand to broad public API coverage.
- Ship as a fast, cross-platform Rust binary with reproducible releases.

### 4.2 Non-goals for `v0.1.0`

- Reimplement the Reltio Hub, Console, Data Loader UI, or Workflow UI.
- Hide Reltio's data model behind a generic CRUD model.
- Provide typed commands for every public endpoint in the first release.
- Generate arbitrary transformations or mapping logic from natural language.
- Store source data, credentials, or request bodies in a hosted service.
- Build an MCP server into the first release. The CLI may expose one later if it adds clear value beyond Reltio's official MCP options.
- Guarantee transactions across multiple Reltio API requests.
- Automatically retry ambiguous non-idempotent writes.
- Make password grant the recommended automation method.
- Support private, undocumented, or browser-scraped Reltio endpoints.

## 5. Users and jobs to be done

### 5.1 Primary personas

#### AI or automation agent

Needs to discover capabilities, select a profile, inspect or change records, stream large results, recover from errors, and verify outcomes without parsing prose or receiving an interactive prompt.

#### Data engineer or integration developer

Needs to explore data, test filters, upsert records, run repeatable imports/exports, wait on tasks, compare environments, and use the CLI in shell pipelines and CI.

#### Reltio configurator or platform administrator

Needs to inspect and validate L3 configuration, understand diffs, apply targeted changes safely, inspect tasks, and diagnose auth, permissions, and tenant routing.

#### Data steward or incident responder

Needs to retrieve profiles and relationships, inspect matches and history, perform carefully guarded merge/unmerge actions, and capture auditable results.

### 5.2 Representative jobs

- "Show me this entity by URI or crosswalk, with only the fields I need."
- "Search for organizations matching this Reltio filter and return the next page token."
- "Stream every matching entity as JSONL and resume if the process stops."
- "Upsert these source records without accidentally replacing values from other crosswalks."
- "Explain why two profiles match before I merge them."
- "Export the editable L3 configuration, review a semantic diff, validate it remotely, and apply it to the intended tenant."
- "Start an export, wait until it reaches a terminal state, and download all outputs."
- "Use our corporate token broker rather than putting a client secret in a local config file."
- "Call a newly released public endpoint before a typed command exists."
- "Given an error, tell an agent whether retrying is safe and which command will resolve the problem."

## 6. Scope and release plan

Typed coverage will be delivered in layers. The raw request command provides broad reach from the first release, but it does not count as typed coverage.

### 6.1 `v0.1.0` — foundation and core data MVP

#### Foundation

- `profile` management and deterministic configuration precedence.
- `auth` setup, status, login, check, token, and logout.
- Credential providers for supplied bearer tokens, client credentials, authorization code/SSO, and external credential processes.
- Secure cross-process token caching and refresh behavior.
- Central service URL resolver for data, tasks, physical configuration, jobs, workflow, RDM, DTSS, MCP, and auth.
- Stable success/error contracts, exit codes, logging, redaction, timeouts, retries, and request IDs.
- `api request` raw escape hatch.
- `skills`, `agent`, `command schema`, and shell-completion commands.

#### Core typed commands

- Entity get, get-by-URIs, get-by-crosswalk, search, cursor scan, create/upsert, explicitly-modeled update, delete, history, and potential-match retrieval.
- Relation get, search, cursor scan, create/update, and delete.
- Business configuration pull/get, validate, diff, backup, and guarded apply.
- Task get, list, wait, and cancel where the target task service supports it.

#### MVP exclusions

- Password/MFA login may be implemented behind an explicit compatibility flag if required by pilot users, but it is not a release blocker because client credentials, SSO, bearer injection, and credential processes cover the recommended paths.
- Typed merge/unmerge, load/export, interaction, RDM, workflow, hierarchy, statistics, validation, and user/client administration are deferred as described below.

### 6.2 `v0.2.x` — operational workflows

- Typed merge, unmerge, verify-match, verify-unmerge, and match-decision commands.
- Export start/status/wait/download and resumable downloads.
- Load/import start/status/wait with JSON and JSONL input support.
- Interaction CRUD and scan.
- Reference Data Management lookups and mappings.
- Password plus MFA state-token flow, only if validated customer need remains.
- Configuration sub-resource commands and environment-to-environment diff helpers.
- Optional token-efficient structured rendering after its contract and ecosystem stability are validated.

### 6.3 `v0.3.x` — platform and governance coverage

- Workflow tasks and process operations.
- Data Validation Functions.
- Hierarchy and graph traversal helpers.
- Statistics/reporting and tenant task operations.
- User, role, customer-client, and other system-administration commands with elevated safety tiers.
- Reltio MCP metadata discovery and connection diagnostics where useful.

### 6.4 `v1.0.0` — stable public contract

- Stable command and output compatibility policy.
- Documented typed coverage matrix for supported Reltio public APIs.
- Migration policy for deprecated Reltio endpoints and CLI commands.
- Proven cross-platform installation and upgrade paths.
- Security review, threat model, release signing, SBOM, and dependency policy.
- At least one release cycle of pilot use against development, test, and production profiles.

## 7. Command-line experience

### 7.1 Binary and naming

- Executable name: `reltio`.
- Cargo package name: `reltio-cli` unless crate-name availability or policy requires a change.
- Commands use singular resource nouns: `entity`, `relation`, `task`, `profile`.
- Verbs are consistent: `get`, `list`, `search`, `scan`, `create`, `update`, `delete`, `start`, `wait`, `cancel`, `pull`, `diff`, `validate`, `apply`.
- Every command and flag has a stable long form. Short flags are conveniences and are never the only documented form.

### 7.2 Proposed top-level command map

```text
reltio
├── profile  list | show | add | update | use | remove
├── auth     login | status | check | token | logout
├── entity   get | get-many | by-crosswalk | search | scan
│            create | upsert | update | delete | history | matches
├── relation get | search | scan | create | update | delete
├── config   get | pull | validate | diff | apply | backup
├── task     get | list | wait | cancel
├── api      request
├── skills   list | get | path
├── agent    guide
├── command  schema
├── completion generate | install
└── doctor
```

Later typed families add `match`, `export`, `load`, `interaction`, `rdm`, `workflow`, `hierarchy`, `validate`, `stats`, and `admin` without flattening hundreds of unrelated operations into the root.

### 7.3 Global flags

| Flag | Behavior |
| --- | --- |
| `--profile <name>` | Select a named profile for this invocation. |
| `--environment <namespace-or-url>` | Override the profile environment. Requires compatible tenant/auth context. |
| `--tenant <id>` | Override the tenant. The resolved target is always reported. |
| `--output <json|jsonl|table|yaml|raw>` | Select rendering. Default is `json`. |
| `--compact` | Emit compact rather than indented JSON. |
| `--fields <expression>` | Pass a supported Reltio field selection to typed reads. |
| `--query <expression>` | Apply a documented local query to the response after retrieval. Deferred until a stable query language is selected. |
| `--timeout <duration>` | Overall request or wait timeout, depending on the command. |
| `--connect-timeout <duration>` | HTTP connection timeout. |
| `--no-retry` | Disable safe automatic retries. |
| `--dry-run` | Resolve and validate a mutation without sending it. |
| `--yes` | Confirm a prompt in non-interactive mode; does not bypass production tenant confirmation. |
| `--confirm-tenant <id>` | Confirm the exact tenant for high-impact production actions. |
| `--no-color` | Disable color on human-readable stderr/table output. |
| `--quiet` | Suppress non-error stderr progress. |
| `--verbose` | Show request timing and routing without secrets. Repeat for greater detail. |
| `--trace-file <path>` | Write a scrubbed diagnostic trace to a local file. |

Environment and tenant overrides are intentionally separate. A token being valid does not prove that the user intended the resolved tenant.

### 7.4 Input contract

Commands accepting bodies support the same forms:

- `--data @path.json` reads a file;
- `--data -` reads stdin;
- `--data '<json>'` accepts small inline JSON;
- `--file <path>` is an ergonomic alias on file-centric commands;
- JSONL is accepted only by commands that explicitly document record streaming or batches;
- UTF-8 is required unless a load service explicitly supports another encoding;
- a TTY prompt is never used to collect an API body in non-interactive mode.

Inline bodies remain available, but docs prefer files or stdin so large/sensitive payloads do not enter shell history or process listings.

### 7.5 Example workflows

```bash
# Create a profile without storing a secret in the TOML file.
reltio profile add dev --environment dev --tenant ExampleTenant
reltio --profile dev auth login --method client-credentials --client-id "$RELTIO_CLIENT_ID"

# Inspect the resolved target and credential source.
reltio --profile dev auth status
reltio --profile dev doctor

# Retrieve and search data.
reltio --profile dev entity get entities/00009qz
reltio --profile dev entity by-crosswalk --type HCS --value 00370257
reltio --profile dev entity search \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --max 25

# Stream a cursor scan without buffering the full result set.
reltio --profile dev entity scan \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --output jsonl > organizations.jsonl

# Preview and then perform a partial override explicitly.
reltio --profile dev entity update entities/00009qz \
  --mode partial-override --data @update.json --dry-run
reltio --profile dev entity update entities/00009qz \
  --mode partial-override --data @update.json --yes

# Safe configuration-as-code flow.
reltio --profile dev config pull --out tenant-l3.json
reltio --profile dev config diff --file tenant-l3.json
reltio --profile dev config validate --file tenant-l3.json
reltio --profile dev config apply --file tenant-l3.json --yes

# Use a public endpoint before a typed command exists.
reltio --profile dev api request GET /entities/00009qz --service data

# Load version-matched instructions for an agent.
reltio skills get reltio-usage
reltio command schema entity.update
```

Examples use shell variables only to show headless usage. Guided login must accept secrets through a hidden prompt, stdin, keyring, or credential process rather than requiring a secret in a command argument.

## 8. Profiles, environments, and configuration

### 8.1 Profile model

A profile describes routing, identity-provider configuration, and safety posture. It does not store source data and does not store raw client secrets by default.

Illustrative configuration:

```toml
version = 1
current_profile = "dev"

[profiles.dev]
environment = "dev"
tenant = "ExampleTenant"
production = false

[profiles.dev.auth]
method = "client_credentials"
client_id = "example-client"
secret_source = "keyring"

[profiles.prod]
base_url = "https://example.reltio.com"
tenant = "ExampleTenantProd"
production = true
write_policy = "confirm"

[profiles.prod.auth]
method = "credential_process"
command = ["company-auth", "reltio-token", "--environment", "prod"]
```

### 8.2 Locations

- Config: platform config directory, conventionally `$XDG_CONFIG_HOME/reltio/config.toml` or `~/.config/reltio/config.toml`.
- Cache: platform cache directory, conventionally `$XDG_CACHE_HOME/reltio/`.
- State: platform state directory for resumable cursors, task references, and configuration metadata.
- Explicit override: `RELTIO_CONFIG` points to a complete config path.
- Created files and parent directories receive the narrowest practical permissions. On Unix, secret-bearing state must be owner-only.

### 8.3 Resolution precedence

Highest precedence wins:

1. Explicit command flags.
2. Environment variables.
3. Selected profile.
4. Configured current profile.
5. Safe product defaults.

No tenant or production environment is inferred from an access token. If environment or tenant remains unresolved, the command fails before any network request.

Supported environment variables include:

```text
RELTIO_CONFIG
RELTIO_PROFILE
RELTIO_ENVIRONMENT
RELTIO_BASE_URL
RELTIO_TENANT
RELTIO_AUTH_URL
RELTIO_ACCESS_TOKEN
RELTIO_CLIENT_ID
RELTIO_CLIENT_SECRET
RELTIO_OUTPUT
RELTIO_TIMEOUT
RELTIO_CONFIRM_TENANT
```

`auth status` reports each resolved non-secret value and its source. Secret values are never printed; only presence, provider, and expiry metadata may be shown.

### 8.4 Service resolver

The client owns a typed service resolver rather than concatenating arbitrary strings in commands. It supports at least:

- authentication;
- tenant Data API and task API;
- physical tenant configuration;
- jobs/export;
- workflow;
- RDM;
- DTSS/data loader where public and supported;
- Reltio MCP endpoint;
- explicitly configured custom base URLs for private regions or future host conventions.

`doctor` prints the resolved URLs but never sends a mutating request. URL overrides must be profile-scoped or explicit so a global override cannot silently redirect unrelated services.

## 9. Authentication requirements

### 9.1 Credential-provider chain

The auth subsystem implements one common provider interface. Commands receive only a valid bearer token plus non-secret metadata; they never handle client secrets directly.

Supported providers for `v0.1.0`:

1. **Supplied bearer token** — `RELTIO_ACCESS_TOKEN`, secure stdin, or a one-shot invocation. It is never persisted unless the user explicitly imports it.
2. **Client credentials** — recommended for agents, CI, and machine-to-machine access. Client ID may live in the profile; client secret comes from OS keyring, environment, protected file, stdin, or an external process.
3. **Authorization code/SSO** — for user-delegated access. Supports browser launch with a loopback callback where the registered client permits it, plus a headless mode that prints the URL and accepts the returned code/callback safely. State is mandatory; PKCE is used where the Reltio/client configuration supports or requires it.
4. **Credential process** — runs a configured executable without a shell and accepts a strict JSON response containing `access_token`, optional `refresh_token`, `expires_at`, and optional metadata. This is the integration point for vaults, corporate brokers, cloud workload identity, and unsupported IdP variations.

Password grant and MFA state-token exchange are compatibility providers, not defaults. If implemented, passwords and OTPs are accepted only from a hidden prompt, stdin, keyring, or explicitly named environment variables. The CLI warns that client credentials or SSO should be preferred.

### 9.2 Secret storage

- Raw secrets never appear in the profile file by default.
- The OS credential store is preferred for interactive workstations.
- Headless environments use environment injection, credential processes, or protected files.
- Access and refresh tokens may be cached in an OS credential store or an owner-only cache according to profile policy.
- The CLI clearly reports when it falls back to a protected plaintext token cache because no credential store is available.
- Client secrets are not copied into diagnostic bundles, errors, shell completion, history, crash reports, or dry-run output.
- Values use secrecy/zeroization-aware types where practical. Redaction is defense in depth, not a reason to log secret-bearing objects.

### 9.3 Token caching and concurrency

- Cache tokens until their documented expiry rather than requesting one per command.
- Use a cross-process lock and single-flight refresh to prevent concurrent agents from creating a token storm.
- Account for clock skew, but do not assume that an early client-credentials request returns a fresh token when multi-token support is disabled.
- Refresh tokens when supported. Client credentials obtain a new token at expiry or after an explicit authentication rejection.
- A received `401` may trigger one refresh and one replay because the server explicitly rejected authorization. Ambiguous transport failures on mutations do not trigger automatic replay.
- Cache entries are keyed by auth host, client/user identity, grant/provider, and relevant scopes—not only by profile name.
- `auth logout` revokes a token where supported, clears cached material, and reports any SSO logout URL without opening it in non-interactive mode.

### 9.4 Auth commands

- `auth login` guides setup on a TTY and is deterministic with flags/stdin when non-interactive.
- `auth status` is offline and reports configuration source, provider, cache state, and known expiry.
- `auth check` performs a minimal non-mutating validation against the selected environment/tenant and distinguishes invalid token, missing roles, IP allowlist denial, wrong tenant, and network failure where the response permits.
- `auth token` prints a token only with an explicit `--show` acknowledgement and refuses when stdout is a TTY unless additionally confirmed. Its main use is controlled process integration.
- `auth logout` clears and optionally revokes credentials.
- Environment variables that override profile auth produce a visible warning on stderr and a metadata field in structured output.

## 10. Output and automation contract

### 10.1 Core stream rules

- Successful data is written to stdout.
- Errors, progress, warnings, prompts, and debug logs are written to stderr.
- Default success output is pretty-printed JSON, regardless of whether stdout is a TTY. This avoids behavior changes when agents allocate pseudo-terminals.
- `--output table` is the primary human-readable view.
- `--output raw` emits the unwrapped API body only where documented.
- `--output jsonl` emits one compact JSON object per line and is required for unbounded scans and event-like progress output.
- Color is used only for table/prose output on a TTY and never inside JSON.
- Commands never mix a final JSON document and JSONL events on the same stream.

### 10.2 Success envelope

Finite JSON commands use one stable envelope:

```json
{
  "schema_version": 1,
  "ok": true,
  "data": {},
  "meta": {
    "command": "entity.get",
    "cli_version": "0.1.0",
    "profile": "dev",
    "environment": "dev",
    "tenant": "ExampleTenant",
    "service": "data",
    "request_id": null,
    "elapsed_ms": 127,
    "pagination": null,
    "warnings": []
  }
}
```

API payloads stay under `data` without lossy remodeling unless a command explicitly documents a normalized model. `meta` fields may be added compatibly, but existing fields are not renamed or repurposed before the next major version.

JSONL scans emit records shaped as:

```json
{"schema_version":1,"type":"item","data":{},"meta":{"sequence":1,"cursor":null}}
{"schema_version":1,"type":"checkpoint","data":null,"meta":{"sequence":1000,"cursor":"...","returned":1000}}
{"schema_version":1,"type":"summary","data":null,"meta":{"returned":1204,"exhausted":true,"elapsed_ms":6421}}
```

Checkpoint events allow an agent to persist a safe resume point. A broken stream does not emit a false success summary.

### 10.3 Error envelope

Errors are compact JSON on stderr by default when the selected output is structured:

```json
{
  "schema_version": 1,
  "ok": false,
  "error": {
    "code": "auth_insufficient_permissions",
    "category": "authentication",
    "message": "The token is valid but cannot read entities in tenant ExampleTenant.",
    "retryable": false,
    "http_status": 403,
    "request_id": "example-request-id",
    "details": {},
    "hint": "Check tenant roles or select a different profile.",
    "suggested_commands": [
      "reltio --profile dev auth check",
      "reltio --profile dev auth status"
    ],
    "docs_url": "https://github.com/aiadjacent/reltio-cli/blob/main/docs/errors.md"
  }
}
```

Requirements:

- Error codes are stable, lowercase `snake_case` identifiers.
- `retryable` reflects CLI policy, not merely HTTP status.
- Reltio response bodies are preserved under `details` only after size limits and secret/PII-aware redaction.
- HTML proxy errors and non-JSON bodies become bounded text diagnostics rather than parser failures.
- Batch commands report per-item failures and use a partial-failure exit status.
- Human-readable error mode remains available with `--output table` or an explicit error-format setting.

### 10.4 Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Complete success. |
| `1` | Unclassified runtime or API failure. |
| `2` | Invalid CLI usage, input, or local validation failure. |
| `3` | Profile, authentication, credential, or target-resolution failure. |
| `4` | Requested resource not found. |
| `5` | Conflict, precondition failure, or refused safety policy. |
| `6` | Partial failure in a batch or multi-step operation. |
| `7` | Timeout while the remote operation may still be running. |
| `8` | Operation canceled locally or remotely. |

Signal-derived process codes remain platform-standard. `task wait` timing out never implies that the remote task was canceled.

### 10.5 Command discovery for agents

- `reltio agent guide` prints a concise version-matched overview of command selection, output, auth, safety, and common recovery paths.
- `reltio skills list/get/path` exposes embedded Markdown skills such as `reltio-usage`, `reltio-auth`, `reltio-data`, `reltio-config`, and `reltio-operations`.
- `reltio command schema [command]` emits JSON metadata for arguments, types, requirements, safety tier, accepted input formats, output shape, and examples.
- Help examples are tested in CI so the embedded agent instructions cannot silently drift from the CLI.
- The repository root `AGENTS.md` is the standing instruction for implementing agents.

### 10.6 Compatibility policy

- `schema_version` identifies the CLI envelope/event schema independently of the Reltio response body and CLI package version.
- `--output raw` follows Reltio's upstream response and receives no CLI schema compatibility guarantee.
- During `v0.x`, an unavoidable breaking command or structured-output change requires a minor-version release, a migration note, and a deprecation window where practical.
- Beginning with `v1.0.0`, existing commands, exit-code meanings, error codes, and schema fields change incompatibly only in a new major version.
- New optional object fields, new commands, new enum/error values, and additional metadata are compatible additions; consumers must ignore unknown fields and handle unknown upstream task states.
- Deprecated commands emit a stderr warning and a structured `meta.warnings` entry while continuing to keep stdout parseable.
- Embedded skills and `command schema` always document the contract of the installed binary, not the latest unreleased documentation.

## 11. Pagination, streaming, and asynchronous work

### 11.1 Pagination

- Typed commands normalize page metadata without hiding the underlying cursor or offset.
- `search` returns one page by default and includes how to request the next page.
- `scan` iterates a cursor and streams JSONL by default; it never buffers an unbounded tenant result in memory.
- First-scan filters are validated locally where possible and otherwise fail with the original Reltio diagnostic.
- `--max-items`, `--page-size`, and `--max-pages` bound agent work independently.
- A resume file includes endpoint, profile identity, tenant, normalized filter hash, page size, cursor, sequence, and CLI version. A mismatched resume attempt fails instead of silently changing the query.
- Cursor values are secrets only if Reltio treats them that way; regardless, they are excluded from ordinary verbose logs and included in checkpoint output only when needed for resume.

### 11.2 Task waiting

- `task wait` accepts a typed service/task reference or a task URL returned by another command.
- Poll intervals use bounded exponential backoff with jitter and honor server hints where available.
- Known states normalize to `queued`, `running`, `paused`, `succeeded`, `failed`, `canceled`, and `unknown`, while preserving the original Reltio state.
- Unknown states do not become success. They are polled until timeout unless the user supplies an explicit terminal-state override.
- Progress goes to stderr. The terminal task document is the only stdout result.
- Ctrl-C stops local polling and leaves the remote task running. A second explicit command is required to cancel it.
- Start commands can offer `--wait` as a convenience, implemented through the same task waiter.

### 11.3 Retry policy

Safe automatic retries apply only to:

- connection setup failures before a request is sent;
- idempotent `GET`/`HEAD` operations;
- documented idempotent requests;
- `408`, `429`, and selected `5xx` responses when method safety and endpoint semantics allow it;
- one explicit `401` refresh/replay cycle.

Retries honor `Retry-After`, use exponential backoff with jitter, and have both attempt and elapsed-time budgets. Creates, merges, unmerges, deletes, configuration applies, and other ambiguous mutations are not retried after a transport timeout unless Reltio provides a verified idempotency mechanism or the user explicitly chooses an unsafe retry mode.

## 12. Core resource requirements

### 12.1 Entities

- Accept entity IDs and canonical `entities/<id>` URIs consistently.
- Support retrieval by URI, URI batch, and crosswalk.
- Preserve Reltio query options such as operational-value, hidden-attribute, and field-selection controls through typed flags or a documented repeatable query option.
- Distinguish indexed `search` from cursor `scan` and explain consistency implications.
- Accept create/upsert arrays without assuming that one input produces one independent unmerged profile.
- Require an explicit update mode where Reltio semantics differ, including `partial-override` versus full/source replacement. No ambiguous generic `patch` command is introduced.
- Report returned object URIs, crosswalks, status, and per-record failures in a stable batch result.
- Delete requires confirmation and reports the exact URI and tenant.
- History and potential matches are read-only in the MVP.
- Typed merge/unmerge commands are added only after tests cover contributor trees, winner/loser behavior, retries, and confirmation semantics.

### 12.2 Relations

- Accept canonical relation URIs and preserve start/end objects, direction, type, attributes, tags, and crosswalks without lossy normalization.
- Support offset search and cursor scan as distinct commands when the underlying endpoints differ.
- Validate obvious start/end object formatting before a create request.
- Update commands require an explicit mode when partial-override semantics affect nested or referenced values.
- Delete is safety-tiered and reports affected relation URI, endpoints, profile, and tenant.

### 12.3 Business configuration

Configuration is a high-risk workflow and receives purpose-built behavior:

- `config get` can retrieve effective/inherited configuration for inspection.
- `config pull --out <file>` retrieves editable tenant L3/no-inheritance configuration by default.
- `pull` writes a sidecar manifest containing tenant, environment, retrieval time, layer, CLI version, source hash, and non-secret request metadata.
- `config diff` compares canonicalized JSON semantically while preserving array-order significance where the Reltio schema requires it.
- `config validate` performs local structural checks and the Reltio tenant validation call.
- `config apply` refuses an artifact marked as effective/inherited.
- `apply` verifies the sidecar target, fetches the current L3, creates a timestamped local backup, calculates a fresh diff, validates the candidate, then requests confirmation.
- A changed remote source hash causes a conflict unless the user intentionally rebases or uses an explicitly named force option.
- Production apply requires exact tenant confirmation.
- Full-configuration replacement and granular sub-resource operations share the same validation, backup, target, and audit metadata pipeline.
- Secrets or environment-specific values identified by policy are redacted from diffs and backups where doing so does not make the artifact invalid; otherwise the CLI warns and secures the files.

### 12.4 Raw API request

Proposed shape:

```bash
reltio api request <METHOD> <PATH> \
  --service <data|tasks|physical-config|jobs|workflow|rdm|dtss|mcp|auth> \
  --query key=value \
  --header 'Name: value' \
  --data @body.json
```

Requirements:

- Resolves relative paths only against a named known service.
- Rejects embedded credentials in URLs.
- Adds the selected bearer token automatically.
- Rejects user attempts to override `Authorization`, `Host`, or other protected headers unless a specifically named unsafe flag is provided.
- Absolute URLs are limited to configured Reltio hosts by default. Cross-host redirects do not forward authorization.
- Applies the same timeout, TLS, proxy, redaction, output, request ID, and safe-retry policies as typed commands.
- Mutating methods participate in dry-run and safety confirmation.
- Does not guess pagination or task semantics unless an endpoint adapter is explicitly selected.
- Can include sanitized response headers on request.

## 13. Safety model

### 13.1 Safety tiers

| Tier | Examples | Default behavior |
| --- | --- | --- |
| Read | Get, search, scan, status, diff | Execute after local validation. |
| Write | Create, explicit partial update | TTY confirmation according to profile policy; `--yes` for non-interactive use. |
| High impact | Delete, merge, unmerge, task cancel, full config apply | Exact target summary and explicit acknowledgement. Production also requires `--confirm-tenant`. |
| Administrative | User/client/role changes, bulk destructive jobs | Deferred until an operation-specific threat and recovery model exists. |

### 13.2 Dry run

`--dry-run` must:

- resolve profile, tenant, service, auth provider, and endpoint;
- parse and validate input;
- show the method, sanitized URL, query, body hash/summary, safety tier, and planned retry policy;
- perform no mutation;
- avoid claiming server-side validity unless a documented validation endpoint was called;
- identify any read-only preflight calls it did make.

### 13.3 Production and non-interactive behavior

- Profiles can be explicitly marked `production = true`; the CLI never infers production solely from a hostname substring.
- High-impact production operations require both `--yes` and `--confirm-tenant <exact-id>` in non-interactive mode.
- TTY prompts display profile, environment, tenant, operation, resource count, and recoverability.
- Prompts fail closed when stdin is not a TTY. An agent receives a structured safety error with the exact required flag.
- `--yes` never means "select all" and never disables input validation, target checks, or tenant confirmation.
- Batch expansion limits are shown before execution and can be capped by policy.

### 13.4 Auditability

Every mutation result includes, where available:

- client-generated operation ID;
- Reltio request/correlation ID;
- command and CLI version;
- profile, environment, tenant, and service;
- authenticated principal/client identifier when available without exposing secrets;
- input file hash or canonical body hash;
- affected resource URIs/count;
- start/end timestamps and result;
- backup or task reference.

The CLI does not create a hidden remote audit store. Users can redirect structured results to their own approved system.

## 14. Reliability, performance, and diagnostics

### 14.1 Timeouts and resource limits

- Every network request has connect, idle/read, and overall deadlines.
- Defaults are command-class specific and documented.
- Scans and downloads stream with bounded memory.
- Concurrent batch operations have a conservative default limit and an explicit maximum.
- Request bodies over a threshold stream from disk rather than being duplicated in memory.
- Response sizes, item limits, and task wait deadlines can be bounded independently.

### 14.2 Consistency awareness

- Direct object reads and indexed search are labeled in command metadata as `consistent`, `eventual`, or `unknown` based on a maintained endpoint registry.
- Mutation success never promises immediate search visibility.
- Errors and docs recommend direct URI reads for read-after-write verification where appropriate.
- A future `--wait-visible` helper may poll an indexed view with a deadline, but it must not be part of write success itself.

### 14.3 Diagnostics

`doctor` performs safe checks:

- config parse and permissions;
- selected profile and resolution sources;
- service URL construction;
- credential provider availability and cache health;
- token validity/expiry without printing it;
- DNS/TLS/connectivity when online checks are enabled;
- a minimal tenant read that can separate invalid auth, insufficient role, wrong tenant, IP allowlist, proxy, TLS, and service outage where possible;
- clock-skew warnings;
- current CLI version and update channel.

Verbose and trace modes scrub:

- authorization and cookie headers;
- client secrets, access tokens, refresh tokens, passwords, OTPs, state tokens, codes, and signed URLs;
- configured sensitive query/body keys;
- large Reltio payloads by default.

No debug mode can disable core secret redaction.

## 15. Technical architecture

### 15.1 Proposed Rust workspace

```text
reltio-cli/
├── Cargo.toml                 # workspace
├── crates/
│   ├── reltio-client/        # reusable auth, routing, HTTP, models, pagination
│   └── reltio-cli/           # clap interface, renderers, prompts, skills
├── skills/                   # embedded agent guidance
├── docs/
├── tests/fixtures/
└── .github/workflows/
```

`reltio-client` is a real library boundary, not a promise of a separately stable SDK in `v0.x`. Its modules should include:

- `auth`: provider trait, token models, cache, refresh, revocation;
- `config`: profile models, precedence, secure locations;
- `service`: URL and endpoint routing;
- `http`: request policy, middleware, retry, redaction, correlation;
- `entities`, `relations`, `configuration`, `tasks`: typed service clients;
- `pagination`: cursor and offset primitives;
- `error`: structured error taxonomy;
- `models`: minimally modeled stable fields plus lossless `serde_json::Value` for evolving payloads.

The CLI crate owns:

- command parsing and validation;
- interactive auth and confirmation;
- input readers and output renderers;
- progress reporting;
- embedded skills and command schemas;
- process exit-code mapping.

### 15.2 Dependency direction

Use mature Rust crates for CLI parsing, async HTTP with rustls, serialization, errors, tracing, protected secrets, platform directories, credential storage, file locking, and terminal prompts. Exact crates and versions are implementation decisions verified at implementation time.

Requirements:

- default TLS must not require a system OpenSSL installation;
- TLS verification is never disabled by a general convenience flag;
- proxy behavior follows standard environment conventions with redaction;
- the auth and HTTP layers are injectable for deterministic tests;
- command modules do not instantiate their own HTTP clients;
- no unsafe Rust without an approved design note and targeted tests.

### 15.3 Modeling strategy

Reltio payloads are large, tenant-configured, and evolving. Over-modeling every entity attribute would make the client brittle; treating everything as untyped JSON would make auth, tasks, pagination, and errors unsafe.

Use a hybrid model:

- strongly type stable protocol fields such as token responses, pagination, task identity/status, errors, object URI/type, crosswalk identity, and configuration artifact metadata;
- retain unknown fields with flattening or lossless JSON;
- keep tenant-defined `attributes` lossless;
- use builders or typed command inputs for dangerous operations;
- fixture-test round-trip preservation for representative complex entities and relations.

### 15.4 Endpoint registry

Maintain a versioned registry for typed operations containing:

- service family and path template;
- HTTP method;
- consistency classification;
- idempotency/retry classification;
- safety tier;
- pagination type;
- expected task reference behavior;
- relevant Reltio documentation URL;
- date last verified.

This registry drives command metadata, help, retry policy, and coverage reporting. It is not generated blindly from documentation.

## 16. Testing and quality requirements

### 16.1 Test layers

- Unit tests for config precedence, URL construction, duration parsing, redaction, exit mapping, state normalization, and retry classification.
- Auth tests for every provider, expiry boundary, refresh, concurrent process cache behavior, malformed credential-process output, revocation, and secret non-disclosure.
- HTTP contract tests using a local mock server for headers, query encoding, bodies, pagination, retries, redirect safety, timeouts, and non-JSON errors.
- Golden tests for success/error JSON, JSONL events, tables, help text, and command schemas.
- Fixture round-trip tests for entities, relations, configuration, task states, and error bodies.
- CLI integration tests that execute the compiled binary with stdin/stdout/stderr and assert exit codes.
- Property/fuzz tests for filter/query encoding, redaction, URI normalization, and config parsing where they provide value.
- Optional live smoke tests against a dedicated non-production tenant, gated by secrets and never required for forks.
- Security tests proving that tokens do not appear in traces, panics, process arguments generated by the CLI, or snapshots.

### 16.2 Required CI gates

- Format check.
- Clippy with warnings denied for workspace code.
- Unit and integration tests on Linux, macOS, and Windows.
- Minimum supported Rust version check once selected.
- Dependency vulnerability and license policy checks.
- Documentation link and example verification.
- Agent-skill/CLI drift test.
- Release-build smoke test for every supported target.

### 16.3 MVP acceptance test scenarios

The release cannot be called `v0.1.0` until tests demonstrate:

1. A human can create a profile, complete client-credential or SSO login, and retrieve an entity without editing a config file.
2. A headless process can authenticate through environment variables or a credential process without a TTY or a secret CLI argument.
3. Twenty concurrent CLI processes share cached client-credential state without producing a token storm.
4. Expired tokens refresh correctly and a single explicit `401` is replayed at most once.
5. Entity and relation scans stream multiple cursor pages without loading the full result into memory and emit resumable checkpoints.
6. A transport timeout during an entity create does not cause an automatic duplicate write.
7. Structured stdout remains valid when progress, warnings, and retries occur.
8. Every documented exit condition maps to the expected stable exit code and error envelope.
9. Configuration apply rejects inherited/effective configuration, target mismatch, stale source hash, failed validation, and missing production confirmation.
10. Trace output contains no test tokens, secrets, passwords, OTPs, authorization codes, or sensitive headers.
11. `api request` cannot leak authorization through a cross-host redirect or protected-header override.
12. Agent skills and command schemas use only commands and flags accepted by that exact binary version.

## 17. Distribution and release

### 17.1 Supported platforms

Initial release targets:

- Linux x86_64 and ARM64;
- macOS Intel and Apple Silicon;
- Windows x86_64.

### 17.2 Channels

- Signed GitHub Release archives with checksums.
- `cargo install reltio-cli` if crate naming and publication are approved.
- Homebrew tap and Scoop manifest after release automation is stable.
- Shell installer only after checksum verification and failure behavior are independently reviewed.
- Container image is optional for CI/headless use and must run rootless by default.

### 17.3 Supply chain

- Reproducible or provenance-attested release builds.
- Artifact signing and published checksums.
- SBOM per release by `v1.0.0`, preferably earlier.
- Pinned CI actions and least-privilege release permissions.
- Automated dependency review without automatic unreviewed major upgrades.
- License recommendation: dual `MIT OR Apache-2.0`, subject to repository-owner approval before the first public package release.

## 18. Documentation requirements

The repository and binary must ship:

- a five-minute quickstart;
- profile and auth guide with a provider decision table;
- command reference generated from the binary where practical;
- output and compatibility contract;
- structured error reference;
- safety and production operations guide;
- entity, relation, configuration, task, and raw-request workflow guides;
- troubleshooting/`doctor` guide;
- public API coverage matrix with verified documentation links and dates;
- security policy and vulnerability reporting path;
- contributing and release guides;
- embedded agent skills sourced from the same maintained documentation.

The README should describe the product as independent/unofficial unless Reltio explicitly authorizes different branding.

## 19. Success criteria

Because telemetry is off by default, early success is measured through tests, pilot sessions, issue feedback, and release health rather than hidden usage collection.

### 19.1 MVP product outcomes

- A new user completes a first authenticated entity read in under five minutes using only the quickstart and guided CLI.
- A prepared headless agent completes profile selection, auth check, entity read, scan, and safe update with no prose parsing and no interactive input.
- Pilot users perform the top entity, relation, task, and configuration workflows without falling back to hand-written HTTP in at least 80% of cases.
- No known path writes a raw secret into default config, logs, shell history generated by the CLI, or structured output.
- All high-impact operations have tested wrong-tenant and non-interactive failure cases.
- Release artifacts install and execute `reltio --version`, `reltio --help`, and `reltio agent guide` on every supported platform.

### 19.2 Long-run outcomes

- Typed coverage grows according to observed workflows, while `api request` keeps new public endpoints reachable.
- Breaking automation changes occur only under the documented compatibility policy.
- Incident diagnosis starts with a structured error and request ID rather than packet-level debugging.
- Configuration changes are routinely validated, diffed, backed up, and target-checked through the CLI.
- The CLI is trusted enough for production use by both operators and supervised agents.

## 20. Risks and mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Reltio API breadth causes an incoherent command tree | Poor discoverability and unstable naming | Domain-based hierarchy, command vocabulary rules, coverage registry, raw escape hatch. |
| Reltio documentation or behavior changes | Incorrect requests or unsafe retry assumptions | Record verification dates, fixture/contract tests, live non-prod smoke tests, conservative unknown behavior. |
| Auth permutations expand without bound | Delayed release and fragile login | Provider interface, credential-process escape hatch, recommended paths first, compatibility flows based on validated need. |
| Token caching leaks secrets | Security incident | Keyring preference, owner-only fallback, strict redaction, threat model, secret-focused tests. |
| Multiple agents refresh simultaneously | Token limits and failures | Cross-process lock, keyed cache, single-flight refresh, token reuse. |
| Automatic retry duplicates writes | Data corruption | Method/endpoint retry registry, no ambiguous mutation replay, explicit unsafe override only. |
| A user applies effective configuration as L3 | Tenant configuration damage | Artifact layer metadata, refusal rules, remote validation, diff, backup, stale-hash check, confirmation. |
| JSON wrappers make direct API use awkward | Users bypass typed commands | Stable envelope plus `--output raw`; preserve API body losslessly. |
| Default table output changes under a pseudo-TTY | Agent parsing failure | JSON is default independent of TTY. |
| Agent documentation drifts | Invalid autonomous commands | Embed version-matched skills and test all examples against command metadata. |
| Official MCP overlaps with CLI | Duplicated effort | Position CLI around process/shell/config-as-code workflows; defer MCP server; integrate metadata only where useful. |
| No live tenant in public CI | Missed contract drift | Strong mock/fixture suite plus optional scheduled smoke tenant owned by maintainers. |

## 21. Product decisions

The following are decisions for the initial implementation unless explicitly revised:

1. The executable is `reltio`.
2. JSON is the default output even on a TTY.
3. Errors are structured by default when output is structured.
4. Profile selection never infers a tenant from the token.
5. Client credentials, SSO authorization code, supplied bearer, and credential process are the primary auth methods.
6. Password/MFA is a compatibility path, not the recommended path or an MVP blocker.
7. Raw public API access ships in the MVP with host and header restrictions.
8. The MVP provides typed entity, relation, configuration, and task commands.
9. Update mode is explicit when Reltio semantics could replace or preserve different source-owned values.
10. Configuration pull defaults to editable tenant L3/no-inheritance, not effective configuration.
11. High-impact production operations require exact tenant confirmation.
12. Automatic retries are conservative and never replay an ambiguous mutation by default.
13. Scans stream JSONL and expose resumable checkpoints.
14. Agent skills are embedded and version-matched.
15. An MCP server is out of scope for the initial release.
16. Product telemetry is disabled by default.

## 22. Open questions requiring owner or pilot validation

These questions do not block repository scaffolding, auth/client abstractions, or read-only MVP work. They should be resolved before the affected feature is declared stable.

1. Which real Reltio namespaces, private regions, proxy patterns, and SSO providers must be included in the pilot matrix?
2. Can pilot customers register a loopback redirect URI for CLI authorization-code login, or must the first SSO implementation emphasize headless code paste/credential process?
3. Is OS keyring plus owner-only file cache an acceptable default, or must all persistent token caching be keyring-only in managed environments?
4. Which entity update modes are most common in target tenants, and what exact terminology will users recognize for full override, partial override, and crosswalk-owned updates?
5. Which load/export service variants and cloud-storage providers are required first?
6. Which task services share compatible status payloads, and which need dedicated adapters?
7. Should a production profile require exact-tenant confirmation for every mutation or only high-impact operations?
8. Is dual `MIT OR Apache-2.0` licensing approved?
9. Is crates.io publication desired, and is `reltio-cli` available/appropriate as the package name?
10. What non-production tenant and synthetic dataset can maintainers use for scheduled contract tests?
11. Should token-efficient structured output be added, and if so which format has a stable enough ecosystem to become a product contract?
12. Which first five typed API families after the MVP produce the highest operational value?

## 23. Implementation sequence

The implementation should proceed in vertical slices that remain releasable:

1. Establish workspace, quality gates, error taxonomy, output envelope, config locations, and command metadata.
2. Implement profiles, service resolver, supplied bearer auth, and `doctor` offline checks.
3. Implement client credentials, secure cache, cross-process locking, auth status/check/logout, and redaction tests.
4. Implement `api request` for read-only methods, then add mutation safety and dry run.
5. Implement entity get/search/scan end to end, including cursor checkpoints and consistency metadata.
6. Add entity writes with explicit modes and conservative retry behavior.
7. Add relation read/write/scan commands using shared pagination and safety primitives.
8. Implement authorization-code/SSO and credential-process providers with integration tests.
9. Implement configuration artifact, diff, validation, backup, stale-hash, and guarded apply workflow.
10. Implement task adapters and wait behavior.
11. Embed skills, generate command schemas/completions, write docs, and run pilot acceptance scenarios.
12. Complete cross-platform packaging, security review, and `v0.1.0` release assessment.

Each slice includes tests, user documentation, agent guidance, error cases, and final verification. Features are not complete when only the happy-path HTTP call works.

## 24. Source references

Research was reviewed on 2026-08-08. Links are included to preserve the assumptions behind the design; implementation agents must re-verify details that can change.

### Reltio

- [Developer resources](https://docs.reltio.com/en/developer-resources)
- [Get started with Reltio REST APIs and service URLs](https://docs.reltio.com/en/developer-resources/about-developer-resources/developer-resources-at-a-glance/reltio-rest-apis-at-a-glance/get-started-with-reltio-rest-apis)
- [Consistency of data retrieval in Reltio APIs](https://docs.reltio.com/en/developer-resources/about-developer-resources/developer-resources-at-a-glance/reltio-rest-apis-at-a-glance/consistency-of-data-retrieval-in-reltio-apis)
- [Authentication API](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/authentication-api)
- [Access Reltio APIs](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/authentication-api/access-reltio-apis)
- [Obtain a token with client credentials](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/authentication-api/obtaining-access-tokens-with-client-credentials-grant-type)
- [Obtain an access token for SSO users](https://docs.reltio.com/en/objectives/administer-system/system-administration-at-a-glance/access-management-at-a-glance/access-management-operation/authentication/authenticate-with-sso/sso-configuration/obtain-an-access-token-for-sso-users)
- [Get access token with MFA](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/authentication-api/access-token-authentication/get-access-token-with-mfa)
- [Multi Token Support](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/authentication-api/multi-token-support)
- [Entities API](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/entities-api)
- [Entity cursor scan](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/entities-api/get-entity/search-entity-with-cursor)
- [Relations API](https://docs.reltio.com/en/developer-resources/relation-management-apis/relation-management-apis-at-a-glance/relations-api)
- [Relation cursor scan](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/entities-api/get-entity/search-relations-using-pagination)
- [Potential matches API](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/potential-matches-api)
- [Verifying matches](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/potential-matches-api/verifying-matches)
- [Merge and unmerge Entities API](https://docs.reltio.com/en/developer-resources/entity-management-apis/entity-management-apis-at-a-glance/merge-and-unmerge-entities-api)
- [Configuration API](https://docs.reltio.com/en/developer-resources/system-administration-apis/system-administration-apis-at-a-glance/configuration-api)
- [Load and Export APIs](https://docs.reltio.com/en/developer-resources/load-and-export-apis/load-and-export-apis-at-a-glance)
- [Export task statuses](https://docs.reltio.com/en/developer-resources/load-and-export-apis/load-and-export-apis-at-a-glance/export-service-apis/export-tasks-management-api/status-of-an-export-task)
- [Reltio MCP Server](https://docs.reltio.com/en/developer-resources/ai-integrations/reltio-model-context-protocol-mcp-server-at-a-glance)
- [AgentFlow MCP authentication flow](https://docs.reltio.com/en/developer-resources/ai-integrations/reltio-model-context-protocol-mcp-server-at-a-glance/authentication-flow-for-the-agentflow-mcp-server)

### Inspiration

- [Microck/kagi-cli](https://github.com/Microck/kagi-cli)
- [Kagi CLI output contract](https://github.com/Microck/kagi-cli/blob/main/docs/reference/output-contract.mdx)
- [Kagi CLI auth matrix](https://github.com/Microck/kagi-cli/blob/main/docs/reference/auth-matrix.mdx)

## 25. Direction for implementing agents

The repository-level instructions in `AGENTS.md` are mandatory for implementation work. The PRD is intentionally a planning artifact; creating it does not authorize implementation beyond the planning and repository-guidance files committed with it.
