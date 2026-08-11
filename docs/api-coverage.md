# API Coverage

Reviewed on 2026-08-10 against official English documentation, release notes through `2026.1.8.0`, current deprecation notices, and AI-ready corpus commit `1c290ec16beb53b7754c0aa3195e9918d0d41ef6`.

| Operation | Service | Method and path | Safety | Consistency | Coverage |
| --- | --- | --- | --- | --- | --- |
| Client credentials | Auth | `POST /oauth/token` | Authentication | N/A | Reviewed |
| Entity get | Data | `GET /entities/{id}` | Read | Consistent | Reviewed, including exact top-level selections, tenant attribute paths, the eight documented response options, historical time, duplicate-crosswalk handling, value limits, explicit survivorship groups, reverse transcoding, and masking |
| Entity search | Data | `POST /entities/_search` | Read-semantic POST | Eventual | Reviewed |
| Raw entity search | Data | `GET /entities` or `GET /entities/_search` | Read | Eventual | Reviewed with POST recommendation |
| Entity scan | Data | `POST /entities/_scan` | Read-semantic POST | Eventual | Reviewed |

The raw request command does not count as typed coverage. It matches method, service, and relative path against the same registry:

- Exact reviewed matches apply endpoint limits, replay classification, and practice IDs. Malformed values for known reviewed parameters are rejected rather than relabeled as partial coverage; only genuinely unknown parameters cause a partial match.
- Catalog rules still match method, service, and path when an endpoint is not fully registered or an exact endpoint uses unreviewed parameters. Such reads report `practice_coverage: partial`, enforce every matched guard, and retain conservative no-retry behavior.
- Reads with no endpoint-specific catalog match proceed with `practice_coverage: unknown`, a warning, and no automatic retries.
- Unmatched mutations fail without a dedicated unreviewed-endpoint acknowledgement and normal tenant confirmations.

## Machine Sources

- `docs/endpoints.yaml`: protocol and safety classification.
- `docs/reltio-api-practices.yaml`: authoritative source, interpretation, enforcement, and review date.
- `docs/test-evidence.yaml`: build-validated mapping from every referenced test ID to an actual test function.
- `docs/upstream.lock.yaml`: reviewed corpus, release-note position, and deprecation-notice sitemap URL-set fingerprint.

`reltio api practices check --strict` validates registry joins, checks that the catalog matches `docs/upstream.lock.yaml`, emits endpoint-level practice/test coverage, and enforces the 14-day release freshness rule. The client build fails if an endpoint references an unknown practice, an implementation path is missing, a practice lacks tests/rationale, or test evidence does not point to an attributed test function. CLI tests additionally require exact equality between executable command leaves and command metadata, parse every embedded example, and join command schemas to endpoint practices.

`reverseTranscodeLookups` remains caller-selected and emits an availability warning in structured metadata and on stderr for raw/table output. Reltio's introduction note classified it as Preview, while the current Get Entity reference documents the parameter without a later GA notice in the reviewed corpus.

Replay-safe `429`, `502`, `503`, and `504` handling is exercised through complete response processing and exact attempt ceilings. Oversized diagnostic bodies cannot suppress a qualified retry or replace the terminal status-specific error.

The token endpoint's separate policy receives one attempt except for one bounded `429` replay. Oversized `429` bodies cannot suppress that replay; they are omitted under a deny-all originating output guard, and repeated rate limiting remains `auth_rate_limited` rather than a local size error.

Get Entity accepts the documented lowercase top-level selections `uri`, `type`, `tags`, `createdBy`, `createdTime`, `updatedBy`, `updatedTime`, `isFavorite`, `analyticsAttributes`, `label`, `secondaryLabel`, `crosswalks`, and `attributes`, plus nonempty tenant-defined `attributes.<path>` selections. Its reviewed `options` values are `sendHidden`, `ovOnly`, `nonOvOnly`, `serializeInitialSourcesInCrosswalks`, `cleanEntity`, `showAppliedSurvivorshipRules`, `showEndDatedReferenceAttributes`, and `explainOv`. Options documented only for search are not accepted by Get Entity.

Typed POST search, raw GET/POST search, and first-page scan reject entity filters over Reltio's documented 256-character processed limit rather than accept silent truncation. Typed and reviewed raw GET/POST searches derive the 10,000-result boundary warning from the actual full response page; structured formats retain metadata while raw/table output receives guarded stderr narration. Entity scan consumes its eventual-consistency classification and conservative preserved-cursor TTL directly from the endpoint registry. Evidence covers multi-page termination, coherent cursor/sequence state, normalized context, exact CLI-version identity, resolved service-route identity, cursor-expiry deadlines across authentication and retries, and output-before-checkpoint commit ordering. `auth check` and online `doctor` expose reviewed Entity Search metadata; an unhealthy `doctor` returns a nonzero guarded diagnostic rather than a successful envelope.

Typed entity writes, relations, business configuration, tasks, SSO, and later families remain planned in the [product contract](PRD.md). They must not be described as reviewed or production-supported until their registry, safeguards, documentation, and tests land together.
