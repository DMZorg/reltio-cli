# API Coverage

Reviewed on 2026-08-11 against the live Data Operation OpenAPI, official English documentation, release notes through `2026.1.8.0`, current deprecation notices, and AI-ready corpus commit `1c290ec16beb53b7754c0aa3195e9918d0d41ef6`.

| Operation | Service | Method and path | Safety | Consistency | Coverage |
| --- | --- | --- | --- | --- | --- |
| Client credentials | Auth | `POST /oauth/token` | Authentication | N/A | Reviewed |
| Entity get | Data | `GET /entities/{id}` | Read | Consistent | Reviewed, including exact top-level selections, tenant attribute paths, the eight documented response options, historical time, duplicate-crosswalk handling, value limits, explicit survivorship groups, reverse transcoding, and masking |
| Entity get by crosswalk | Data | `GET /entities/_byCrosswalk/{crosswalkValue}` | Read | Consistent | Reviewed for simple path values, required `type`, optional `sourceTable`, and the `sendHidden`, `ovOnly`, and `nonOvOnly` option intersection |
| Entity search | Data | `POST /entities/_search` | Read-semantic POST | Eventual | Reviewed |
| Raw entity search | Data | `GET /entities` or `GET /entities/_search` | Read | Eventual | Reviewed with POST recommendation |
| Entity scan | Data | `POST /entities/_scan` | Read-semantic POST | Eventual | Reviewed |
| Entity history | Data | `GET /entities/{id}/_changes` | Read | Unknown | Reviewed with explicit ordering and a conservative 1,000-event offset boundary |
| Entity potential matches | Data | `GET /entities/{id}/_matches` | Read | Unknown/freshness conditional | Reviewed for stored direct matches without forced recalculation |

The raw request command does not count as typed coverage. It matches method, service, and relative path against the same registry:

- Exact reviewed matches apply endpoint limits, replay classification, and practice IDs. Malformed reviewed values are rejected; syntactically valid but unreviewed variants and unknown parameters downgrade coverage or are hard-refused when their safety semantics are unresolved.
- Catalog rules still match method, service, and path when an endpoint is not fully registered or an exact endpoint uses unreviewed parameters. Such reads report `practice_coverage: partial`, enforce every matched guard, and retain conservative no-retry behavior.
- Reads with no endpoint-specific catalog match proceed with `practice_coverage: unknown`, a warning, and no automatic retries.
- Mutation dry runs require the dedicated unreviewed-endpoint acknowledgement and normal tenant confirmations. Actual raw mutations fail closed with `mutation_audit_unavailable` until `mutation_audit_v1` has implementation evidence.

## Machine Sources

- `docs/endpoints.yaml`: schema-v2 protocol, safety, and role-aware command ownership classification.
- `docs/reltio-api-practices.yaml`: authoritative source, interpretation, enforcement, and review date.
- `docs/test-evidence.yaml`: build-validated mapping from every referenced test ID to an actual test function.
- `docs/release-requirements.yaml`: PRD-digest-bound inventory of all 50 `v0.1.0` command leaves, exact endpoint bindings, required capabilities, all 19 MVP acceptance scenarios, and per-field/per-result mutation audit evidence.
- `docs/upstream.lock.yaml`: reviewed corpus, release-note position, deprecation fingerprints, and reproducible OpenAPI URL/response metadata/content digest.

`reltio api practices check --strict` validates registry joins, checks that the catalog matches `docs/upstream.lock.yaml`, emits endpoint-level practice/test coverage plus current release blockers, and enforces the 14-day review freshness rule. `--release-ready` additionally exits nonzero unless every PRD-required command, capability, approved endpoint ID/role, MVP acceptance scenario, and acceptance contract is complete. The client build binds the manifest to the exact LF-normalized `docs/PRD.md` digest and compares it with independent compiled sets for the 50 operations, every operation safety tier, endpoint obligations/current bindings, SSO capability, 19 scenarios, and exact mutation-audit fields/results. Unknown manifest fields, substituted operations, reused refusal evidence, safety mismatches, mutation requirements without `mutation_audit_v1`, missing guard evidence, inapplicable practices, and unattributed tests fail the build. CLI tests additionally require exact equality between executable command leaves and command metadata, parse every embedded example, and prove that auth/raw dependencies cannot count as typed endpoint ownership. Stable-tag CI executes the complete attributed test suite and passes the tag through `--expected-release`, which must equal both the manifest target and package version. This is a product-MVP gate, not a substitute for the PRD's platform, packaging, signing, provenance, and pilot gates.

`reverseTranscodeLookups` remains caller-selected and emits an availability warning in structured metadata and on stderr for raw/table output. Reltio's introduction note classified it as Preview, while the current Get Entity reference documents the parameter without a later GA notice in the reviewed corpus.

Replay-safe `429`, `502`, `503`, and `504` handling is exercised through complete response processing and exact attempt ceilings. Oversized diagnostic bodies cannot suppress a qualified retry or replace the terminal status-specific error.

The token endpoint's separate policy receives one attempt except for one bounded `429` replay. Oversized `429` bodies cannot suppress that replay; they are omitted under a deny-all originating output guard, and repeated rate limiting remains `auth_rate_limited` rather than a local size error.

Get Entity accepts the documented lowercase top-level selections `uri`, `type`, `tags`, `createdBy`, `createdTime`, `updatedBy`, `updatedTime`, `isFavorite`, `analyticsAttributes`, `label`, `secondaryLabel`, `crosswalks`, and `attributes`, plus nonempty tenant-defined `attributes.<path>` selections. Its reviewed `options` values are `sendHidden`, `ovOnly`, `nonOvOnly`, `serializeInitialSourcesInCrosswalks`, `cleanEntity`, `showAppliedSurvivorshipRules`, `showEndDatedReferenceAttributes`, and `explainOv`. Options documented only for search are not accepted by Get Entity.

Typed POST search, raw GET/POST search, and first-page scan reject entity filters over Reltio's documented 256-character processed limit rather than accept silent truncation. Typed and reviewed raw GET/POST searches derive the 10,000-result boundary warning from the actual full response page; structured formats retain metadata while raw/table output receives guarded stderr narration. Entity scan consumes its eventual-consistency classification and conservative preserved-cursor TTL directly from the endpoint registry. Evidence covers multi-page termination, coherent cursor/sequence state, normalized context, exact CLI-version identity, resolved service-route identity, cursor-expiry deadlines across authentication and retries, and output-before-checkpoint commit ordering. `auth check` and online `doctor` expose reviewed Entity Search metadata; an unhealthy `doctor` returns a nonzero guarded diagnostic rather than a successful envelope.

Get by crosswalk preserves Reltio's `ObjectEntryEntityTO` wrapper array. The CLI conservatively rejects values outside the RFC 3986 unreserved set because Reltio directs special-character values to `POST /entities/_byCrosswalk` without defining the exact set; that POST variant and options not shared by the current reference and OpenAPI remain deferred. A successful response object without the requested crosswalk tuple receives an ID-fallback warning.

Entity History preserves the upstream `ObjectChangeTO` array, sends `order=desc` explicitly because official default descriptions conflict, rejects `showAll=true` with `filter`, and refuses `offset + max > 1000`. Raw history requests without an explicit reviewed order remain partial. The `skipReferenceAttributesProcessing` performance option is opt-in because it can omit some reference-attribute changes. Typed and raw guidance warns that history stores canonical values without current `Accept-Language` retranscoding.

Potential-match retrieval preserves the dynamic match-group object and unknown nested entity/result fields. Typed requests explicitly send `forceMatch=false`, `transitive=false`, and `deep=1`, and use a conservative CLI default of 50. OpenAPI's 200 is a default rather than a maximum, so positive caller bounds are forwarded. Because grouped cardinality and continuation semantics are undocumented, metadata does not synthesize `returned` or `next_offset`. Every result warns about `ON_REQUEST`, strategy `NONE`, and custom-handler persistence conditions. Raw `forceMatch=true` is hard-refused; transitive traversal, filtering, sorting, action grouping, arbitrary options, custom action types, and response normalization remain deferred with partial coverage and no automatic retry.

`POST /entities/_byUris` remains deferred because current sources do not establish a trustworthy body optionality contract, request limit, response ordering/missing-item correlation, partial-failure model, or replay behavior.

Typed entity writes, relations, business configuration, tasks, SSO, and later families remain planned in the [product contract](PRD.md). The release report currently identifies 22 absent command leaves, absent endpoint bindings, the missing authorization-code provider, all 19 unproven MVP scenarios, and unimplemented mutation audit fields/results/runtime support. They must not be described as reviewed or production-supported until their registry, safeguards, documentation, and tests land together.
