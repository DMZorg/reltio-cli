# Reltio CLI Entity Data

## Direct Read

`entity get` accepts an ID or `entities/<id>` URI and reports `consistency: consistent`. `--fields` accepts documented lowercase top-level fields or nonempty `attributes.<path>` values. Repeated `--option` accepts `sendHidden`, `ovOnly`, `nonOvOnly`, `serializeInitialSourcesInCrosswalks`, `cleanEntity`, `showAppliedSurvivorshipRules`, `showEndDatedReferenceAttributes`, or `explainOv`. It also exposes Reltio's documented historical `--time`, duplicate-crosswalk, value-limit, explicit-survivorship-group, reverse-transcoding, and masking controls. `--reverse-transcode-lookups` carries a Preview availability warning in structured metadata and on stderr for raw/table output; verify the tenant capability and destination mapping before depending on the result.

```bash
reltio --profile dev --fields uri,label,type entity get 00009qz
```

## Crosswalk Read

`entity by-crosswalk` returns Reltio's wrapper array unchanged. Supply `--type`, `--value`, optional `--source-table`, and only the reviewed shared options `sendHidden`, `ovOnly`, or `nonOvOnly`. The lookup is consistent. The CLI conservatively accepts only RFC 3986 unreserved path values because Reltio directs special-character values to a separate POST variant without defining the exact GET character set. A warning identifies the documented Reltio-ID fallback when a successful object lacks the requested crosswalk tuple.

```bash
reltio --profile dev entity by-crosswalk \
  --type configuration/sources/CRM \
  --value customer-123
```

## Indexed Search

`entity search` uses the Reltio-recommended POST-body form. Filters over 256 characters are refused because Reltio otherwise processes only the first 256 characters. `offset + max-items` cannot exceed 10,000. Search is eventually consistent, so use direct get for read-after-write verification.

```bash
reltio --profile dev entity search \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --max-items 50
```

## Cursor Scan

Use scan for exhaustive retrieval. It streams bounded pages and never builds the full tenant result in memory.

```bash
reltio --profile dev entity scan \
  --filter "equals(type,'configuration/entityTypes/Organization')" \
  --page-size 100 \
  --resume-file organizations.resume.json \
  > organizations.jsonl
```

The first request requires a filter. Repeated `--option` accepts only the conservative locked-OpenAPI allowlist `sendHidden`, `searchByOv`, `ovOnly`, and `nonOvOnly`; `ovOnly` and `nonOvOnly` conflict. Current English cursor documentation omits options, while the OpenAPI and connector material use incompatible route and cursor contracts. The CLI refuses option transmission unless `--allow-unverified-scan-options` explicitly acknowledges that conflict, and option-bearing raw requests remain partial coverage. Pilot behavior in a non-production tenant before using the acknowledgement. A response containing the conflicting `entities` collection without canonical `objects` is refused rather than interpreted as exhaustion. Resume identity includes the state schema, endpoint, profile, environment, tenant, normalized filter and query hashes, page size, resolved data-service route, and exact CLI version. Resume paths must be valid UTF-8. A mismatch or incoherent cursor, sequence, or timestamp fails before network I/O. Checkpoint events keep `data` null and expose the complete resumable state under `meta.resume`. The CLI derives expiry from the last-read time and reviewed one-hour registry limit, then bounds each continuation's authentication and complete retry chain by that expiry because tenant `preserveCursor` capability is not always discoverable.

## History

`entity history` preserves Reltio's history-event array, sends descending order explicitly, and refuses windows beyond the 1,000 most recent events. `--show-all` cannot be combined with `--filter` because Reltio ignores that filter. Reltio recommends `--show-all` when no `changes(...)` filter is used. `--skip-reference-attributes-processing` can improve latency but may omit reference-attribute deltas, so it is never automatic. History contains stored canonical values and is not retranscoded for `Accept-Language`, so it can differ from a current entity read.

```bash
reltio --profile dev entity history entities/00009qz --max-items 50
```

## Potential Matches

`entity matches` retrieves stored direct potential matches and preserves the dynamic match-group object. It explicitly disables forced recalculation and transitive traversal, so it remains a replay-safe read. Reltio documents 200 as the API default, not a maximum, and does not document grouped continuation cardinality, so the CLI does not invent `next_offset`. Results may be absent or out of date with `ON_REQUEST`, strategy `NONE`, or custom handlers that do not persist suspect links. After release `2026.1.9.0` reaches a tenant, selected returned relevance values change from rounding to two-decimal truncation; DEV/TEST rollout is scheduled for August 21, 2026 and PRD for August 28, 2026. Preserve the server score, order, and `matchActionLabel`; do not derive an action or sort from the displayed score. Raw `forceMatch=true` is refused until its cost, state-change, and replay contract is reviewed. Use `--match-type automatic`, `relevance_based`, or `suspect` to select a reviewed built-in group type.

```bash
reltio --profile dev entity matches entities/00009qz \
  --match-type suspect \
  --max-items 50
```
