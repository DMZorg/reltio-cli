# Reltio CLI Entity Data

## Direct Read

`entity get` accepts an ID or `entities/<id>` URI and reports `consistency: consistent`. `--fields` accepts documented lowercase top-level fields or nonempty `attributes.<path>` values. Repeated `--option` accepts `sendHidden`, `ovOnly`, `nonOvOnly`, `serializeInitialSourcesInCrosswalks`, `cleanEntity`, `showAppliedSurvivorshipRules`, `showEndDatedReferenceAttributes`, or `explainOv`. It also exposes Reltio's documented historical `--time`, duplicate-crosswalk, value-limit, explicit-survivorship-group, reverse-transcoding, and masking controls. `--reverse-transcode-lookups` carries a Preview availability warning in structured metadata and on stderr for raw/table output; verify the tenant capability and destination mapping before depending on the result.

```bash
reltio --profile dev --fields uri,label,type entity get 00009qz
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

The first request requires a filter. Resume identity includes the state schema, endpoint, profile, environment, tenant, normalized filter and query hashes, page size, resolved data-service route, and exact CLI version. Resume paths must be valid UTF-8. A mismatch or incoherent cursor, sequence, or timestamp fails before network I/O. Checkpoint events keep `data` null and expose the complete resumable state under `meta.resume`. The CLI derives expiry from the last-read time and reviewed one-hour registry limit, then bounds each continuation's authentication and complete retry chain by that expiry because tenant `preserveCursor` capability is not always discoverable.
