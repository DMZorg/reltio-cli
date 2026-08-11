# Reltio CLI Authentication

## Provider Choice

| Situation | Provider | Secret input |
| --- | --- | --- |
| CI or agent | `client-credentials` | `RELTIO_CLIENT_SECRET` or owner-only file |
| Corporate broker or vault | `credential-process` | strict JSON on process stdout |
| One invocation | supplied bearer | `RELTIO_ACCESS_TOKEN` |
| Deliberate local import | bearer login | `--token-stdin` |

Client credentials use `https://auth.reltio.com/oauth/token`, HTTP Basic client authentication, and form-encoded `grant_type=client_credentials`. Tokens are opaque and may be multi-kilobyte JWT values.

The CLI coordinates cache acquisition through an owner-only cross-process lock and reuses a token until its documented expiry. Provider and imported candidates inside the five-second expiry-skew window are rejected before replacing a valid cache preimage. Login secret stdin and file inputs are mutually exclusive, and profile validation occurs before secret stdin is consumed. Login preflights exact guarded output, stages the candidate cache, retains displaced generations for crash and reader coherence, then compare-and-swaps the profile. An ordinary profile failure restores the candidate cache under the same lock. If a physical output failure reports `local_state_committed: true`, inspect `auth status` instead of replaying login. In the positional guarded-failure shape, local commit state is field index `11`. The CLI reacquires and replays at most once after an explicit `401`, and only when the request can be replayed safely.

Token acquisition itself is not retried after transport or non-`429` failures. A `429` may be replayed once within the auth deadline; `--no-retry` disables both that replay and the safe `401` refresh.

```bash
reltio --profile dev auth status
reltio --profile dev auth check
printf '%s' "$TOKEN" | reltio --profile dev auth login --method bearer --token-stdin --expires-in 1h
reltio --profile dev auth logout
```

`auth token --show` intentionally discloses only the selected access token. Distinct refresh tokens, client secrets, derived HTTP Basic credentials, environment credentials, and every final, displaced, or orphaned local cache generation remain protected even in raw mode, help, and generated output errors. Malformed provider and cache JSON is guarded before strict parsing, with duplicate values retained. Rendering guards include the automatically appended newline. Broken pipes are errors rather than successful disclosure. Prefer `--output raw` redirected to the consuming process, and never log its output.
