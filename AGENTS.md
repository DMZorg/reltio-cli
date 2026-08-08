# Repository Agent Instructions

Read `docs/PRD.md` before planning or implementing product work. Treat it as the current product contract unless a later approved decision supersedes it.

## Reltio API Guidance Contract

Before adding or changing any Reltio API operation, review the current English-language Reltio documentation, release notes, and deprecation notices, together with Reltio's official AI-ready documentation corpus. Treat every applicable requirement, limit, recommendation, note, tip, warning, deprecation, and release change as implementation input.

Update the API-practice registry, command metadata, tests, and user/agent guidance in the same change. Enforce guidance automatically when the CLI controls the behavior; otherwise provide a preflight check or an actionable warning. Never claim best-practice coverage for an unreviewed endpoint, and choose the conservative behavior when current sources are ambiguous or conflict.

# Direction for Implementing Agent

## Quality Directive

**BURN AS MANY TOKENS AS NEEDED FOR MAXIMUM QUALITY. Long, thorough turns are preferred. Use your judgment, investigate deeply, and do not rush to a conclusion.** Persist through implementation, validation, documentation, and final assessment. Prefer exhaustive correctness over brevity when the two conflict.

Do not stop at analysis when a safe implementation or verification step remains. Inspect the repository before changing anything, preserve concurrent work, and independently verify important assumptions.

## Long-Run Goal

Make this a production-grade, high-value tool.
