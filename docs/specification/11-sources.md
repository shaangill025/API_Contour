# Sources and scope reconciliation

## Supplied planning material

| Source | Requirements retained |
|---|---|
| README_HANDOFF.md, baseline 1.0, 2 October 2026 | Stack, every collector family, passive operation, review authority and real evidence |
| CODEX_START.md | Preflight, shared foundation, no fabricated platform results, deployment boundaries |
| 13_PROGRAM_PLAN.md | All 16 workstreams, one full R1, dependency sequencing and no silent deferral |
| ARTIFACT_REPORT.md | Historical validation is not implementation or real-platform evidence |
| API Discovery End-to-End View image | Collection points, structure extraction, change detection, visibility limits and bounded processing |
| Product discussion | Separate collector packages, central PostgreSQL, optional local persistence, sanitized batch delivery |

The original package reported 46 requirements, 122 tasks, 47 capability rows and 169 acceptance tests. Their content is unavailable. Matching those counts would not prove equivalent scope. This baseline instead maps every recoverable requirement to explicit new tasks and tests. If the original package appears later, perform a requirement-by-requirement comparison and add any missing scope. Do not claim full equivalence until that comparison is possible.

The image's MVP roadmap conflicts with the handoff's full R1 requirement. This baseline treats phases as internal checkpoints and retains every family for R1. The image's visibility indicators are illustrative; only tested support profiles can establish actual visibility.

Original effort ranges are planning estimates, not delivery commitments. This baseline does not infer a completion date from task counts or tool speed.

## Technical references

- [PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html): role and row-policy behavior.
- [SQLite appropriate uses](https://www.sqlite.org/whentouse.html): embedded storage and write-concurrency tradeoffs.
- [Chrome webRequest API](https://developer.chrome.com/docs/extensions/reference/api/webRequest): managed-browser API and permission limits.
- [OpenTelemetry sensitive-data guidance](https://opentelemetry.io/docs/security/handling-sensitive-data/): minimizing sensitive telemetry.

These references support limited design facts. They do not establish that any APIContour component works. Exact dependency versions and compatibility remain preflight outputs.
