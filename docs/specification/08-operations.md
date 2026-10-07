# Performance and operations

## Initial acceptance targets

These targets are reconstructed engineering defaults. They are not measurements or customer service commitments. Record machine configuration and repeatable load before assessing them. Changing a target requires a recorded reason and review; do not weaken it to hide a failing test.

| Limit | Initial target |
|---|---|
| Body inspected | 64 KiB per message; oversize content marked partial |
| Structure depth | 32 levels |
| Fields per object | 256 approved fields |
| Array items inspected | 64 items; remaining content marked partial |
| Numeric token | 256 bytes |
| Structural output | 64 KiB per record |
| Distinct structures cached | 10,000 per collector; bounded eviction |
| Memory queue | 16 MiB per standalone collector; 1 MiB per embedded instance |
| Durable queue | 256 MiB including database auxiliary files; 24-hour TTL |
| Batch | 500 records and 1 MiB uncompressed; 5-second flush |
| Collector health | 16 KiB per report; normally once per 30 seconds |
| Ingress | 20 requests/second and 10 MiB/second per collector; bounded tenant aggregate quota |
| Worker intake | Stop claiming inbox work when downstream storage is constrained |

All parsers must have a 2 ms cooperative local work budget per message. A budget overrun yields partial or unavailable evidence. Native hooks must not await that work on a latency-sensitive callback if it cannot stay within the callback budget. Embedded observation callback target: p99 at most 100 microseconds on the defined fixture host.

For a representative HTTP workload, throughput loss must be at most 5%, and added p99 request latency at most 1 ms. Standalone agent RSS target is 128 MiB excluding documented kernel buffers. Embedded-library incremental RSS target is 32 MiB. Mobile testing must include battery and background constraints; a separate measured target is required before that lane can pass.

The server reference profile uses 4 vCPU, 8 GiB RAM and a separately measured PostgreSQL service. Test 1,000 sanitized records/second for 60 minutes, with 10% new variants, 10,000 operations and 100 concurrent catalog readers. Target durable ingestion p95 below 250 ms and searchable-data lag p95 below 30 seconds. Test at twice intake load for 15 minutes: quotas and loss/backlog signals must remain accurate, and no process may grow without bound. Payload distribution is 90% 1 KiB and 10% 16 KiB structural records. Publish actual database resources and storage latency with results.

## Capacity and retention

Estimate storage from distinct structures, per-source summary windows, change rate and retention. Do not size solely from request count. Proposed retention defaults: processed inbox 7 days, observation summaries 30 days, discrepancy history 90 days and audit history 365 days. Approved contracts stay until an authorized deletion policy applies. Immutable does not mean undeletable under policy.

Cleanup must preserve deduplication for the delivery retry horizon. Delete expired data from derived stores and document backup expiry. Keep health history sufficient to explain missing observations. Unknown traffic volume must remain unknown.

## Recovery and upgrades

Production requires tested database backups and restore instructions. Proposed recovery targets are RPO at most 15 minutes and RTO at most 4 hours for the reference profile. A receipt proves durable acceptance on the configured database, not survival of every regional disaster. An HA profile must document its stronger receipt durability and failover behavior.

Test process kill before/after local commit, before/after server commit, lost acknowledgments, worker restart, disk full, database failover, expired identity and policy changes. Restore must preserve tenant isolation and contract history. Schema upgrades use compatible expand/migrate/contract steps where overlap is needed. Refuse incompatible collector/server versions before accepting data.

## Operational signals

Expose queue bytes, oldest batch age, dropped/expired records, policy state, source gaps, parser limits, active capture profile, inbox lag, worker failures and database health. Metrics must use bounded approved labels. Support bundles contain configuration identifiers and safe counters only.

The UI must show stale collector health after 90 seconds without a report. Do not change stale to healthy merely because the catalog still has records. Alert destinations require explicit configuration and restricted egress.

Each package must have install, uninstall, upgrade, backup, restore and emergency-disable procedures. Uninstall documents what data remains. Offline mode must not require external telemetry, licensing checks or a hosted identity provider to process authorized data; customer-local identity is supported.
