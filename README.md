# APIContour

APIContour is an enterprise API discovery and contract intelligence project.
Its goal is to show which APIs an organization uses, what data structures those
APIs exchange, and how those structures change across services and deployments.

It is designed to observe authorized traffic, remove values locally, and send
only approved structural information to a central catalog. Teams will compare
observed structures with declared and approved contracts, then review changes.

**Status: under development.** This repository currently contains the Rust core
and two PostgreSQL identity/policy migrations with separated administrative and
ingestion privileges. It does not yet provide a runnable platform,
collector, ingestion service, or web UI. The architecture and packages below
describe the intended release.

## Enterprise workflows

| Team | Intended workflow |
|---|---|
| Platform | Enroll collectors, set capture scope, publish policy, and revoke access |
| Service owners | Review API variants and approve a specific contract version |
| Developers | Compare declared contracts with observations and check changes in CI |
| Security | Find APIs without an approved catalog entry and inspect visibility gaps |
| Operations | Monitor collection health, data loss, backlog, retention, and recovery |

Observed, declared, and approved contracts remain separate. An observation does
not approve a contract. An API that was not observed is not proof that it is absent.
Counts remain specific to each capture source unless a tested method removes duplicates.

## Intended architecture

```mermaid
flowchart LR
  subgraph Customer[Customer workload boundary]
    C[Collectors and adapters] --> S[Local policy and value removal]
    S --> Q[Bounded queue]
  end
  Q -->|Sanitized batches over mTLS| I[Ingestion API]
  I --> D[(PostgreSQL inbox)]
  D --> W[Background processing]
  W --> K[(API catalog and contracts)]
  K --> U[Catalog API and React UI]
  P[Signed policy administration] --> S
```

Rust supplies the backend and shared structural core. PostgreSQL is the central
system of record. React and TypeScript will supply the web UI.

Collectors will send bounded batches to the ingestion API; they will not connect
to PostgreSQL directly. Embedded collectors will use bounded memory by default.
Standalone collectors may use an optional local SQLite queue for sanitized data.
The queue and delivery service are not implemented yet.

Collection must not wait for a remote response on the application request path.
If a collector reaches its limits, it must report loss or incomplete visibility.
Encrypted traffic exposes only what the authorized capture point can see.
APIContour will not bypass certificate pinning or collect TLS secrets.
Collection is passive. It must not probe endpoints, replay production requests,
change request routing, or join business consumer groups to obtain messages.

## Planned packages and coverage

| Package | Intended use |
|---|---|
| Platform images, Helm chart, and migrations | Enterprise deployment with PostgreSQL |
| Docker Compose bundle | Local evaluation with synthetic traffic |
| Gateway and runtime adapters | Observe traffic at approved proxies or application hooks |
| Linux host agent | Authorized host observation, including a separate eBPF component |
| Managed browser, Android library, and iOS framework | Observe supported client interactions |
| AWS, GCP, Azure, and messaging connectors | Read approved telemetry or supported traffic sources |
| CLI and CI integration | Import, export, and compare contracts |
| Offline bundle | Install versioned packages without external runtime services |

Runtime/serverless, Kubernetes, Docker, and CI integrations are part of the
required scope. Protocol work includes HTTP, JSON, XML, forms, GraphQL, gRPC,
WebSocket, Kafka, and MQTT within tested support profiles. This list describes
planned coverage; it is not a claim that these integrations are available today.

Customer-hosted deployment is the proposed production model. The hosting decision
and production target are still pending. No production deployment is included yet.

## Implemented today

- Checked structural types, canonical encoding, and SHA-256 fingerprints.
- Bounded local JSON extraction that returns structure without observed values.
- Strict sanitized batch decoding, time checks, and canonical request digests.
- Signed Ed25519 policy verification, identity checks, and bounded policy leases.
- Pure batch admission against historical and current policies and supplied source assignments.
- PostgreSQL identity tables, tenant row security, and restricted runtime roles.
- Immutable policy history, active collector revision/revocation state, enrolled
  source profiles, separated administration/ingestion privileges, and advisory locks.
- Checked PostgreSQL deployment settings and owned TLS transport with explicit
  bounded CA trust, verified server identity, and cooperative DNS/TLS/auth deadlines.
  No arbitrary-query or raw-client public API is exposed.
- Rust CI on Linux and macOS, plus actual PostgreSQL integration tests.

Pure admission validates a supplied snapshot. Authentication, application
signature/metadata verification of stored policies, live revocation integration,
collector revision high-water storage, transactional ingestion, durable receipts, collector queues,
all collectors, contract comparison, and the UI still need implementation.
Full platform, device, cloud, recovery, and performance acceptance is pending.

## Build and test the current code

Install Rust 1.88 or later. Fetch the locked dependencies once, then run the checks:

```sh
cargo fetch --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked --offline -- -D warnings
cargo test --workspace --locked --offline
cargo build --workspace --locked --offline
```

For database tests, install Docker and fetch the pinned PostgreSQL fixture:

```sh
docker pull postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4
bash scripts/test-postgres.sh
```

The database test creates an isolated temporary container with no network or host
mounts. It removes that container when the test exits. See [database setup and
security boundaries](db/README.md). These commands test the current foundation;
they do not start an APIContour service.

## Design documents

- [Product scope and required workflows](docs/specification/01-product.md)
- [Privacy, signed policy, and admission rules](docs/specification/03-privacy.md)
- [Structural data and PostgreSQL model](docs/specification/04-data.md)
- [Collection, queues, batches, and delivery](docs/specification/05-delivery.md)
- [Performance targets and operations](docs/specification/08-operations.md)

The design documents include requirements that are not implemented yet.
Performance targets are acceptance criteria, not measured results.
