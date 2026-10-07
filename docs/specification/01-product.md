# Product scope

## Required outcome

The platform must identify observed APIs, their structures, their source and their limits. It must compare observed behavior with declared and approved contracts. It must show changes by service, environment and deployment.

R1 includes gateway/proxy, Linux eBPF, managed browsers, Android, iOS, AWS, GCP, Azure, messaging, runtime/serverless, Kubernetes, Docker and CI integration. It includes HTTP, JSON, XML, forms, GraphQL, gRPC and WebSocket structural handling within declared support profiles.

The backend and shared native core use Rust. PostgreSQL is the system of record. The UI uses TypeScript and React. Rust/WASM and Rust FFI share extraction logic where practical. Platform adapters can use TypeScript, Kotlin, Swift or Java. They must not replace the Rust backend.

## Users and workflows

| User | Required workflow |
|---|---|
| Platform administrator | Enroll collectors, assign scopes, publish signed policies, revoke access and view health |
| Service owner | Review endpoint variants, compare contracts and approve a selected version |
| Developer | Import a declared contract, inspect a discrepancy and run a CI contract check |
| Security reviewer | Inspect privacy policy, unknown APIs, visibility gaps and audit history |
| Operator | Inspect queue loss, collection failure, ingestion backlog, retention and recovery |
| Read-only viewer | Search authorized catalog records without changing contracts or policies |

An unknown API means an observed API with no matched approved catalog entry. It does not mean a proven security vulnerability. An unobserved field is not proof of absence. Observation counts are source-specific unless a tested correlation method can remove duplicate captures.

## Boundaries

The product must not probe endpoints, replay production requests, bypass certificate pinning, harvest TLS keys or join business consumer groups to obtain messages. Synthetic test traffic is allowed only in an isolated authorized fixture. Cloud management reads and existing-log ingestion require separate scoped permission.

The product must not change request routing, broker delivery semantics, application responses or encryption controls. It may export approved structural contracts. It must never promote observations to approved contracts without an authorized review.

The image's phased roadmap defines internal checkpoints only. It does not remove a family from R1. Database observation is limited to approved service metadata in R1; SQL values and general database query capture are outside this baseline.

## Completion

Release requires real positive structural capture and accurate-limit tests for every traffic-capture family. Deployment and CI integrations require real attribution and artifact-comparison evidence, plus integration with traffic collectors. It also requires privacy, overload, recovery, security, UI and compatibility evidence. Missing resources have status BLOCKED. Unexecuted tests have status NOT_RUN. Neither status is a pass.
