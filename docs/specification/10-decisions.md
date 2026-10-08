# Decisions and prerequisites

## Established requirements

Rust backend/native core, PostgreSQL, React/TypeScript, passive collection, local sanitization, no raw-value persistence/export, bounded overhead, explicit coverage and all named families in R1 are fixed by the supplied handoff. Specification reconstruction is authorized. No alternative stack or reduced release is introduced.

## Owner decisions

| ID | Decision | Recommended option and reason | Other option and tradeoff | Status |
|---|---|---|---|---|
| D01 | Production hosting | Customer-hosted, one enterprise per installation. Supports private networks and limits service-operation scope. | Add vendor-hosted R1. Requires an additional operational and customer-isolation specification. | PENDING_OWNER |
| D02 | Real integration resources | Customer-approved isolated test accounts and devices, supplied through existing secret management. Tests real behavior without production collection. | Dedicated new paid resources. Requires budget and account authorization. | REQUIRED_BEFORE_LIVE_TESTS |
| D03 | Production release target | Named customer-controlled test/staging target first, followed by separately authorized production rollout. | No deployment; deliver verified packages only. | REQUIRED_BEFORE_DEPLOYMENT |

D01 is pending. Customer-hosted diagrams are a proposed baseline, not an accepted hosting decision. Shared extraction, schemas and local test design do not depend on this choice. SaaS-specific operations must not be silently added or declared complete.

## Engineering choices

This baseline selects bounded batching, immutable contract versions, source-specific counts, mTLS collector identity, OIDC users, optional SQLite spooling and PostgreSQL inbox processing. Exact library choices require a dependency review before installation. Their design does not authorize account access or activate collection.

Numeric limits in [Operations](08-operations.md) are initial engineering acceptance targets. Support technologies in [Collectors](07-collectors.md) are proposed positive test profiles. P00 must lock supported version tuples after feasibility checks. Failure requires a documented replacement within the same lane, not removal of coverage.

## External prerequisites

| Area | Required evidence before lane execution |
|---|---|
| Linux | Authorized test host/kernel, architecture and supported TLS build |
| Browser | Managed distribution/test policy and supported browser versions |
| Android | Java/Android build tools and selected physical test device |
| iOS | Full Xcode, selected physical device and authorized signing process |
| Cloud | Isolated AWS/GCP/Azure scope, least-privilege identities and approved cost limits |
| Messaging | Real isolated Kafka and MQTT brokers and producer/consumer fixtures |
| Platform | PostgreSQL, container runtime, target cluster and identity-provider fixture |
| Supply chain | Reviewed dependencies, licensing, package signing and publication destinations |

Do not put credentials, private account IDs or local personal paths in this document. Keep environment-specific secret references in the customer's approved configuration system.
