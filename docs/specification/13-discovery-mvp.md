# Replacement discovery MVP requirements

This addendum extends the [product scope](01-product.md) and [collector support contract](07-collectors.md). It records required behavior, not an implementation or completion claim. The existing R1 collector families and protocol obligations remain in scope. Test profiles and inventories are evidence tools; they do not reduce the universal requirement.

## Discovery and attribution

Discover policy-permitted API structure from actual requests and responses, including TLS-protected traffic where authorized plaintext is accessible. Capture integrations must be interchangeable through a versioned capability and observation interface. At least two independently exercised real integrations must feed the same semantics, including switching, detachment and overlap tests; that minimum does not exhaust universal coverage.

Attribute observations to the authenticated tenant, project, service, environment, deployment and workload instance that originated each call. Keep collector identity separate from workload identity and retain replacement history. Use platform identifiers together with lifecycle identity; PID, IP address, arbitrary headers and self-asserted labels alone are insufficient. Verify collector assignments and their validity over time, prevent cross-tenant association and stale reuse, and keep approved destination-service references and capture provenance separate from operation identity.

## Causality

Represent bounded causal events and their links separately from structural observations. Capture parent and link evidence, retries, fan-out and asynchronous boundaries when accessible. Distinguish verified, inferred and missing links; inferred or missing links do not satisfy a required complete causal path. Trace identifiers are untrusted correlation input, never identity or authorization. Temporal proximity and socket adjacency do not prove causality. Do not export raw baggage or business values by default. Define and review trust, sampling, propagation, size and retention rules before introducing causal metadata to a wire or storage contract.

## Managed TLS termination

An explicitly authorized APIContour-managed gateway must provide routing configuration, capture policy, certificate loading and renewal integration, upstream hostname and trust validation, health, rotation and rollback using a reviewed, mature TLS/proxy implementation. Keep keys within customer-approved secret boundaries and out of capture records and source control. Design and test the two TLS legs separately, including client mutual TLS; a new upstream certificate does not preserve the original client proof. Test certificate failures, reload and rotation, streaming, retries, recovery and rollback. Capture failure must not gate live requests; the inline proxy itself is an availability dependency requiring failure and production high-availability design. Customer routing and trust changes require appropriate scoped authorization.

## Universal coverage and feasibility

Universal black-box coverage remains a literal release requirement, including the inherited families and protocols. A finite positive matrix, metadata-only observation, visibility badge or proxy suggestion cannot establish universal coverage. Arbitrary inaccessible encrypted systems may not expose plaintext, and causality inside opaque concurrent systems may not be recoverable without suitable runtime access or trustworthy evidence. Such cases are **BLOCKED**, not passes or a reason to redefine the requirement. Maintain an inventory of access, runtime, protocol and trust boundaries with evidence, and obtain an owner decision for unresolved feasibility; an inventory does not narrow scope.

## Cross-cutting and release evidence

Existing privacy, authorization, isolation, reliability and performance requirements remain binding. Check current signed capture authority before inspecting payloads; sanitize before observation queues, export and persistence. Resolve any raw plaintext buffer boundary without weakening those requirements. Do not bypass certificate pinning, harvest TLS keys or perform unauthorized probing. Preserve bounded resources and honest loss under overload, expiry, revocation, stop and failure. New identity, trace and TLS metadata require reviewed compatibility, privacy and migration designs; this addendum does not change existing wire schemas.

Integrate instance and destination views, causal and capture provenance, health, and lifecycle history with authorized catalog and review workflows. Observations never automatically approve contracts. Release requires real end-to-end, concurrency, privacy, security, compatibility, recovery and performance evidence across these requirements as well as the inherited scope. Missing resources and unresolved feasibility remain BLOCKED; unexecuted evidence remains NOT_RUN. Neither is a pass.
