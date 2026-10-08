# Specification validation

## Executed checks

The reconstructed baseline contains 20 requirements, 16 workstreams, 56 work packages, 47 capability cases and 123 acceptance cases. It defines 21 API operations, 15 batch fixtures and 11 canonical structure vectors.

Run the offline check from the repository root:

```sh
python3 docs/specification/validate.py
```

It checks IDs, requirement coverage, task dependencies, required families, acceptance associations, document links, local contract references, API structure, batch fixtures and canonical outputs. It rejects missing prerequisites and premature task readiness. Its small schema interpreter is not a full conformance validator.

The pinned standard validators require Python 3.11 or later. CI selects Python 3.13. Run them in a dedicated environment:

```sh
python3.13 -m venv /tmp/apicontour-spec-validation
/tmp/apicontour-spec-validation/bin/python -m pip install -r docs/specification/validation-requirements.txt
/tmp/apicontour-spec-validation/bin/python docs/specification/validate-standard.py
```

The standard command first runs the offline checks. It then validates the batch schema and fixtures with JSON Schema 2020-12 and the complete API contract with OpenAPI 3.1. Dependency versions match the validation environment used during implementation. Product CI runs both commands and retains all native and database checks.

At the 2026-10-08 evidence checkpoint, local specification and standard validation passed. Independent reviews checked reference equivalence and publication closure from the Git index. Negative cases cover dependency cycles, missing required families, broken links and value-bearing structural nodes.

Rust formatting, Clippy, workspace tests and builds have run successfully. Real PostgreSQL fixtures have exercised migrations, tenant isolation, verified TLS, policy admission, atomic inbox submission, duplicate/conflict handling, cancellation, lost commit replies and owned process crash recovery. Each implementation PR has its own revision-specific results. These checks support the implemented foundation; they do not constitute the complete release acceptance suite.

## Remaining limits

All 123 product acceptance cases remain NOT_RUN in this design baseline. No full collector integration, physical-device, cloud-platform, load, rendered UI or production deployment acceptance is claimed. Database process crash tests do not prove power-loss durability, backup restoration or high availability. Diagram source is included; rendered diagram layout has not been inspected.

Local development uses a configured verification registry. It is not part of the product package and is not a release attestation. A passing specification check does not establish product correctness or authorize deployment.

The production hosting model remains pending. See [Decisions](10-decisions.md) for the recommended customer-hosted design and required live-test resources.
