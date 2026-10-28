# Whole-service declared imports

`import_service_declared` projects an OpenAPI 3.0.3 JSON document into a transient
`DeclaredImportBundle`. Its `ServiceImportPolicy` must come from trusted
configuration: tenant/project/service/environment identifiers, source-path to
sanitized-route mappings, approved structural names and approved media labels.
Uploaded values must never be used to grant their own approval.

The bundle enumerates request and response bodies across configured paths, methods,
status selectors and media types. Each member retains its body selector and media
label separately from its checked graph; consumers must preserve those associations
even when two graph encodings are identical. Iteration is deterministic regardless
of JSON object order. Missing bodies and unsupported surfaces produce closed
partial-import warnings, not evidence of operation removal.

The existing duplicate-aware parser and graph converter enforce input, reference,
privacy and per-graph limits. A bundle additionally limits members to 4096, encoded
graphs to 8 MiB, graph nodes to 65536 and shared conversion visits to 262144.
Any failed member fails the entire import; the API never returns a truncated prefix.
Diagnostics and Debug output omit raw document values and source selectors.

This API does not allocate a public revision, resolve a configured default
environment, persist selector associations, authorize a human or serve HTTP. Those
steps belong to the application/storage transaction around the checked bundle.
