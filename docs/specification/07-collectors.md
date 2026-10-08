# Collector support contract

## Support rules

Every traffic-capture family needs at least one real structural capture case plus its accurate-limit cases. Kubernetes and Docker integrations must prove workload attribution and deployment behavior. CI must prove artifact comparison. These integrations also undergo end-to-end tests with real traffic collectors. A metadata-only result cannot satisfy a structural case. Exact operating-system, kernel, SDK, library, browser and service versions must be pinned and tested in P00 and P14. The table gives proposed initial profiles, not verified compatibility.

| Family | Initial positive profile | Required limits |
|---|---|---|
| Gateway | Envoy integration after TLS termination; NGINX integration where supported | Passthrough TLS has no body visibility; do not alter routing |
| Linux eBPF | Supported dynamically linked TLS library boundary with HTTP plaintext | Unsupported/static/inlined libraries, kernel or ABI changes report limits; no key harvesting |
| Browser | Managed Chromium extension plus explicit first-party page instrumentation | Host permission and API limits; no universal response-body claim |
| Android | Opt-in OkHttp application instrumentation through a native library | Unsupported clients and app-level encryption report limits |
| iOS | Opt-in URLSession instrumentation through an application library | No pinning bypass; background execution and framework limits |
| AWS | Authorized API Gateway/log telemetry plus SDK or Lambda runtime structure | Logs without bodies provide operation evidence only |
| GCP | Authorized audit/gateway telemetry plus client or function instrumentation | Provider logs alone do not establish payload structure |
| Azure | Authorized API Management/monitor telemetry plus runtime instrumentation | Same distinction between metadata and structure |
| Messaging | Kafka and MQTT producer/consumer runtime hooks | Never join business groups, publish discovery messages or change acknowledgments |
| Runtime | Java, Node.js and Rust HTTP adapters using the shared core where practical | Native hooks, concurrency and unsupported libraries have explicit profiles |
| Serverless | AWS Lambda, Google Cloud functions and Azure Functions runtime adapters | Cold start, time limit and shutdown can cause reported loss |
| Kubernetes | Node agent and workload attribution through scoped metadata reads | No automatic broad cluster privilege; namespace isolation |
| Docker | Container deployment and identity association | Restart and ephemeral volume behavior remain visible |
| CI | Contract comparison CLI with scoped identity | Cannot prove runtime behavior from an artifact alone |

These concrete technologies reconstruct a minimum test matrix. A proven infeasible technique can be replaced within its family through a recorded design decision. Removing a family needs an owner scope decision; it cannot be achieved by changing a test status.

Chrome webRequest is an event API with permission and request-type constraints. It is not a general response-body feed. Managed page instrumentation needs its own security and compatibility tests. See the [Chrome API reference](https://developer.chrome.com/docs/extensions/reference/api/webRequest).

## Protocol handling

HTTP records methods, normalized routes, approved names and status codes. JSON and forms extract types after removing values. XML disables external entity resolution and uses approved element/attribute names. Multipart treats binary parts as binary and never retains file contents or filenames.

GraphQL removes arguments and variables, normalizes operation structure, and bounds aliases and nesting. Do not persist arbitrary operation text. gRPC uses approved supplied descriptors or runtime type access; encrypted or descriptor-free bytes do not imply known fields. WebSocket messages use bounded per-message inspection. Protocol upgrades and binary unknowns remain explicit.

AI API handling follows the same rules. Prompts, model outputs, tool arguments and embeddings are values and must not persist. Only approved operation and structural information is exported. Application-level encrypted content exposes an envelope at most; never claim inner-field visibility.

Message operation keys include approved channel template, publish/consume direction, protocol and service. Payload handling uses the shared structural model. Header values, keys and business identifiers are removed. Multi-consumer observations are separate sources.

## Test matrix

[Capability cases](backlog/traceability.json) list required positive and limit scenarios. For each case record exact versions, architecture, permission profile, policy hash, test corpus, result, resource measurements and evidence checksum.

Every family must also run policy-off, permission-denied, collector-stop, network-outage, overload, malformed-input and privacy-sink tests. Evidence from a unit mock cannot replace a real library, browser, device, cloud service, broker or kernel lane. Emulators can provide additional evidence; mobile release acceptance requires the selected physical-device profiles.
