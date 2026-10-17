# OIDC ID-token verification boundary

`IdTokenVerifier` verifies an RS256 ID token against an immutable, operator-supplied
HTTPS issuer, client ID and public JWKS. It has no network or discovery capability.
Token headers cannot introduce a key, URL, algorithm or certificate trust source.
Only `alg`, `kid` and optional `typ: JWT` headers are accepted; unsupported critical
headers and token-directed key references fail closed. JWKS certificate metadata
is public metadata only and never establishes trust. Private key fields are rejected.

Call `verify(token, expected_nonce, now_unix)` with the nonce from the server's
one-use login transaction and trusted UTC Unix seconds. Neither argument may come
from the submitted token or request. The result contains only the verified issuer,
subject and expiry. Map the exact `(issuer, subject)` pair to an enabled application
actor and check tenant/project/service permissions separately on every operation.
An ID token is a login credential for this relying party, not a general API bearer
credential. Resource IDs and successful token verification do not grant approval.

Registered identity claims must have their proper JSON types. Issuer, subject,
audience, expiry, issued-at and nonce are required. NumericDate values use whole
nonnegative Unix seconds in this supported subset; strings, nulls, fractions and
out-of-range integers fail. Expiry must be strictly later than trusted now and
issued-at; issued-at cannot be in the future. Optional not-before must be typed,
not later than now and earlier than expiry. No clock leeway is applied. Audience
must contain the configured client ID; multiple audiences require `azp` equal to
that ID, and `azp`, if present, must always match. The subject is 1–255 ASCII bytes.
Duplicate registered fields and positional JSON arrays fail. Additional claims
are ignored, including asserted application roles and tenant identifiers.

Allocation limits: token 16 KiB, decoded protected header 2 KiB, supplied JWKS
64 KiB, at most 32 unique key IDs, RSA modulus 2048–8192 bits, audience array at
most 16 entries, issuer 1024 bytes and client/key ID/nonce 256 bytes. Nonempty text
must not contain control characters. These are this implementation's accepted
subset and server resource limits, not new platform endpoint schema limits.

The verifier does not implement authorization-code exchange, PKCE, state, browser
binding, replay prevention, sessions, refresh, discovery, key rotation fetching,
revocation, logout or membership storage. The caller must provide those boundaries.
When retaining tokens, verify again with current trusted time and current approved
key configuration, then authorize current membership. No authenticated-pilot-ready
claim is made by this crate alone.

## Dependency and focused verification

`jsonwebtoken = 11.1.0`, with defaults disabled and `aws_lc_rs`, performs signature
verification. Existing exact serde, JSON, base64 and HTTP pins are reused. No OAuth
client dependency is added before it is used. `aws-lc-rs 1.18.2` / `aws-lc-sys 0.46.0`
introduce native C/assembly compilation and bundled third-party notices; retain
those license notices when distributing binaries. This is not a FIPS configuration.

Use `AWS_LC_SYS_USE_SYSTEM=0 cargo test -p contour-auth --locked --offline` and the
same environment for Clippy/builds to select the reviewed bundled source instead
of automatically discovered system AWS-LC. Leave explicit system directory unset.
The synthetic DER fixture is a publicly committed, test-only RSA key and must
never be used as an application identity or issuer signing credential.
