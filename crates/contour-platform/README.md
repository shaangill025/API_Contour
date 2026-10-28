# Local HTTPS authentication host

This is the bounded local login/session boundary, not a complete platform server.
It serves `https://localhost:9443` on `127.0.0.1:9443`. The fixed local provider is
`https://localhost:8444/realms/apicontour-local`; there is no discovery, remote URL
selection, system root trust, redirect-following token client or password grant.

After the separately approved `deploy/local` provider setup and verification,
create an operator-owned JSON configuration (paths are relative to process cwd):

```json
{
  "issuer": "https://localhost:8444/realms/apicontour-local",
  "authorization_endpoint": "https://localhost:8444/realms/apicontour-local/protocol/openid-connect/auth",
  "token_endpoint": "https://localhost:8444/realms/apicontour-local/protocol/openid-connect/token",
  "client_id": "apicontour-local",
  "callback": "https://localhost:9443/auth/callback",
  "tls_certificate": ".local-mvp/tls/server.crt",
  "tls_private_key": ".local-mvp/tls/server.key",
  "provider_ca": ".local-mvp/ca.crt",
  "jwks": ".local-mvp/approved-jwks.json"
}
```

Use the actual public JWKS filename written by the provider verification script.
Run `AWS_LC_SYS_USE_SYSTEM=0 cargo run --locked -p contour-platform -- CONFIG.json`.
Browser trust for the development CA must be handled explicitly by the operator;
this host never installs a certificate or weakens certificate verification.

Login uses 256-bit independent random state, nonce, PKCE verifier and browser
binding. State expires after five minutes and is consumed before token exchange,
including unsuccessful callbacks. At most 512 pending logins and 256 sessions are
retained; capacity returns 503 rather than evicting active sessions. Sessions are
opaque host-only Secure/HttpOnly/SameSite=Lax cookies, stored only in memory with
the ID token and nonce. Every use re-verifies the token against current UTC and
the immutable configured issuer/audience/public keys. Sessions last at most 30
minutes and cannot outlive ID token expiry. Restart logs everyone out. There is
no refresh flow; sign in again after expiry. Logout removes the application
session and cookie; the provider's SSO session is separate.

Requests have 32-header/16KiB header, 8KiB query, 5MiB body and 20-second entire
connection limits. At most 32 connections run concurrently. Token exchange has a
10-second deadline and 64KiB response cap. The listener owns and reaps accepted
connection tasks; cancelling it aborts pending connection/request work even when
the runtime remains alive. No HTTP keepalive, CORS or request logs
are enabled. Duplicate query keys/cookie names and multiple Cookie headers are
rejected. Mutations require exact configured Origin and JSON Content-Type. These
checks execute before business callbacks. GET/HEAD bodies and trailers are rejected.

`Platform::serve_with` accepts an async callback receiving `BusinessRequest`
(`Request<Bytes>`) and a freshly `VerifiedIdentity`. Only authenticated `/v1/`
requests reach it. It must perform current enabled actor and exact scoped database
membership checks in the business transaction; an ID token never grants a role.
The standalone binary returns 503 for business requests. `/livez` reports process
liveness; `/readyz` explicitly returns 503 while business integration is pending.
The landing page accurately describes this limitation.

Focused checks: `cargo test -p contour-platform --locked --offline`,
`cargo clippy -p contour-platform --all-targets --locked --offline -- -D warnings`,
and `cargo fmt --all --check` (with `AWS_LC_SYS_USE_SYSTEM=0`). Unit tests cover
browser binding, replay, exact expiry, bounded state, logout removal, PKCE known
vector, cookie attributes, origin/host/content-type checks and duplicate/malformed
wire inputs. A real loopback regression requires socket EOF and pending handler
drop on host cancellation, with no completion after its barrier is released while
the runtime remains alive. They do not establish live provider, browser, database,
provider/TLS cancellation or complete MVP readiness; those require parent integration.
