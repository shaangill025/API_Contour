# Local MVP infrastructure

This setup runs the pinned Keycloak and PostgreSQL images locally. It provisions
synthetic users and one synthetic service; it is not a production deployment or
a fully containerized application. Docker Compose, Python 3.13, OpenSSL, the
already available pinned images, and the repository's locked Rust dependencies
are required. Docker is used only by the setup process; neither container receives
its socket.

From the repository root, run:

```sh
python3.13 deploy/local/up.py
```

On a fresh checkout this initializes `.local-mvp`, starts the two containers
without pulling images, verifies real owner and viewer OIDC logins, applies the
existing database bootstrap, role provisioning, and migrations, then provisions
the two verified subjects. On restart it checks the migration ledger, fixed
identities and runtime privileges and verifies a TLS login. If configuration or
identity has drifted, or state is incomplete, startup fails for inspection. It
never resets a volume, replaces an existing credential, or repairs partial role
provisioning. Existing `.local-mvp` directories created before this database setup
lack its credential files and must be handled explicitly; startup will not generate
replacement files over existing state.

The private ignored state contains account credentials, a local CA, the database
password, `platform.json` and `business.json`. Keep it with the named Keycloak and
PostgreSQL volumes. Certificates expire after 30 days. No system trust is installed.
The provider listens on `https://localhost:8444` and PostgreSQL on
`localhost:5544`, both loopback only. PostgreSQL requires TLS for network logins;
the application checks the local CA and hostname. The runtime database login has
only the declared, comparison, review, approval, catalog reader and human lookup
groups. The provisioning administrator is used only from the startup script.

The host platform can be launched with its identity configuration:

```sh
cargo run -p contour-platform --locked --offline -- .local-mvp/platform.json .local-mvp/business.json web/dist
```

Build the UI with its pinned Node toolchain before starting the host. This command
serves the UI and authenticated business API on https://localhost:9443. The local
CA is not installed in browser trust automatically. The approved synthetic import
route maps `/source` to `/orders`; example OpenAPI documents are
[baseline](sample-baseline.json) and [candidate](sample-candidate.json).
The initial MVP profile accepts OpenAPI JSON, one configured service/environment,
and catalog limit/cursor pagination; the broader protocol and optional catalog
filter surface remains pending. Unsupported formats and filters are rejected.
`Idempotency-Key` optionally supplies a lowercase UUID for create requests; reuse
it only for the identical request after an uncertain response. The UI retains
pending keys only in the current tab memory and never automatically retries.

Account passwords are in `.local-mvp/accounts.json`; these users are local-only.

Stop and restart without deleting data:

```sh
docker compose -f deploy/local/compose.yaml stop
python3.13 deploy/local/up.py
```

The setup's static configuration still requires a real startup, restart, migration,
authorization and browser workflow verification before it is considered complete.
