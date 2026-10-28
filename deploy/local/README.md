# Local MVP infrastructure

This setup runs the application, pinned Keycloak and PostgreSQL images locally.
It provisions synthetic users and one synthetic service; it is not a production
deployment. Docker Compose, Python 3.13, OpenSSL, Rust 1.88.0 with locked dependencies
fetched for the startup identity verifier, the pinned infrastructure images,
and network access for the pinned build images and locked Rust and Node dependencies
are required. Containers do not receive the Docker socket.

From the repository root, run:

```sh
export RUSTUP_TOOLCHAIN=1.88.0
cargo +1.88.0 fetch --locked
docker pull postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4
docker pull quay.io/keycloak/keycloak@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244
python3.13 deploy/local/up.py
```

On a fresh checkout this initializes `.local-mvp`, starts the infrastructure containers
without pulling images, verifies real owner and viewer OIDC logins, applies the
existing database bootstrap, role provisioning, and migrations, then provisions
the two verified subjects, builds the application image, and starts the application. On restart it checks the migration ledger, fixed
identities and runtime privileges and verifies a TLS login. If configuration or
identity has drifted, or state is incomplete, startup fails for inspection. It
never resets a volume, replaces an existing credential, or repairs partial role
provisioning. Existing `.local-mvp` directories created before this database setup
lack its credential files and must be handled explicitly; startup will not generate
replacement files over existing state.

The private ignored state contains account credentials, a local CA, the database
password, `platform.json`, `business.json` and separate container configuration files. Keep it with the named Keycloak and
PostgreSQL volumes. Certificates expire after 30 days. No system trust is installed.
The provider listens on `https://localhost:8444` and PostgreSQL on
`localhost:5544`, both loopback only. PostgreSQL requires TLS for network logins;
the application checks the local CA and hostname. The runtime database login has
only the declared, comparison, review, approval, catalog reader and human lookup
groups. The provisioning administrator is used only from the startup script.

The application serves the UI and authenticated business API on https://localhost:9443.
To run the platform on the host instead, stop the app container first and build the UI
with its pinned Node toolchain, then run:

```sh
cargo run -p contour-platform --locked --offline -- .local-mvp/platform.json .local-mvp/business.json web/dist
```

The local CA is not installed in browser trust automatically. The approved synthetic import
route maps `/source` to `/orders`; example OpenAPI documents are
[baseline](sample-baseline.json) and [candidate](sample-candidate.json).
The initial MVP profile accepts OpenAPI JSON, one configured service/environment,
and catalog limit/cursor pagination; the broader protocol and optional catalog
filter surface remains pending. Unsupported formats and filters are rejected.
Imported operations without runtime evidence show **Not observed**. Their
`last_seen`, `visibility`, and `completeness` response fields are all `null`;
importing a contract does not create runtime observations.
`Idempotency-Key` optionally supplies a lowercase UUID for create requests; reuse
it only for the identical request after an uncertain response. The UI retains
pending request hashes and keys only in tab-scoped session storage and never automatically retries.

Account passwords are in `.local-mvp/accounts.json`; these users are local-only.

Stop and restart without deleting data:

```sh
export RUSTUP_TOOLCHAIN=1.88.0
docker compose -f deploy/local/compose.yaml stop
python3.13 deploy/local/up.py
```

The app runs as the invoking non-root user, with a read-only root filesystem and
only the required configuration and credentials mounted read-only. Startup retains
the named data volumes and existing credentials.

After startup, verify the HTTPS owner/viewer workflow and durable restart:

```sh
export RUSTUP_TOOLCHAIN=1.88.0
python3.13 -m venv /tmp/apicontour-spec-validation
/tmp/apicontour-spec-validation/bin/python -m pip install -r docs/specification/validation-requirements.txt
/tmp/apicontour-spec-validation/bin/python deploy/local/check_business.py --external --validate-schema
python3.13 deploy/local/check_stack.py
```

These checks create synthetic import and review records, retain those records,
and restart the owned application, provider and database containers. The restart
check also verifies that startup rejects an application that exits immediately.
