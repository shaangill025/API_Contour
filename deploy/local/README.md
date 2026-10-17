# Local MVP identity provider

This starts the local login provider. The application HTTP/session/UI integration
is still in progress; this is not the complete runnable MVP.

Prerequisites: Docker Compose, Python 3.13, OpenSSL and the repository's locked
Rust dependencies. From the repository root:

```sh
python3.13 deploy/local/init.py
docker compose -f deploy/local/compose.yaml up -d
python3.13 deploy/local/check_oidc.py
```

Initialization refuses to overwrite `.local-mvp`. It generates a private local CA,
HTTPS certificate and random passwords for synthetic `owner` and `viewer` accounts.
Keycloak generates its own issuer signing keys; committed test signing keys are
never used. Runtime files are ignored by Git. No system/browser trust is installed.
The provider publishes only `https://localhost:8444`; its issuer is
`https://localhost:8444/realms/apicontour-local`. Account passwords are in the private
`.local-mvp/accounts.json` file. Never use these accounts for a real installation.

The pinned image uses a local file database in an owned Docker volume. Keys and
users survive provider restart; reimport does not update an existing realm.
Keep `.local-mvp` with that volume. The generated certificates expire after 30 days;
this setup is for local development, not production. The container is limited to
1 GiB and two CPUs and receives no host Docker socket or elevated capabilities.

The check builds the current Rust verifier, uses HTTPS trust from the generated CA,
performs independent owner/viewer authorization-code logins with S256 PKCE, verifies
the resulting ID tokens and rejects nonce mismatch, code replay, wrong PKCE and
direct password grants. It never follows redirects or prints credentials/tokens.
It writes the approved RS256 public keys and verified account subjects to private
configuration files for application provisioning. Provider token roles do not grant
database authority. This check does not prove application sessions or browser CSRF.

```sh
docker compose -f deploy/local/compose.yaml stop
docker compose -f deploy/local/compose.yaml start
python3.13 deploy/local/check_oidc.py
```

Stopping preserves the provider's data. Do not delete its volume or replace local
credentials as an implicit reset. The approved initial application profile will
retain full imports and reject ambiguous multi-member operation comparisons.
