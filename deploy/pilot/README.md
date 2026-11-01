# Owned Node-RED pilot baseline

This opt-in synthetic baseline uses two stock Node-RED 5.0.9 containers and an
owned Node HTTPS destination, all from the same digest-pinned image. It does not
establish verified capture origin, instance lifecycle or causal attribution. It
uses no customer traffic or contributed nodes. The local CA must already exist
under `.local-mvp`; no CA private key is mounted into any container.

From the repository root, after the pinned image is available locally:

```sh
python3.13 deploy/pilot/prepare.py
export LOCAL_UID="$(id -u)" LOCAL_GID="$(id -g)"
docker compose -f deploy/pilot/compose.yaml up -d --pull never
python3.13 deploy/pilot/check.py
docker compose -f deploy/pilot/compose.yaml down
```

`prepare.py` refuses an existing `.local-mvp/pilot`; partial state is preserved
for inspection, never overwritten. Each replica mounts only its own client and
server keys. The destination mounts only its server key and the CA certificate.
Seven-day synthetic leaf certificates are intentionally short-lived. No system
trust store is changed. Stop/removal targets this Compose project only; the
private pilot state remains on disk.

Product HTTPS listeners remain private to the internal container network; no host
ports are published. A later root-managed gateway may provide a separate entrypoint.
The editor/admin API is disabled;
a fixed `GET /pilot` invokes a stock HTTP Request node to send a constant synthetic
POST to the owned destination. Its TLS config requires peer verification and
uses that replica's mounted client identity. The default fixed target is
`https://pilot-destination:9443/pilot`. `PILOT_TARGET` may select only that URL
or `https://pilot-gateway:9443/pilot`; the latter requires a separately provided
local gateway network endpoint presenting a certificate valid for
`pilot-destination`. It does not configure or claim gateway capture. No caller
header or request body chooses the upstream URL, method, credentials or payload.

`check.py` checks both product versions, authenticated HTTPS results, disabled
admin surface, wrong server name, untrusted server and missing client certificate.
It never prints keys, payloads or peer identities. Runtime startup, actual
mTLS behavior and cleanup must be verified on the approved execution lane; static
source checks alone do not prove them. The product image must be preloaded; this
profile does not pull it.

The TLS-node file fields and verification behavior were checked against the
Node-RED 5.0.9 `05-tls.js` tag; HTTP Request behavior was checked against
`21-httprequest.js` from the same tag. Both are stock upstream code.

The default check uses the normal stock flow. Three closed test modes require
recreating the owned containers, then invoking the matching check:

```sh
PILOT_TLS_TEST=wrong-name docker compose -f deploy/pilot/compose.yaml up -d --force-recreate --pull never
PILOT_TLS_TEST=wrong-name python3.13 deploy/pilot/check.py --expect wrong-name
PILOT_TLS_TEST=wrong-ca docker compose -f deploy/pilot/compose.yaml up -d --force-recreate --pull never
PILOT_TLS_TEST=wrong-ca python3.13 deploy/pilot/check.py --expect wrong-ca
PILOT_DESTINATION_MODE=redirect docker compose -f deploy/pilot/compose.yaml up -d --force-recreate --pull never
PILOT_DESTINATION_MODE=redirect python3.13 deploy/pilot/check.py --expect redirect
```

The TLS-negative modes change only the trusted server name or trust file in the
stock HTTP Request TLS configuration; certificate verification stays enabled.
Each must return a static failure from the product flow. Redirect mode returns a
controlled 302 to `/disallowed`; the flow disables redirects and the checker reads
the destination's synthetic disallowed-request counter. A nonzero counter fails
the check. These modes are local qualification controls, not capture evidence.
Both the in-container product HTTPS probe and destination TLS probe have
whole-exchange deadlines. The product probe verifies the local CA and hostname;
it does not disable TLS checks.
