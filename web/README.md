# Contract review workspace

This is the first React/TypeScript review slice, not the complete eight-view product.
It uses the normative `/v1` operation, import, comparison and review schemas.

The workflow selects an authorized operation explicitly, imports declared baseline
and candidate separately, compares exact IDs, creates a pending review, and approves
or rejects with the loaded `expected_revision`. Import returns one public contract
ID under the current schema; this client does not infer per-operation IDs or select
the first imported operation. Contract grouping and import-selection extensions
remain a backend/contract integration decision.

Authentication comes from the same-origin server's verified session. There are no
identity headers, token inputs, credential storage, mock users or fallback fixtures.
A host must provide the authorized session and same-origin CSRF protection for
JSON writes. The client never stores uploaded raw contents in browser persistence.
The selected File exists in memory until submission; successful import clears it.

On conflict or unavailable state, existing context stays visible and mutations
pause. An explicit review reload fetches the exact comparison and current approved
association. A changed association blocks the stale review; start a new comparison.
Requests abort after 30 seconds, including response body reads; an interrupted write
may already have completed, so reload before retrying. Catalog read failures do not
mark a fresh import draft stale. No mutation is retried automatically. A failed live request never produces fixture
success. Start a new comparison or reselect an operation to reset a failed draft.

The pinned manifest and lockfile use React/ReactDOM 19.3.1, React types 19.3.0,
TypeScript 5.9.3 and esbuild 0.28.2. Use Node 22.23.1. Run `npm ci --ignore-scripts`,
`npm run typecheck`, `npm test`, then `npm run build` inside this directory. The
builder resolves the locked native esbuild platform package directly; missing
platform packages fail rather than triggering installer downloads. No dependency
install scripts are needed. Do not omit optional dependencies.

Build output is `dist/index.html`, `/assets/main.js`, `/assets/main.css` and linked
license notices. Source entry is `src/main.tsx`, using automatic JSX transform and
a production React build. No CDN. The host owns same-origin static asset serving,
authentication, security headers and container packaging. Dependency review and
execution evidence are in the ignored task record. Repository ignore rules exclude `node_modules/` and `dist/` from source integration.

Focused dependency-free checks (Node with native TypeScript stripping):

```sh
node --experimental-strip-types --test tests/domain.test.ts tests/api.test.ts
```

These verify exact identity/revision invariants, safe failures, same-origin request
shape, no conflict retry, and response guards. They are not rendered interaction,
integration, browser compatibility, security audit or full mandatory-gate evidence.
On Node 22.23.1, strict typecheck and production build passed, and all twelve
focused tests passed. Lockfile audit reported zero advisories at review time; this
is not a security audit. No rendered browser interactions or live authentication /
API integration have been inspected.
