# Authenticated-database authority snapshots

`AuthorityReadRequest::new` checks trusted-server tenant/collector syntax and a
nonempty unique list of at most500 canonical UUID sources before DB contact.
Request construction does not authenticate or enroll a collector.

`ConnectedDatabase::read_authority` (or deadline-shortening `_until`) holds the
existing collector lock and tenant context. It verifies enabled/nonrevoked current
signed policy with fresh DB time and returns exact unchanged envelope bytes plus
DB-derived source/workload/technique/profile bindings. Signed bytes are at most1MiB;
metadata-first logical aggregate accounting is at most16MiB, with at most500
bindings and128 bounded profiles each. These are logical bounds, not RSS limits.
Cancellation/deadline/uncertain rollback invalidate the connection; ordinary
rejection can reuse it only after confirmed rollback and empty tenant context.

The sealed `AuthorityRead` is a server-side snapshot for already operator-enrolled
collectors. `checked_at` precedes transaction cleanup and response transit. A
future client must account for that elapsed time from request start and perform
full current policy/source admission. It is not a response-receipt online grant,
does not extend the signed lease, and does not close cached-startup/enrollment gaps.
Challenge-bound HTTP transport and monotonic client lease handling are separate work.

Required restricted-login TLS PostgreSQL evidence is appended to
`python3 scripts/test-postgres-tls.py --authority`; existing cases and240s bound
remain intact. Fixture keys, credentials and bindings are synthetic and owned.
