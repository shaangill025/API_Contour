# Synthetic receiver issuer qualification

The fixed issuer scenario runs inside the existing owned SQL28 reader fixture
only after its original reader, role, closure and revocation checks. It creates
a separate synthetic instance, source, lifecycle and runtime; appends a new
signed policy revision under the collector guard; and uses fresh ephemeral
Ed25519 keys and signed envelopes. The fixed probe reads a bounded private JSON
input over stdin and prints only a fixed pass or fail line.

The scenario checks a committed receiver-profile session, generic 504 refusal,
501 and 503 refusal by the dedicated issuer, and peer, signature, scope, expiry,
role and original-deadline negatives. It verifies the committed session nonce,
epoch, exact manifest and policy bytes independently through SQL. The receipt
is synthetic database/TLS evidence, not peer possession, process identity,
deployment, factory or permit authority.

In-flight cancellation and unknown commit are not covered by this scenario;
they require separately reviewed deterministic barriers and are not in its
receipt. Runtime execution, independent review and actual resource cleanup must
succeed before reporting a pass.

The dedicated issuer's live 504 session also enters the separately owned
SQL20 event-writer login through the 504 inbox. A canonical root batch is
submitted after wrong-role, wrong-peer, wrong-scope and expired-deadline
denials. The probe checks that an exact retry returns the same receipt and
acceptance time with duplicate status. Independent SQL verifies the committed
canonical bytes, digest, receipt integrity, root event and the single-batch
quota increase. This remains synthetic database/TLS evidence; it does not
prove a production receiver, registered peer or request.
