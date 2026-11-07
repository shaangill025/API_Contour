These are public, synthetic test-only RSA keys and certificates. They have no
security value and must never be trusted or used in a deployment. The CA private
key was generated temporarily and discarded; it is not in the repository.

Generation recipe (OpenSSL installed on the fixture author machine; OpenSSL is
not invoked by Rust tests): create a temporary 2048-bit RSA CA with critical
CA:TRUE, keyCertSign,cRLSign, SHA-256 and 3650-day validity; create three
independent 2048-bit RSA keypairs and CSRs with subjects synthetic-product,
synthetic-export, synthetic-server; sign with that CA for 3650 days using
CA:FALSE, digitalSignature,keyEncipherment, clientAuth for product/export and
serverAuth plus SAN DNS:causal-node for server. Discard the CA private key,
CSRs and extension files. The certs use the generator host actual creation time;
tests use production wall-clock validation and intentionally fail after expiry.
