These sources are qualification-only and are not a production control API.
The fixed destination preserves the real HTTPS destination and capture path.
It exposes a bounded nonce-bound HTTP control only at 127.0.0.1 inside its own
container; it does not accept destinations, raw response bytes or credentials.
The qualification must mount the exact source at original container creation,
include all three scripts in its source closure, and independently verify that
mount and the owned container before/after each barrier. The production static
and managed models must not expose this control socket or silently substitute it.
