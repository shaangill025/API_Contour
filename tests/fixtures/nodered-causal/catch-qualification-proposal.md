# Review-only: direct Catch ownership boundary

Status: BLOCKED for the proposed two-site integration. This is a model and
source analysis, not an implementation or runtime qualification. Existing loss
on direct Catch delivery remains required. Pinned input fingerprints: Flow.js
`cc38e231211557d95e68dd7ca3f3845e1715d7129324ce3563a0a5049e323c5a`;
Node.js `4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be`.

## Source boundary

Pinned Flow.handleError constructs a cloned error message, including error fields,
then calls `targetCatchNode.receive(errorMessage)` directly before `handled = true`
(Flow.js lines 665-693). No normal Flow.send/preDeliver occurs. Pinned
Node.prototype.receive first tests and may write `msg._msgid`, then calls
`this.emit("input",msg)` (Node.js lines 499-507). `emit` delegates input to
`this._emitInput.apply(this,args)` (lines 187-193), and `_emitInput` invokes
`this.metric` before `hooks.trigger("onReceive",receiveEvent,...)` (201-206).
Node._emitInput is an accessible prototype method, not a private dispatcher.

## Candidate and concrete escape

A candidate could hash-check the exact source and transform the specific
Flow.handleError callsite and Node.receive entry before either module loads. A
bootstrap-owned lexical bridge, injected as an unexported closure into both
module wrappers and the adapter, could issue a fresh one-use capability from the
current owned parent for the exact target object. The callsite must resolve and
validate its target and receive function *before* issuance, invoke the original
method with its original receiver, and clear the capability in `finally`; failure,
unknown profile, mutation or no valid parent must forward with explicit loss.
The Node entry consumes the capability before touching the message, validating
exact target and parent; no capability or mint appears on app objects, module
exports, headers or messages. A new private frame per receive prevents a nested
`receive` for another target from inheriting it. This is still insufficient.

After consumption, Node.receive reads `msg._msgid`. A getter can synchronously
call `target._emitInput(otherMessage)` without entering receive. If the consumed
capability is held in an ambient per-receive frame until the normal onReceive
hook, that nested call reaches the hook first and can steal the target-bound
capability, fabricating its parent. Clearing on use means the intended delivery
then loses ownership. `catch-entry-model-offline.js` demonstrates this exact
entry-only model counterexample; it does not execute the Node-RED runtime. A
broad ALS flag, message marker, message identity, target ID or error fields do
not repair the ambiguity. Getter evaluation during error cloning occurs before
issuance and must never inherit a pending capability.

A sound design may need an additional exact `_emitInput`/onReceive callsite
integration or a private continuation passed directly through a qualified path,
with no ambient capability available while application getters, metric hooks,
method lookups, or other reentrant code run. Such changes could alter event
semantics and expand the integration/profile; this proposal does not assert they
are safe or authorized. Simply adding another frame around public `_emitInput`
is not enough, because a caller can invoke that method directly. Any future
loader must keep the bridge lexical and unavailable through `require.cache`,
exports, app objects, symbol properties, and function arguments visible to app
callbacks; account for all module-loading paths, exact hashes, source transforms,
entry replacement and mutation; and fail closed without interrupting forwarding.
No stock transport changes or runtime activation are proposed here.

## Required evidence for any revised design

Show actual pinned-source regression and controlled pinned-image qualification:
two roots concurrently targeting a shared Catch with reversed error completion,
correct distinct parents and downstream continuations; two eligible Catch targets
per error; nested message getters invoking same and different target `receive` and
`_emitInput`; spoofed error/message fields; arbitrary direct receive inside and
outside owned context; synchronous and asynchronous delivery; throwing getters,
cleanup and reentrant finally paths; error loops, exception and cancellation;
registry/method mutation, unsupported source/profile rejection, bounded pending
state and loss, and unchanged ordinary forwarding. An offline model is not proof
of loader isolation or actual hook ordering. Error-path ownership remains required
for the MVP and incomplete until a separately reviewed integration is exercised.
