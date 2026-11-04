'use strict';
// Quarantined building block: only a trusted initializer may receive control.
// This module does not qualify a loader, profile, hook source, or application.
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomBytes } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const KINDS = ['onSend', 'preRoute', 'preDeliver', 'postDeliver', 'onReceive',
    'postReceive', 'onComplete', 'preInstall', 'postInstall', 'preUninstall', 'postUninstall'];
const id = () => randomBytes(16).toString('hex');

function install(hooks, options, initialize) {
    if (typeof initialize !== 'function') throw new TypeError('trusted initializer required');
    const { inbound, requests, maxPending, maxEvents, maxBytes, ttlMs, ingressPoint } = options;
    if (!Array.isArray(inbound) || !inbound.length || !Array.isArray(requests) ||
        ![maxPending, maxEvents, maxBytes, ttlMs].every(Number.isSafeInteger) ||
        maxPending < 1 || maxPending > 4096 || maxEvents < 1 || maxEvents > 4096 ||
        maxBytes < 256 || maxBytes > 1048576 || ttlMs < 1 || ttlMs > 60000) {
        throw new Error('unsupported adapter bounds');
    }
    // Unscoped mode exists only for prior white-box tests. Qualified bootstrap
    // supplies its immutable owner-selected point explicitly.
    let point;
    if (ingressPoint !== undefined) {
        if (!ingressPoint || typeof ingressPoint !== 'object' ||
            ![ingressPoint.node, ingressPoint.method, ingressPoint.url].every(x => typeof x === 'string' && x.length > 0 && x.length <= 64) ||
            !inbound.includes(ingressPoint.node)) throw new Error('unsupported ingress point');
        point = Object.freeze({node:ingressPoint.node, method:ingressPoint.method, url:ingressPoint.url});
    }
    const inboundIds = new Set(inbound), requestIds = new Set(requests);
    if (inboundIds.size !== inbound.length || requestIds.size !== requests.length ||
        [...inboundIds, ...requestIds].some(x => typeof x !== 'string' || x.length > 64)) {
        throw new Error('unsupported adapter profile');
    }
    const als = new AsyncLocalStorage(), pending = new Map(), frames = new Map(), bindings = new WeakMap(), events = [];
    let valid = true, loss = 0, bytes = 2;
    const now = () => performance.now();
    const lose = () => { loss = Math.min(Number.MAX_SAFE_INTEGER, loss + 1); };
    function invalidate() { if (valid) { valid = false; loss = Math.min(Number.MAX_SAFE_INTEGER, loss + pending.size + 1); pending.clear(); frames.clear(); } }
    function record(event) {
        const length = Buffer.byteLength(JSON.stringify(event)) + 1;
        if (events.length >= maxEvents || bytes + length > maxBytes) { lose(); return; }
        bytes += length;
        events.push(Object.freeze(event));
    }
    function sweep() {
        const t = now();
        for (const [key, value] of pending) if (value.deadline <= t) { pending.delete(key); lose(); }
        for (const [key, value] of frames) if (value.deadline <= t || !value.target.deref()) { frames.delete(key); lose(); }
    }
    function safe(fn, done) {
        let continued = false;
        const next = () => { continued = true; done(); };
        try { fn(next); } catch (err) {
            if (continued) throw err;
            invalidate(); done();
        }
    }
    function atPoint(source, msg) {
        if (!point) return true;
        try {
            if (source !== point.node || !msg || typeof msg !== 'object') return false;
            const rd = Object.getOwnPropertyDescriptor(msg, 'req');
            const req = rd && 'value' in rd && rd.value;
            if (!req || typeof req !== 'object') return false;
            const method = Object.getOwnPropertyDescriptor(req, 'method');
            const url = Object.getOwnPropertyDescriptor(req, 'url');
            return !!(method && 'value' in method && method.value === point.method &&
                url && 'value' in url && url.value === point.url);
        } catch (_) { return false; }
    }
    // Never remove ordinary application fields. Only these reserved names are
    // controlled by the adapter, with data descriptors to avoid invoking getters.
    function scrub(msg) {
        if (!msg || typeof msg !== 'object') return false;
        for (const name of ['_apicontour', 'apicontour']) {
            const d = Object.getOwnPropertyDescriptor(msg, name);
            if (d && (!d.configurable || !('value' in d) || !delete msg[name])) return false;
        }
        const rd = Object.getOwnPropertyDescriptor(msg, 'req');
        if (!rd || !('value' in rd) || !rd.value) return false;
        const raw = rd.value.rawHeaders;
        if (raw !== undefined) {
            if (!Array.isArray(raw) || raw.length % 2 !== 0) return false;
            for (let i = raw.length - 2; i >= 0; i -= 2) {
                if (typeof raw[i] !== 'string') return false;
                if (raw[i].toLowerCase().startsWith('x-apicontour-')) raw.splice(i, 2);
            }
        }
        const h = rd.value.headers;
        if (!h || typeof h !== 'object') return false;
        for (const name of Object.keys(h)) {
            if (name.toLowerCase().startsWith('x-apicontour-')) {
                const d = Object.getOwnPropertyDescriptor(h, name);
                if (!d || !d.configurable || !('value' in d) || !delete h[name]) return false;
            }
        }
        return true;
    }
    const result = () => Object.freeze({ snapshot() { sweep(); return Object.freeze({ registryIntact: valid, loss, pending: pending.size, frames: frames.size,
        events: Object.freeze(events.map(e => Object.freeze({ ...e }))) }); }, invalidate });
    // The initializer is trusted bootstrap code, never application code. Tokens are
    // opaque identities; target and event are held weakly, never placed in a ledger.
    const control = Object.freeze({
        capture(target) {
            sweep();
            const current = als.getStore();
            if (!valid || !target || (typeof target !== 'object' && typeof target !== 'function') ||
                !current || !current.root || !current.activity || current.deadline <= now() ||
                pending.size + frames.size >= maxPending) { lose(); return undefined; }
            const frame = Object.freeze({});
            frames.set(frame, { target: new WeakRef(target), root: current.root, parent: current.activity, deadline: current.deadline });
            return frame;
        },
        claimDelivery(event) {
            sweep();
            const token = als.getStore()?.token;
            const item = token && pending.get(token);
            if (token) pending.delete(token);
            if (!valid || !item || item.event.deref() !== event || item.deadline <= now()) {
                lose(); return undefined;
            }
            let target;
            try {
                const destination = Object.getOwnPropertyDescriptor(event, 'destination');
                const dest = destination && 'value' in destination && destination.value;
                const descriptor = dest && Object.getOwnPropertyDescriptor(dest, 'node');
                target = descriptor && 'value' in descriptor && descriptor.value;
            } catch (_) { lose(); return undefined; }
            if (!target || item.target.deref() !== target) { lose(); return undefined; }
            const frame = Object.freeze({});
            frames.set(frame, item);
            return frame;
        },
        cancel(frame) { frames.delete(frame); lose(); },
        bind(frame, target, event, invoke) {
            sweep();
            const item = frames.get(frame);
            if (frame) frames.delete(frame);
            if (!valid || !item || item.target.deref() !== target || item.deadline <= now() ||
                !event || (typeof event !== 'object' && typeof event !== 'function') ||
                typeof invoke !== 'function' || bindings.has(event)) {
                lose();
                return als.run(undefined, invoke);
            }
            bindings.set(event, item);
            try { return als.run(undefined, invoke); } finally {
                if (bindings.delete(event)) lose();
            }
        }
    });
    const methods = ['add', 'remove', 'clear', 'trigger', 'has'];
    if (methods.some(name => {
        const descriptor = Object.getOwnPropertyDescriptor(hooks, name);
        return !descriptor || !descriptor.configurable || !('value' in descriptor) ||
            typeof descriptor.value !== 'function';
    }) || KINDS.some(k => hooks.has(k))) { invalidate(); return result(); }
    const add = hooks.add, remove = hooks.remove, clear = hooks.clear;
    try {
    add.call(hooks, 'onSend.apicontour', function (batch, done) {
        safe(next => {
            sweep();
            if (!valid || !Array.isArray(batch) || !batch.length) return next();
            const src = batch[0].source;
            if (src && inboundIds.has(src.id)) {
                if (!batch.every(e => e.source && e.source.id === src.id && atPoint(src.id, e.msg)) ||
                    !batch.every(e => scrub(e.msg))) { lose(); return als.run(undefined, next); }
                const root = id();
                record({ kind: 'ROOT_INTENT', root });
                return als.run({ root, activity: root, source: src.id, deadline: now() + ttlMs }, next);
            }
            const current = als.getStore();
            if (!current || current.source !== (src && src.id) || current.deadline <= now()) {
                lose(); return als.run(undefined, next);
            }
            next();
        }, done);
    });
    add.call(hooks, 'preDeliver.apicontour', function (event, done) {
        safe(next => {
            sweep();
            const current = als.getStore();
            const destination = event && Object.getOwnPropertyDescriptor(event, 'destination');
            const dest = destination && 'value' in destination && destination.value;
            const descriptor = dest && Object.getOwnPropertyDescriptor(dest, 'node');
            const target = descriptor && 'value' in descriptor && descriptor.value;
            if (!valid || !current || !current.root || !current.activity || current.deadline <= now() ||
                !target || (typeof target !== 'object' && typeof target !== 'function') ||
                pending.size + frames.size >= maxPending) {
                lose(); return als.run(undefined, next);
            }
            const token = id();
            pending.set(token, { event: new WeakRef(event), target: new WeakRef(target), root: current.root, parent: current.activity, deadline: current.deadline });
            als.run({ token }, next);
        }, done);
    });
    add.call(hooks, 'onReceive.apicontour', function (event, done) {
        safe(next => {
            sweep();
            const bound = event && bindings.get(event);
            if (bound) bindings.delete(event);
            const destination = event && Object.getOwnPropertyDescriptor(event, 'destination');
            const dest = destination && 'value' in destination && destination.value;
            const node = dest && Object.getOwnPropertyDescriptor(dest, 'node');
            const boundTarget = bound && node && 'value' in node && node.value === bound.target.deref();
            const delivery = boundTarget ? bound : undefined;
            if (!valid || !delivery || delivery.deadline <= now() || !event.destination) {
                lose(); return als.run(undefined, next);
            }
            const activity = id();
            record({ kind: 'DELIVERY_INTENT', root: delivery.root, parent: delivery.parent, activity });
            if (requestIds.has(event.destination.id)) record({ kind: 'REQUEST_INTENT', root: delivery.root, activity, attempt: id() });
            als.run({ root: delivery.root, activity, source: event.destination.id, deadline: delivery.deadline }, next);
        }, done);
    });
    // Later supported registration still executes, but capture fails closed first.
    for (const [name, original] of [['add', add], ['remove', remove], ['clear', clear],
        ['trigger', hooks.trigger], ['has', hooks.has]]) {
        let implementation = name === 'trigger' || name === 'has' ? original :
            function (...args) { invalidate(); return original.apply(this, args); };
        Object.defineProperty(hooks, name, { configurable: false, enumerable: true,
            get() { return implementation; },
            set(replacement) { invalidate(); implementation = replacement; } });
    }
    initialize(control);
    } catch (_) {
        // Any partial installation is inert; never export the original methods.
        invalidate();
    }
    return result();
}
module.exports = { install };
