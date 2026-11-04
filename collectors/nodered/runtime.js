'use strict';
// Experimental building block. A trusted, pinned bootstrap must establish the
// exact module/flow profile before this may be used; this file does not do so.
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomBytes } = require('node:crypto');
const { performance } = require('node:perf_hooks');

const KINDS = ['onSend', 'preRoute', 'preDeliver', 'postDeliver', 'onReceive',
    'postReceive', 'onComplete', 'preInstall', 'postInstall', 'preUninstall', 'postUninstall'];
const id = () => randomBytes(16).toString('hex');

function install(hooks, options) {
    const { inbound, requests, maxPending, maxEvents, maxBytes, ttlMs } = options;
    if (!Array.isArray(inbound) || !inbound.length || !Array.isArray(requests) ||
        ![maxPending, maxEvents, maxBytes, ttlMs].every(Number.isSafeInteger) ||
        maxPending < 1 || maxPending > 4096 || maxEvents < 1 || maxEvents > 4096 ||
        maxBytes < 256 || maxBytes > 1048576 || ttlMs < 1 || ttlMs > 60000) {
        throw new Error('unsupported adapter bounds');
    }
    const inboundIds = new Set(inbound), requestIds = new Set(requests);
    if (inboundIds.size !== inbound.length || requestIds.size !== requests.length ||
        [...inboundIds, ...requestIds].some(x => typeof x !== 'string' || x.length > 64)) {
        throw new Error('unsupported adapter profile');
    }
    const als = new AsyncLocalStorage(), pending = new Map(), events = [];
    let valid = true, loss = 0, bytes = 2;
    const now = () => performance.now();
    const lose = () => { loss = Math.min(Number.MAX_SAFE_INTEGER, loss + 1); };
    function invalidate() { if (valid) { valid = false; loss = Math.min(Number.MAX_SAFE_INTEGER, loss + pending.size + 1); pending.clear(); } }
    function record(event) {
        const length = Buffer.byteLength(JSON.stringify(event)) + 1;
        if (events.length >= maxEvents || bytes + length > maxBytes) { lose(); return; }
        bytes += length;
        events.push(Object.freeze(event));
    }
    function sweep() {
        const t = now();
        for (const [key, value] of pending) if (value.deadline <= t) { pending.delete(key); lose(); }
    }
    function safe(fn, done) {
        let continued = false;
        const next = () => { continued = true; done(); };
        try { fn(next); } catch (err) {
            if (continued) throw err;
            invalidate(); done();
        }
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
    const result = () => Object.freeze({ snapshot() { sweep(); return { registryIntact: valid, loss, pending: pending.size,
        events: events.map(e => ({ ...e })) }; }, invalidate });
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
                if (!batch.every(e => e.source && e.source.id === src.id && scrub(e.msg))) { lose(); return als.run(undefined, next); }
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
    add.call(hooks, 'preDeliver.apicontour', function (_event, done) {
        safe(next => {
            sweep();
            const current = als.getStore();
            if (!valid || !current || current.deadline <= now() || pending.size >= maxPending) {
                lose(); return als.run(undefined, next);
            }
            const token = id();
            pending.set(token, { root: current.root, parent: current.activity, deadline: current.deadline });
            als.run({ token }, next);
        }, done);
    });
    add.call(hooks, 'onReceive.apicontour', function (event, done) {
        safe(next => {
            sweep();
            const token = als.getStore()?.token;
            const delivery = token && pending.get(token);
            if (token) pending.delete(token);
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
    } catch (_) {
        // Any partial installation is inert; never export the original methods.
        invalidate();
    }
    return result();
}
module.exports = { install };
