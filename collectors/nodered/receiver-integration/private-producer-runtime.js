'use strict';
// 504-only dormant variant of the 503 producer runtime; 503 bytes remain immutable.
// Quarantined building block: only a trusted initializer may receive control.
// This module does not qualify a loader, profile, hook source, or application.
const { AsyncLocalStorage } = require('node:async_hooks');
const { randomBytes } = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { types } = require('node:util');
const {IncomingMessage}=require('node:http');
const incomingHeaders=Object.getOwnPropertyDescriptor(IncomingMessage.prototype,'headers').get;
const apply=Reflect.apply, splice=Array.prototype.splice;

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
    const als = new AsyncLocalStorage(), pending = new Map(), frames = new Map(), dispatches = new Map(), bindings = new WeakMap(), events = [];
    let valid = true, loss = 0, bytes = 2, producer, receiver, initializing = true;
    const now = () => performance.now();
    const lose = () => { loss = Math.min(Number.MAX_SAFE_INTEGER, loss + 1); };
    function invalidate() { if (valid) { valid = false; loss = Math.min(Number.MAX_SAFE_INTEGER, loss + pending.size + 1); pending.clear(); frames.clear(); dispatches.clear(); if(producer) { try { producer.close(); } catch (_) {} } } }
    function permitted() {
        if (!valid) return false;
        if (!producer) { invalidate(); return false; }
        try { if (producer.gate() === true) return producer.admit() === true; } catch (_) {}
        invalidate(); return false;
    }
    function record(event) {
        if (!permitted()) return false;
        if (producer && (event.kind === 'ROOT_INTENT' || event.kind === 'DELIVERY_INTENT')) {
            try { if (producer.offer(Object.freeze({ ...event })) === false) lose(); } catch (_) { invalidate(); return false; }
            if (!permitted()) return false;
        }
        // Configured producer owns the only event stream; public snapshot is
        // diagnostic-only and cannot be used as a second export channel.
        if (producer) return true;
        const length = Buffer.byteLength(JSON.stringify(event)) + 1;
        if (events.length >= maxEvents || bytes + length > maxBytes) { lose(); return true; }
        bytes += length;
        events.push(Object.freeze(event));
        return true;
    }
    function sweep() {
        const t = now();
        for (const [key, value] of pending) if (value.deadline <= t) { pending.delete(key); lose(); }
        for (const [key, value] of frames) if (value.deadline <= t || !value.target.deref()) { frames.delete(key); lose(); }
        for (const [key, value] of dispatches) if (value.deadline <= t || !value.target.deref()) { dispatches.delete(key); lose(); }
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
            if (!permitted()) return false;
            const rd = Object.getOwnPropertyDescriptor(msg, 'req');
            const req = rd && 'value' in rd && rd.value;
            if (!req || typeof req !== 'object') return false;
            if (!permitted()) return false;
            const method = Object.getOwnPropertyDescriptor(req, 'method');
            if (!permitted()) return false;
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
            if (!permitted()) return false;
            const d = Object.getOwnPropertyDescriptor(msg, name);
            if (!permitted()) return false;
            if (d && (!d.configurable || !('value' in d) || !delete msg[name])) return false;
        }
        if (!permitted()) return false;
        const rd = Object.getOwnPropertyDescriptor(msg, 'req');
        if (!permitted()) return false;
        const req = rd && 'value' in rd && rd.value;
        if (!req || typeof req !== 'object') return false;
        const rawDescriptor=Object.getOwnPropertyDescriptor(req,'rawHeaders');
        if (!permitted()) return false;
        if (rawDescriptor && !('value' in rawDescriptor)) return false;
        const raw=rawDescriptor && rawDescriptor.value;
        if (raw !== undefined) {
            if (!Array.isArray(raw) || types.isProxy(raw) || Object.getPrototypeOf(raw)!==Array.prototype) return false;
            const length=Object.getOwnPropertyDescriptor(raw,'length');
            if (!permitted()) return false;
            if (!length || !('value' in length) || length.value%2!==0 || length.value>16384) return false;
            const names=[];
            for(let i=0;i<length.value;i++) {
                if (!permitted()) return false;
                const d=Object.getOwnPropertyDescriptor(raw,String(i));
                if (!permitted()) return false;
                if(!d || !('value' in d) || typeof d.value!=='string')return false;
                if(i%2===0)names.push(d.value);
            }
            for(let i=names.length-1;i>=0;i--) {
                if (!permitted()) return false;
                if(names[i].toLowerCase().startsWith('x-apicontour-')) apply(splice,raw,[i*2,2]);
            }
        }
        if (!permitted()) return false;
        const headersDescriptor=Object.getOwnPropertyDescriptor(req,'headers');
        if (!permitted()) return false;
        const h=headersDescriptor ? ('value' in headersDescriptor ? headersDescriptor.value : undefined) :
            (req instanceof IncomingMessage && !types.isProxy(req) ? apply(incomingHeaders,req,[]) : undefined);
        if (!h || typeof h !== 'object' || types.isProxy(h)) return false;
        const names=Object.keys(h);
        if (!permitted()) return false;
        for (const name of names) {
            if (!permitted()) return false;
            if (name.toLowerCase().startsWith('x-apicontour-')) {
                const d = Object.getOwnPropertyDescriptor(h, name);
                if (!permitted()) return false;
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
        attachProducer(candidate) {
            if (!initializing || producer || !point || point.node !== 'in' || point.method !== 'POST' || point.url !== '/run' ||
                inboundIds.size !== 1 || !inboundIds.has('in') || !candidate || !Object.isFrozen(candidate)) throw Error('unsupported trusted initializer');
            const methods = ['gate','admit','offer','close'].map(name => Object.getOwnPropertyDescriptor(candidate,name));
            if (methods.some(d => !d || !('value' in d) || typeof d.value !== 'function')) throw Error('unsupported trusted initializer');
            producer=Object.freeze({gate:methods[0].value,admit:methods[1].value,offer:methods[2].value,close:methods[3].value});
        },
        attachReceiver(candidate) {
            if (!initializing || receiver || !candidate || !Object.isFrozen(candidate)) throw Error('unsupported trusted initializer');
            const descriptor=Object.getOwnPropertyDescriptor(candidate,'consume');
            if(!descriptor || !('value' in descriptor) || typeof descriptor.value!=='function') throw Error('unsupported trusted initializer');
            receiver=descriptor.value;
        },
        // Trusted source adapter only: this handle is never attached to a
        // message, node property, options.context, or application value.
        captureDispatch(target) {
            if (!permitted()) return undefined;
            sweep();
            const current=als.getStore();
            if (!current || current.target!==target || !requestIds.has(current.source) ||
                !current.root || !current.activity || current.deadline<=now() ||
                !target || (typeof target!=='object' && typeof target!=='function') ||
                pending.size+frames.size+dispatches.size>=maxPending) { lose(); return undefined; }
            const handle=Object.freeze({});
            dispatches.set(handle,{target:new WeakRef(target),root:current.root,activity:current.activity,deadline:current.deadline});
            return handle;
        },
        dispatchContext(handle,target) {
            if (!permitted()) return undefined;
            sweep();
            const entry=dispatches.get(handle);
            if (!entry || entry.target.deref()!==target || entry.deadline<=now()) return undefined;
            return Object.freeze({root:entry.root,activity:entry.activity,deadline:entry.deadline});
        },
        closeDispatch(handle) { return dispatches.delete(handle); },
        noteDispatchLoss() { lose(); },
        capture(target) {
            if (!permitted()) { lose(); return undefined; }
            sweep();
            const current = als.getStore();
            if (!valid || !target || (typeof target !== 'object' && typeof target !== 'function') ||
                !current || !current.root || !current.activity || current.deadline <= now() ||
                pending.size + frames.size + dispatches.size >= maxPending) { lose(); return undefined; }
            const frame = Object.freeze({});
            frames.set(frame, { target: new WeakRef(target), root: current.root, parent: current.activity, deadline: current.deadline });
            return frame;
        },
        claimDelivery(event) {
            if (!permitted()) { lose(); return undefined; }
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
                if (!permitted()) { lose(); return undefined; }
                const descriptor = dest && Object.getOwnPropertyDescriptor(dest, 'node');
                target = descriptor && 'value' in descriptor && descriptor.value;
            } catch (_) { lose(); return undefined; }
            if (!target || item.target.deref() !== target || !permitted()) { lose(); return undefined; }
            const frame = Object.freeze({});
            frames.set(frame, item);
            return frame;
        },
        cancel(frame) { frames.delete(frame); lose(); },
        bind(frame, target, event, invoke) {
            if (!permitted()) { frames.delete(frame); lose(); return als.run(undefined, invoke); }
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
            if (!permitted()) { lose(); return als.run(undefined, next); }
            sweep();
            if (!valid || !Array.isArray(batch) || types.isProxy(batch)) { lose(); return als.run(undefined,next); }
            const sizeDescriptor=Object.getOwnPropertyDescriptor(batch,'length');
            if (!permitted()) return als.run(undefined,next);
            const size=sizeDescriptor && 'value' in sizeDescriptor && sizeDescriptor.value;
            if (!Number.isSafeInteger(size) || size<1 || size>4096) { lose(); return als.run(undefined,next); }
            const values=[]; let sourceId;
            for (let i=0;i<size;i++) {
                if (!permitted()) return als.run(undefined,next);
                const itemDescriptor=Object.getOwnPropertyDescriptor(batch,String(i));
                if (!permitted()) return als.run(undefined,next);
                const item=itemDescriptor && 'value' in itemDescriptor && itemDescriptor.value;
                if (!item || typeof item!=='object') { lose(); return als.run(undefined,next); }
                const sourceDescriptor=Object.getOwnPropertyDescriptor(item,'source');
                if (!permitted()) return als.run(undefined,next);
                const source=sourceDescriptor && 'value' in sourceDescriptor && sourceDescriptor.value;
                if (!source || typeof source!=='object') { lose(); return als.run(undefined,next); }
                const idDescriptor=Object.getOwnPropertyDescriptor(source,'id');
                if (!permitted()) return als.run(undefined,next);
                const idValue=idDescriptor && 'value' in idDescriptor && idDescriptor.value;
                if (typeof idValue!=='string' || (i && idValue!==sourceId)) { lose(); return als.run(undefined,next); }
                sourceId=idValue;
                if (!permitted()) return als.run(undefined,next);
                const msgDescriptor=Object.getOwnPropertyDescriptor(item,'msg');
                if (!permitted()) return als.run(undefined,next);
                if (!msgDescriptor || !('value' in msgDescriptor)) { lose(); return als.run(undefined,next); }
                values.push(msgDescriptor.value);
            }
            if (inboundIds.has(sourceId)) {
                for (const msg of values) {
                    if (!permitted() || !atPoint(sourceId,msg)) { lose(); return als.run(undefined,next); }
                }
                for (const msg of values) {
                    if (!permitted() || !scrub(msg)) { lose(); return als.run(undefined,next); }
                }
                let received;
                if (receiver) { try { received=receiver(values); } catch (_) { lose(); return als.run(undefined,next); } }
                let root;
                if (received !== undefined) {
                    if (!received || typeof received!=='object' || types.isProxy(received)) { lose(); return als.run(undefined,next); }
                    const status=Object.getOwnPropertyDescriptor(received,'status'), r=Object.getOwnPropertyDescriptor(received,'root'), t=Object.getOwnPropertyDescriptor(received,'ticket');
                    const kind=status && 'value' in status && status.value;
                    if ((kind==='queued'||kind==='dropped') && r && 'value' in r && typeof r.value==='string' && r.value.length===32 && /^[0-9a-f]{32}$/.test(r.value) && (kind==='dropped' ? !t : t && 'value' in t && t.value && typeof t.value==='object' && !types.isProxy(t.value))) {
                        root=r.value; if(kind==='dropped')lose();
                    } else { lose(); return als.run(undefined,next); }
                } else { root=id(); if (!record({ kind: 'ROOT_INTENT', root })) return als.run(undefined, next); }

                if (!permitted()) return als.run(undefined, next);
                return als.run({ root, activity: root, source: sourceId, deadline: now() + ttlMs }, next);
            }
            const current = als.getStore();
            if (!current || current.source !== sourceId || current.deadline <= now()) {
                lose(); return als.run(undefined, next);
            }
            if (!permitted()) return als.run(undefined, next);
            next();
        }, done);
    });
    add.call(hooks, 'preDeliver.apicontour', function (event, done) {
        safe(next => {
            if (!permitted()) { lose(); return als.run(undefined, next); }
            sweep();
            const current = als.getStore();
            const destination = event && Object.getOwnPropertyDescriptor(event, 'destination');
            const dest = destination && 'value' in destination && destination.value;
            if (!permitted()) return als.run(undefined, next);
            const descriptor = dest && Object.getOwnPropertyDescriptor(dest, 'node');
            const target = descriptor && 'value' in descriptor && descriptor.value;
            if (!valid || !current || !current.root || !current.activity || current.deadline <= now() ||
                !target || (typeof target !== 'object' && typeof target !== 'function') ||
                pending.size + frames.size + dispatches.size >= maxPending) {
                lose(); return als.run(undefined, next);
            }
            if (!permitted()) return als.run(undefined, next);
            const token = id();
            pending.set(token, { event: new WeakRef(event), target: new WeakRef(target), root: current.root, parent: current.activity, deadline: current.deadline });
            als.run({ token }, next);
        }, done);
    });
    add.call(hooks, 'onReceive.apicontour', function (event, done) {
        safe(next => {
            if (!permitted()) { lose(); return als.run(undefined, next); }
            sweep();
            const bound = event && bindings.get(event);
            if (bound) bindings.delete(event);
            const destination = event && Object.getOwnPropertyDescriptor(event, 'destination');
            const dest = destination && 'value' in destination && destination.value;
            if (!permitted()) return als.run(undefined, next);
            const node = dest && Object.getOwnPropertyDescriptor(dest, 'node');
            if (!permitted()) return als.run(undefined, next);
            const boundTarget = bound && node && 'value' in node && node.value === bound.target.deref();
            const delivery = boundTarget ? bound : undefined;
            if (!valid || !delivery || delivery.deadline <= now()) { lose(); return als.run(undefined, next); }
            const idDescriptor = Object.getOwnPropertyDescriptor(dest,'id');
            if (!permitted()) return als.run(undefined, next);
            const destinationId = idDescriptor && 'value' in idDescriptor && idDescriptor.value;
            if (typeof destinationId !== 'string') { lose(); return als.run(undefined, next); }
            const activity = id();
            if (!record({ kind: 'DELIVERY_INTENT', root: delivery.root, parent: delivery.parent, activity })) return als.run(undefined, next);
            if (requestIds.has(destinationId)) record({ kind: 'REQUEST_INTENT', root: delivery.root, activity, attempt: id() });
            if (!permitted()) return als.run(undefined, next);
            als.run({ root: delivery.root, activity, source: destinationId, target: node.value, deadline: delivery.deadline }, next);
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
    try { initialize(control); } finally { initializing=false; }
    if (!producer) invalidate();
    } catch (_) {
        // Any partial installation is inert; never export the original methods.
        invalidate();
    }
    return result();
}
module.exports = { install };
