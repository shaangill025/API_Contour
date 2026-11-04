'use strict';
// This fixture runs only inside the pinned Node-RED image under an owned container.
// The transport is loopback HTTP: this tests ownership, not the HTTPS profile.
const assert = require('node:assert/strict');
const http = require('node:http');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createRequire } = require('node:module');
const redRequire = createRequire('/usr/src/node-red/node_modules/node-red/red.js');
const hooks = redRequire('@node-red/util').hooks;
// The owned container must preload this bootstrap before the fixture or Node-RED.
const adapter = require('/adapter/bootstrap.js');
const express = redRequire('express');
const RED = redRequire('node-red');
const temp = fs.mkdtempSync(path.join(os.tmpdir(), 'causal-fixture-'));
const app = express();
const server = http.createServer(app);
const arrivals = [];
const destinationStatuses = [];
const destination = http.createServer((req, res) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
        const status = body === 'retry:1' ? 503 : 200;
        arrivals.push(body); destinationStatuses.push(status);
        res.statusCode = status; res.end('ok');
    });
});
for (const s of [server, destination]) {
    s.requestTimeout = 2000;
    s.headersTimeout = 2000;
    s.setTimeout(2000, socket => socket.destroy());
}
// Includes startup, requests, shutdown and any unexpected unresolved resource.
const watchdog = setTimeout(() => {
    process.stderr.write('FAIL: fixture deadline exceeded\n');
    server.closeAllConnections(); destination.closeAllConnections();
    fs.rmSync(temp, { recursive:true, force:true });
    process.exit(1);
}, 15000);
function listen(s) { return new Promise((resolve, reject) => { s.once('error', reject); s.listen(0, '127.0.0.1', resolve); }); }
function close(s) { return new Promise((resolve, reject) => {
    if (!s.listening) return resolve();
    s.close(err => err ? reject(err) : resolve());
    s.closeIdleConnections();
}); }
function diagnostic(stage, status = null) {
    const snap = adapter.snapshot();
    const count = kind => snap.events.filter(e => e.kind === kind).length;
    process.stdout.write(JSON.stringify({ stage, status, registryIntact:snap.registryIntact,
        loss:snap.loss, pending:snap.pending, events:snap.events.length,
        roots:count('ROOT_INTENT'), deliveries:count('DELIVERY_INTENT'),
        requests:count('REQUEST_INTENT') }) + '\n');
}
function request(port, body) {
    return new Promise((resolve, reject) => {
        const req = http.request({ host:'127.0.0.1', port, path:'/run', method:'POST',
            headers:{'content-type':'text/plain', 'x-apicontour-spoof':'fake'} }, res => {
            res.on('error', reject);
            res.on('aborted', () => reject(new Error('response aborted')));
            res.resume(); res.on('end', () => resolve(res.statusCode));
        });
        req.setTimeout(2000, () => req.destroy(new Error('request timeout')));
        req.on('error', reject); req.end(body);
    });
}
async function main() {
    await listen(destination);
    process.env.CAUSAL_FIXTURE_URL = `http://127.0.0.1:${destination.address().port}/`;
    diagnostic('before-init');
    RED.init(server, { userDir:temp, flowFile:'/fixture/flows.json', httpAdminRoot:false,
        httpNodeRoot:'/', credentialSecret:false, functionExternalModules:false,
        logging:{console:{level:'off', metrics:false, audit:false}} });
    diagnostic('after-init');
    app.use(RED.httpNode);
    // start() resolves before flow activation in the pinned runtime. Subscribe
    // before starting and bound the wait; never probe a route before readiness.
    const flowReady = new Promise(resolve => {
        const timer = setTimeout(() => { RED.events.removeListener('flows:started', ready); resolve(false); }, 6000);
        function ready() { clearTimeout(timer); resolve(true); }
        RED.events.once('flows:started', ready);
    });
    await RED.start();
    diagnostic('runtime-started');
    const ready = await flowReady;
    diagnostic(ready ? 'flows-ready' : 'flows-timeout');
    assert(ready, 'flows did not become ready');
    await listen(server);
    const firstStatus = await request(server.address().port, 'first');
    diagnostic('first-response', firstStatus);
    assert.equal(firstStatus, 200);
    // The driver has sent only the first request at this point; bind the opaque
    // first root independently of payload or adapter-provided message labels.
    const firstRoots = adapter.snapshot().events.filter(e => e.kind === 'ROOT_INTENT');
    assert.equal(firstRoots.length, 1);
    const firstRoot = firstRoots[0].root;
    const secondStatus = await request(server.address().port, 'second');
    diagnostic('second-response', secondStatus);
    assert.equal(secondStatus, 200);
    const secondRoots = adapter.snapshot().events.filter(e => e.kind === 'ROOT_INTENT');
    assert.equal(secondRoots.length, 2);
    assert(secondRoots[0].root === firstRoot, 'first root changed');
    const secondRoot = secondRoots[1].root;
    assert(firstRoot !== secondRoot, 'root IDs were reused');
    const deadline = Date.now() + 4000;
    while (arrivals.length < 4 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(arrivals, ['second', 'second', 'first', 'first']);
    const snap = adapter.snapshot();
    assert.equal(snap.registryIntact, true);
    assert.equal(snap.loss, 0);
    const roots = snap.events.filter(e => e.kind === 'ROOT_INTENT');
    assert.equal(roots.length, 2);
    assert(roots[0].root !== roots[1].root, 'root IDs were reused');
    const intentRoots = snap.events.filter(e => e.kind === 'REQUEST_INTENT').map(e => e.root);
    // Arrival bodies are independently observed by the destination. This
    // checks the matching root order only; an intent is not a wire witness.
    assert(intentRoots.length === 4 && intentRoots.every((root, i) =>
        root === [secondRoot, secondRoot, firstRoot, firstRoot][i]), 'intent root order');
    for (const root of roots) {
        const attempts = snap.events.filter(e => e.kind === 'REQUEST_INTENT' && e.root === root.root);
        assert.equal(attempts.length, 2);
        assert(attempts[0].activity !== attempts[1].activity, 'activity IDs were reused');
    }
    async function chainCase(label, expectedStatuses) {
        const before = arrivals.length;
        const priorRoots = adapter.snapshot().events.filter(e => e.kind === 'ROOT_INTENT');
        const status = await request(server.address().port, label);
        diagnostic(label === 'serial' ? 'serial-response' : 'retry-response', status);
        assert.equal(status, 200);
        const afterRoots = adapter.snapshot().events.filter(e => e.kind === 'ROOT_INTENT');
        assert.equal(afterRoots.length, priorRoots.length + 1);
        const root = afterRoots.at(-1).root;
        assert(priorRoots.every(item => item.root !== root), 'chain root ID reused');
        const end = Date.now() + 3000;
        while (arrivals.length < before + 2 && Date.now() < end) await new Promise(resolve => setTimeout(resolve, 20));
        assert.deepEqual(arrivals.slice(before), [label + ':1', label + ':2']);
        assert.deepEqual(destinationStatuses.slice(before), expectedStatuses);
        const evidence = adapter.snapshot();
        assert.equal(evidence.registryIntact, true);
        assert.equal(evidence.loss, 0);
        const attempts = evidence.events.filter(e => e.kind === 'REQUEST_INTENT' && e.root === root);
        assert.equal(attempts.length, 2);
        assert(attempts[0].activity !== attempts[1].activity, 'chain activity ID reused');
        const second = evidence.events.find(e => e.kind === 'DELIVERY_INTENT' && e.activity === attempts[1].activity);
        assert(second && second.root === root, 'second request has wrong root');
        const intermediate = evidence.events.find(e => e.kind === 'DELIVERY_INTENT' && e.activity === second.parent);
        assert(intermediate && intermediate.root === root && intermediate.parent === attempts[0].activity,
            'serial delivery parent chain');
        return evidence;
    }
    await chainCase('serial', [200, 200]);
    const extended = await chainCase('retry', [503, 200]);
    assert(!JSON.stringify(extended).includes('serial'));
    assert(!JSON.stringify(extended).includes('retry'));
    assert(!JSON.stringify(snap).includes('first'));
    assert(!JSON.stringify(snap).includes('second'));
    assert(!JSON.stringify(snap).includes('spoof'));
    // No delivery token exists in this driver context. Exercise the supported
    // hook directly and require loss without manufacturing a parent; this is a
    // synthetic missing-context probe, not proof of real dispatch cancellation.
    const drainDeadline = Date.now() + 2000;
    while (adapter.snapshot().pending && Date.now() < drainDeadline) await new Promise(resolve => setTimeout(resolve, 20));
    const beforeLoss = adapter.snapshot();
    assert.equal(beforeLoss.pending, 0);
    const deliveries = beforeLoss.events.filter(e => e.kind === 'DELIVERY_INTENT');
    const byActivity = new Map(deliveries.map(e => [e.activity, e]));
    for (const delivery of deliveries) {
        if (delivery.parent !== delivery.root) {
            const parent = byActivity.get(delivery.parent);
            assert(parent && parent.root === delivery.root, 'cross-root or absent delivery parent');
        }
    }
    let continued = false;
    hooks.trigger('onReceive', {destination:{id:'request'}}, () => { continued = true; });
    assert(continued, 'missing-context forwarding');
    const afterLoss = adapter.snapshot();
    assert.equal(afterLoss.registryIntact, true);
    assert(afterLoss.loss > beforeLoss.loss, 'missing context did not report loss');
    assert.equal(afterLoss.events.length, beforeLoss.events.length);
    diagnostic('lost-context');
    const beforeMutation = afterLoss;
    const beforeThird = arrivals.length;
    hooks.add('onReceive.fixtureMutation', function (_event, done) { done(); });
    assert.equal(adapter.snapshot().registryIntact, false);
    assert(adapter.snapshot().loss > beforeMutation.loss);
    const thirdStatus = await request(server.address().port, 'third');
    diagnostic('third-response', thirdStatus);
    assert.equal(thirdStatus, 200);
    const postDeadline = Date.now() + 2000;
    while (arrivals.length < beforeThird + 2 && Date.now() < postDeadline) await new Promise(resolve => setTimeout(resolve, 20));
    assert.deepEqual(arrivals.slice(beforeThird), ['third', 'third']);
    assert.equal(adapter.snapshot().events.length, beforeMutation.events.length);
    process.stdout.write('PASS: pinned runtime fanout, serial, retry, and mutation forwarding\n');
}
async function run() {
    let failure;
    try { await main(); } catch (err) { failure = err; }
    for (const cleanup of [() => RED.stop(), () => close(server), () => close(destination),
        () => fs.rmSync(temp, { recursive:true, force:true })]) {
        try { await cleanup(); } catch (err) { if (!failure) failure = err; }
    }
    clearTimeout(watchdog);
    if (failure) {
        process.stderr.write(`FAIL: ${failure.stack}\n`);
        process.exitCode = 1;
    }
}
run();
