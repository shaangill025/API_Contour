'use strict';
process.on('uncaughtException', () => { process.stderr.write('FAIL phase=unexpected\n'); process.exit(1); });
process.on('unhandledRejection', () => { process.stderr.write('FAIL phase=unexpected\n'); process.exit(1); });
// Runs only in an owned, pinned Node-RED image; no synthetic IncomingMessage.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const { performance } = require('node:perf_hooks');
const { createRequire } = require('node:module');
const redRequire = createRequire('/usr/src/node-red/node_modules/node-red/red.js');
const RED = redRequire('node-red');
const express = redRequire('express');
const hooks = redRequire('@node-red/util').hooks;
const baseApi = require('../../../collectors/nodered/error-integration/private-handoff');
const rootApi = require('../../../collectors/nodered/receiver-integration/private-root-handoff');
const incoming = require('../../../collectors/nodered/receiver-integration/private-incoming');
const bindingFixture = require('../../../docs/specification/fixtures/causal-evidence-v1.json')[0];
const binding = bindingFixture.body;
const epoch = BigInt(binding.receiver_session_epoch);
const material = path.join(__dirname, '../causal-receiver-material');
const read = name => fs.readFileSync(path.join(material, name));
const ca = read('ca.pem'), cert = read('server.pem'), key = read('server.key');
const clientCert = read('product.pem'), clientKey = read('product.key');
const fingerprint = pem => crypto.createHash('sha256').update(new crypto.X509Certificate(pem).raw).digest('hex');
const auth = () => ({ allowed:true, epoch, deadline:performance.now()+60000 });
const scope = () => ({ allowed:true, deadline:performance.now()+60000,
    tenant_id:binding.tenant_id, gateway_id:binding.gateway_id,
    gateway_generation:binding.gateway_generation, receiver_runtime_id:binding.receiver_runtime_id,
    receiver_session_epoch:binding.receiver_session_epoch,
    gateway_backend_leaf:fingerprint(clientCert), receiver_backend_leaf:fingerprint(cert) });
const base = baseApi.create({ tenantId:binding.tenant_id, runtimeId:binding.receiver_runtime_id,
    epoch, authority:auth, maxBatchEvents:8, maxBatchBytes:4096, queueBytes:8192, queueTtlMs:10000 });
const roots = rootApi.create({ base, authority:auth, tenantId:binding.tenant_id,
    runtimeId:binding.receiver_runtime_id, epoch, queueTtlMs:10000 });
const app = express();
const records = new Map(), byRequest = new WeakMap();
const held = [];
let phase = 'setup', failure = false, receiver, redInitAttempted = false;
function check(fn) { try { fn(); } catch (_) { failure = true; } }
function scrubbed(req) {
    for (const view of [req.headers, req.headersDistinct]) {
        assert(view && typeof view === 'object');
        assert(!Object.keys(view).some(name => name.toLowerCase().startsWith('x-apicontour-')));
    }
    assert(!req.rawHeaders.some((value, i) => i % 2 === 0 && value.toLowerCase().startsWith('x-apicontour-')));
}
receiver = incoming.create({ producer:roots.producer, authority:scope, app(req,res) {
    check(() => {
        const label = req.headers['x-fixture-case'];
        assert(['first','second','duplicate'].includes(label));
        assert(!records.has(label));
        assert(req.socket.authorized === true);
        scrubbed(req);
        const record = { req, appCount:1, inbound:0, deliveries:[], root:undefined, cloneChecked:false };
        records.set(label, record); byRequest.set(req, record);
    });
    // Keep both authenticated valid requests live before allowing either into Express.
    if (req.headers['x-fixture-case'] !== 'duplicate') {
        held.push(() => app(req,res));
        if (held.length === 2) for (const resume of held.splice(0)) resume();
    } else app(req,res);
} });
const server = https.createServer({ ca, cert, key, requestCert:true, rejectUnauthorized:true }, receiver.handler);
server.requestTimeout = 3000; server.headersTimeout = 3000;
server.setTimeout(3000, socket => socket.destroy());
const watchdog = setTimeout(() => {
    process.stderr.write('FAIL phase=deadline\n');
    server.closeAllConnections(); process.exit(1);
}, 20000);
const flow = [
    { id:'tab', type:'tab', label:'receiver identity', disabled:false },
    { id:'in', type:'http in', z:'tab', url:'/run', method:'post', upload:false,
      wires:[['one','two','response']] },
    { id:'one', type:'function', z:'tab', func:'return null;', outputs:1, wires:[[]] },
    { id:'two', type:'function', z:'tab', func:'return null;', outputs:1, wires:[[]] },
    { id:'response', type:'http response', z:'tab', statusCode:'200', headers:{}, wires:[] }
];
const temp = fs.mkdtempSync('/data/receiver-identity-');
const flowFile = path.join(temp, 'flows.json');
fs.writeFileSync(flowFile, JSON.stringify(flow), { mode:0o600 });
function listen() { return new Promise((resolve,reject) => {
    server.once('error', reject); server.listen(0, '127.0.0.1', resolve);
}); }
function close() { return new Promise(resolve => {
    if (!server.listening) return resolve();
    server.close(resolve); server.closeAllConnections();
}); }
function request(label, duplicate=false) { return new Promise((resolve,reject) => {
    const headers = ['host','receiver.example.test','x-fixture-case',label,
        'x-apicontour-causal-binding',bindingFixture.canonical,'x-apicontour-extra','discard'];
    if (duplicate) headers.push('X-APIContour-Causal-Binding',bindingFixture.canonical);
    const req = https.request({ host:'127.0.0.1', port:server.address().port, servername:'receiver.example.test',
        ca, cert:clientCert, key:clientKey, rejectUnauthorized:true, method:'POST', path:'/run', headers }, res => {
        res.on('error', reject); res.on('aborted', () => reject(Error('aborted')));
        res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.setTimeout(3000, () => req.destroy(Error('timeout'))); req.end();
}); }
async function main() {
    phase = 'init';
    assert.equal(process.version, 'v24.22.3');
    assert.equal(require('/usr/src/node-red/node_modules/node-red/package.json').version, '5.0.9');
    redInitAttempted = true;
    RED.init(server, { userDir:temp, flowFile, httpAdminRoot:false, httpNodeRoot:'/',
        credentialSecret:false, functionExternalModules:false,
        externalModules:{autoInstall:false,palette:{allowInstall:false}},
        logging:{console:{level:'off',metrics:false,audit:false}} });
    app.use(RED.httpNode);
    hooks.add('onSend.fixtureIdentity', (batch,done) => {
        check(() => {
            if (!Array.isArray(batch) || !batch.length || batch[0].source.id !== 'in') return;
            const req = batch[0].msg.req;
            const record = byRequest.get(req);
            assert(record); assert.strictEqual(req, record.req); record.inbound++;
            assert(batch.every(event => event.source.id === 'in' && event.msg.req === req));
            scrubbed(req);
            const cloned = RED.util.cloneMessage(batch[0].msg);
            assert.notStrictEqual(cloned, batch[0].msg); assert.strictEqual(cloned.req, req);
            record.cloneChecked = true;
            const result = receiver.consume(batch.map(event => event.msg));
            if (req.headers['x-fixture-case'] === 'duplicate') assert.equal(result, undefined);
            else {
                assert(result && result.status === 'queued');
                assert.equal(roots.producer.root(result.ticket), result.root);
                record.root = result.root;
            }
        });
        done();
    });
    hooks.add('preDeliver.fixtureIdentity', (event,done) => {
        check(() => {
            if (!event.source || event.source.id !== 'in') return;
            const record = byRequest.get(event.msg.req);
            assert(record); assert.strictEqual(event.msg.req, record.req);
            assert(['one','two','response'].includes(event.destination.id));
            record.deliveries.push({ id:event.destination.id, msg:event.msg });
        });
        done();
    });
    const started = new Promise(resolve => {
        const timer = setTimeout(() => { RED.events.removeListener('flows:started', ready); resolve(false); }, 6000);
        function ready() { clearTimeout(timer); resolve(true); }
        RED.events.once('flows:started', ready);
    });
    await RED.start();
    assert(await started);
    assert.equal(server.listenerCount('request'),1);
    assert.strictEqual(server.listeners('request')[0],receiver.handler);
    await listen();
    phase = 'concurrent';
    assert.deepEqual(await Promise.all([request('first'),request('second')]), [200,200]);
    phase = 'rejection'; assert.equal(await request('duplicate',true), 200);
    const deadline = Date.now()+3000;
    while ([...records.values()].some(r => r.deliveries.length < 3) && Date.now() < deadline)
        await new Promise(resolve => setTimeout(resolve, 20));
    phase = 'assertions'; assert.equal(failure,false); assert.equal(records.size,3);
    for (const record of records.values()) {
        assert.equal(record.appCount,1); assert.equal(record.inbound,1); assert(record.cloneChecked);
        assert.deepEqual(record.deliveries.map(x => x.id).sort(), ['one','response','two']);
        assert(new Set(record.deliveries.map(x => x.msg)).size > 1);
    }
    assert.notStrictEqual(records.get('first').req, records.get('second').req);
    assert.notEqual(records.get('first').root, records.get('second').root);
    assert.equal(records.get('duplicate').root,undefined);
}
(async () => {
    try { await main(); } catch (_) { failure = true; }
    receiver.close(); roots.close();
    try { if (redInitAttempted) await RED.stop(); } catch (_) { failure = true; }
    try { await close(); } catch (_) { failure = true; }
    try { fs.rmSync(temp,{recursive:true,force:true}); } catch (_) { failure = true; }
    clearTimeout(watchdog);
    if (failure) { process.stderr.write(`FAIL phase=${phase}\n`); process.exitCode = 1; }
    else process.stdout.write('PASS phase=identity counts=3,3,3\n');
})();
