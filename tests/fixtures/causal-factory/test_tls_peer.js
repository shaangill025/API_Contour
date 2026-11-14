'use strict';
// VM isolates the client modes from real networking and records every file read.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, 'tls_peer.js'), 'utf8');

function exercise(mode) {
  const reads = [], calls = [];
  const fixtureFs = {readFileSync(name) {
    reads.push(name);
    if (!['/fixture/ca.pem', '/fixture/client.pem', '/fixture/client.key'].includes(name)) {
      throw Error('unexpected server material');
    }
    return Buffer.from('fixture');
  }};
  const fixtureHttps = {request(options) {
    calls.push(options);
    return {setTimeout() {}, on() {}, end(body) { calls.push(body); }};
  }};
  const context = {
    require(name) {
      if (name === 'node:fs') return fixtureFs;
      if (name === 'node:https') return fixtureHttps;
      if (name === 'node:crypto') return require(name);
      throw Error('unexpected module');
    },
    process: {argv: ['node', 'tls_peer.js', mode], env: {}},
    Buffer,
    setInterval() {},
  };
  vm.runInNewContext(source, context, {filename: 'tls_peer.js', timeout: 1000});
  return {reads, calls};
}

const waiting = exercise('wait');
assert.deepEqual(waiting.reads, []);
assert.deepEqual(waiting.calls, []);
const request = exercise('request');
assert.deepEqual(request.reads, ['/fixture/ca.pem', '/fixture/client.pem', '/fixture/client.key']);
assert.equal(request.calls[0].hostname, 'causal-node');
assert.equal(request.calls[0].port, 1880);
assert.equal(request.calls[0].path, '/run');
assert.equal(request.calls[0].method, 'POST');
assert.equal(request.calls[0].rejectUnauthorized, true);
assert.equal(request.calls[0].headers['content-type'], 'text/plain');
assert.equal(request.calls[1], 'serial');

// In inbox mode the independent business peer never binds the exporter port;
// it emits only a domain-separated digest, never the marker value.
{
  const ports=[], handlers=[], output=[];
  const peer=Buffer.from('fixture-client');
  const fingerprint=require('node:crypto').createHash('sha256').update(peer).digest('hex');
  const context={
    require(name) {
      if (name === 'node:fs') return {readFileSync(){return Buffer.from('fixture');}};
      if (name === 'node:crypto') return require(name);
      if (name === 'node:https') return {createServer(_options,handler) {
        handlers.push(handler); return {listen(port){ports.push(port);}};
      }};
      throw Error('unexpected module');
    },
    process:{argv:['node','tls_peer.js','business'],env:{PRODUCT_LEAF:fingerprint,EXPORT_LEAF:'b'.repeat(64)},stdout:{write(value){output.push(value);}}},
    Buffer,
  };
  vm.runInNewContext(source,context,{filename:'tls_peer.js',timeout:1000});
  assert.deepEqual(ports,[9443]);
  const marker='private-fixture-marker';
  handlers[0]({socket:{authorized:true,getPeerCertificate(){return {raw:peer};}},method:'POST',url:'/pilot',
    headers:{'x-apicontour-causal-marker':marker},resume(){}},{writeHead(){},end(){},destroy(){throw Error('rejected');}});
  const expected=require('node:crypto').createHash('sha256').update('apicontour/causal-marker-wire/1\n').update(marker,'ascii').digest('hex');
  assert.deepEqual(output,['MARKER '+expected+'\n']);
  assert(!output[0].includes(marker));
}
