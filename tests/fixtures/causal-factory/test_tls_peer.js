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
assert.equal(request.calls[1], JSON.stringify('serial'));
