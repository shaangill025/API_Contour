'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const path = require('node:path');
const { FILES, validateLaunch, validateFiles } = require('../../../collectors/nodered/profile');
const valid = () => ({ version:'24.22.1', executable:'/usr/local/bin/node',
    argv:['/usr/local/bin/node', '/fixture/image-fixture.js'],
    execArgv:['--require', '/adapter/bootstrap.js'],
    env:{ NODE_OPTIONS:'', NODE_PATH:'/usr/src/node-red/node_modules', NODE_VERSION:'24.22.1',
        NODE_RED_VERSION:'v5.0.9', FLOWS:'flows.json', YARN_VERSION:'1.22.22',
        PATH:'/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' },
    cached:['/adapter/bootstrap.js', '/adapter/profile.js'] });
assert(validateLaunch(valid()));
for (const suffix of [[], ['negative']]) {
    const tls = valid(); tls.argv = ['/usr/local/bin/node', '/fixture/image-tls-fixture.js', ...suffix];
    assert(validateLaunch(tls));
}
const invalidTls = valid(); invalidTls.argv = ['/usr/local/bin/node', '/fixture/image-tls-fixture.js', 'other'];
assert.equal(validateLaunch(invalidTls), false);
assert(validateFiles({ ...FILES }));
const sha = file => crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
assert.equal(sha(path.join(__dirname, 'flows-tls.json')), FILES['/fixture/flows-tls.json']);
assert.equal(sha(path.join(__dirname, 'image-tls-fixture.js')), FILES['/fixture/image-tls-fixture.js']);
assert.equal(sha(path.join(__dirname, 'flows.json')), FILES['/fixture/flows.json']);
assert.equal(sha(path.join(__dirname, 'image-fixture.js')), FILES['/fixture/image-fixture.js']);
assert.equal(sha(path.join(__dirname, '../../../collectors/nodered/runtime.js')), FILES['/adapter/runtime.js']);
assert.equal(sha(process.argv[2]), FILES['/usr/src/node-red/node_modules/@node-red/util/lib/hooks.js']);
for (const mutate of [
    v => v.version = '24.22.0',
    v => v.executable = '/tmp/node',
    v => v.argv.push('--inspect'),
    v => v.argv[1] = '/fixture/other.js',
    v => v.execArgv.push('--require', '/tmp/extra.js'),
    v => v.execArgv[0] = '--import',
    v => v.env.NODE_OPTIONS = '--require /tmp/extra.js',
    v => v.env.NODE_PATH += ':/data/node_modules',
    v => v.env.NODE_RED_VERSION = 'v5.0.8',
    v => v.env.LD_PRELOAD = '/tmp/extra.so',
    v => v.env.NODE_COMPILE_CACHE = '/tmp/cache',
    v => v.cached.push('/tmp/previous-module.js'),
]) {
    const candidate = valid(); mutate(candidate); assert.equal(validateLaunch(candidate), false);
}
for (const name of Object.keys(FILES)) {
    const changed = { ...FILES, [name]:'0'.repeat(64) };
    assert.equal(validateFiles(changed), false);
    delete changed[name]; assert.equal(validateFiles(changed), false);
}
assert.equal(validateFiles({ ...FILES, '/fixture/extra':'0'.repeat(64) }), false);
// This process is intentionally not the exact image entrypoint/profile. A
// failed bootstrap exposes only explicit loss, without touching the dispatcher.
const blocked = require('../../../collectors/nodered/bootstrap');
assert.deepEqual(blocked.snapshot(), {registryIntact:false, loss:1, pending:0, events:[]});
const moduleCopy = {exports:{}};
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), { module:moduleCopy,
    exports:moduleCopy.exports, require() { return {debug(){}}; }, Error, Promise });
let forwarded = false;
moduleCopy.exports.trigger('onReceive', {}, () => { forwarded = true; });
assert(forwarded);
process.stdout.write('PASS: fixed launch/profile rejects unsupported input with explicit loss and forwarding\n');
