'use strict';
// Fully controlled fake client; no sockets or certificates are opened.
const assert = require('node:assert/strict');
const {EventEmitter} = require('node:events');
const {probe} = require('./probe.js');
function fakeClient(mode) {
  return {request: (_options, callback) => {
    const req = new EventEmitter();
    req.destroy = () => req.emit('error',new Error('closed'));
    req.end = () => {
      if (mode === 'success') {
        const response = new EventEmitter(); response.statusCode=200;
        callback(response);
        response.emit('data', Buffer.from('{"result":"owned-pilot-ok"}'));
        response.emit('end');
      }
      if (mode === 'denied') {
        const response = new EventEmitter(); response.statusCode=503;
        callback(response); response.emit('data', Buffer.from('opaque synthetic failure')); response.emit('end');
      }
      // In stalled mode no headers are ever delivered; only deadline can finish.
    };
    return req;
  }};
}
(async () => {
  const ok=await probe(fakeClient('success'),Buffer.from('ca'),'/pilot',200,'{"result":"owned-pilot-ok"}',100);
  assert.equal(ok.expected_body,true);
  const denied=await probe(fakeClient('denied'),Buffer.from('ca'),'/pilot',[502,503],null,100);
  assert.deepEqual(denied,{status:503,expected_body:true,exception:'none'});
  const start=Date.now();
  const stalled=await probe(fakeClient('stalled'),Buffer.from('ca'),'/pilot',200,'',30);
  assert.equal(stalled.exception,'Deadline');
  assert.equal(stalled.expected_body,false);
  assert.ok(Date.now()-start < 1000);
  process.stdout.write('PASS\n');
})().catch(()=>{process.stderr.write('probe test failed\n');process.exitCode=1;});
