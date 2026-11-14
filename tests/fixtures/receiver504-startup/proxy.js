'use strict';
// Offline synthetic framing only; not an owned process/FD/TLS qualification.
const assert=require('node:assert/strict'),fs=require('node:fs');
const proxy=require('../../../collectors/nodered/receiver-integration/private-launch-proxy-504');
const vector=JSON.parse(fs.readFileSync(__dirname+'/../receiver504-bootstrap/vector.json','utf8'));
const raw=Buffer.from(vector.canonical),head=Buffer.alloc(8);head.write('CLB2');head.writeUInt32BE(raw.length,4);
const payload=Buffer.concat([head,raw,Buffer.alloc(32,7)]);assert.equal(proxy.inspectBootstrap(payload).identity,vector.identity);
const old=Buffer.from(payload);old.write('CLB1');assert.throws(()=>proxy.inspectBootstrap(old));
const sent=proxy.frame(66,payload),got=[];let failed=0;const decoder=new proxy.Decoder((kind,bytes)=>got.push([kind,Buffer.from(bytes)]),()=>failed++);
for(const byte of sent)decoder.push(Buffer.from([byte]));decoder.end();assert.equal(failed,0);assert.equal(got.length,1);assert.equal(got[0][0],66);assert(got[0][1].equals(payload));
const other=Buffer.from(sent);other.write('CBP1');const bad=new proxy.Decoder(()=>assert.fail(),()=>failed++);bad.push(other);assert.equal(failed,1);
console.log('receiver 504 proxy offline frame tests passed');
