'use strict';
// Synthetic in-memory EventEmitter peer; no socket/network or authority.
const assert=require('node:assert/strict'),{EventEmitter}=require('node:events'),net=require('node:net'),fs=require('node:fs');
const vector=JSON.parse(fs.readFileSync(__dirname+'/../receiver504-bootstrap/vector.json','utf8'));
const descriptor=Object.freeze(JSON.parse(vector.canonical));
const original=net.Socket;let latest;
class Socket extends EventEmitter {
 constructor(){super();this.writes=[];this.destroyed=false;latest=this;}
 write(b,cb){this.writes.push(Buffer.from(b));if(cb)cb();return true;}
 destroy(){if(!this.destroyed){this.destroyed=true;this.emit('close');}}
}
net.Socket=Socket;
const permit=require('../../../collectors/nodered/receiver-integration/private-owner-permit-504');
function start(options={}){const p=permit.create({fd:4,descriptor,...options});p.ready.catch(()=>{});return [p,latest];}
function response(request,epoch=BigInt(descriptor.epoch),duration=1000){const r=Buffer.alloc(152);r.write('CRP2');request.copy(r,4,4);r.writeBigUInt64BE(epoch,140);r.writeUInt32BE(duration,148);return r;}
function sleep(ms){return new Promise(resolve=>setTimeout(resolve,ms));}
(async()=>{
 assert.throws(()=>permit.create({fd:4,descriptor:{...descriptor}}));
 const [p,s]=start();const request=s.writes[0];assert.equal(request.length,140);assert.equal(request.subarray(0,4).toString(),'CQP2');assert.equal(request.readBigUInt64BE(68),1n);assert.equal(request.subarray(108).toString('hex'),descriptor.receiver_enrollment_commitment);
 const reply=response(request);s.emit('data',reply.subarray(0,1));s.emit('data',reply.subarray(1,79));s.emit('data',reply.subarray(79));await p.ready;
 const a=p.authority();assert.equal(a.tenant_id,descriptor.tenant);assert.equal(a.gateway_id,descriptor.gateway_id);assert.equal(a.gateway_generation,descriptor.gateway_generation);assert.equal(a.gateway_backend_leaf,descriptor.gateway_backend_leaf);assert.equal(a.receiver_runtime_id,descriptor.runtime);assert.equal(a.receiver_session_epoch,descriptor.epoch);assert.equal(a.receiver_backend_leaf,descriptor.server_leaf);assert.equal(a.epoch,BigInt(descriptor.epoch));
 let closes=0;const resource={close(){closes++;}};p.bind({producer:resource,exporter:resource,signer:{sign:x=>x,close(){closes++;}}});assert.throws(()=>p.bind({producer:resource,exporter:resource,signer:{sign:x=>x}}));p.close();p.close();assert.equal(closes,3);assert.equal(p.authority(),undefined);assert(s.destroyed);
 for(const mutate of [r=>r.write('CRP1'),r=>r[4]^=1,r=>r[36]^=1,r=>r[68]^=1,r=>r[76]^=1,r=>r[108]^=1,r=>r.writeBigUInt64BE(1n,140),r=>r.writeUInt32BE(0,148),r=>r.writeUInt32BE(1001,148)]){
  const [item,sock]=start();const r=response(sock.writes[0]);mutate(r);sock.emit('data',r);await assert.rejects(item.ready);assert.equal(item.authority(),undefined);assert(sock.destroyed);
 }
 const [trailing,t]=start();t.emit('data',Buffer.concat([response(t.writes[0]),Buffer.from([0])]));await assert.rejects(trailing.ready);
 const [failure,fsock]=start();let closed=0;const f={close(){closed++;}};failure.bind({producer:f,exporter:f,signer:{sign:x=>x,close(){closed++;}}});const bad=response(fsock.writes[0]);bad.write('CRP1');fsock.emit('data',bad);await assert.rejects(failure.ready);failure.close();assert.equal(closed,3);
 const [unsolicited,us]=start();us.emit('data',response(us.writes[0]));await unsolicited.ready;us.emit('data',response(us.writes[0]));assert.equal(unsolicited.authority(),undefined);
 const [late,l]=start();l.emit('data',response(l.writes[0],BigInt(descriptor.epoch),1));await sleep(5);assert.equal(late.authority(),undefined);
 const [replay,rs]=start();const first=response(rs.writes[0]);rs.emit('data',first);await replay.ready;await sleep(300);assert.equal(rs.writes.length,2);rs.emit('data',first);assert.equal(replay.authority(),undefined);assert(rs.destroyed);
 const controller=new AbortController();const [cancel,c]=start({signal:controller.signal});controller.abort();await assert.rejects(cancel.ready);assert(c.destroyed);
 const [ended,e]=start();e.emit('end');await assert.rejects(ended.ready);assert(e.destroyed);
 const [timeout,ts]=start();await assert.rejects(timeout.ready);assert(ts.destroyed);
 net.Socket=original;console.log('receiver 504 private permit synthetic stream tests passed');
})().catch(()=>{net.Socket=original;console.error('receiver 504 private permit tests failed');process.exitCode=1;}).finally(()=>{net.Socket=original;});
