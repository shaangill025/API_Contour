'use strict';
// Uses a private socketpair and a synthetic owner; no listener or database.
const assert=require('node:assert/strict'),{spawnSync}=require('node:child_process'),path=require('node:path');
const child=String.raw`
const {create}=require(process.argv[1]);
const mode=process.argv[2],g=Buffer.alloc(32,1),i=Buffer.alloc(32,2);
const permit=create({fd:Number(process.argv[3]),generation:g,identity:i});
let closed=0,signs=0;
const wrapped=permit.bind({producer:{close(){closed++;}},exporter:{close(){closed++;}},signer:{sign(){signs++;return 'ok';}}});
permit.ready.then(()=>{
 if(!['ok','replay','epoch'].includes(mode))throw Error('unexpected permit');
 if(!permit.authority()||wrapped.sign({})!=='ok')throw Error('bad permit');
 setTimeout(()=>{if(permit.authority()!==undefined||closed!==2)throw Error('owner loss not terminal');try{wrapped.sign({});throw Error('sign accepted');}catch(e){if(e.message==='sign accepted')throw e;}if(signs!==1)throw Error('signer reused');},mode==='ok'?100:600);
},()=>{if(['ok','replay','epoch'].includes(mode))throw Error('valid permit rejected');setTimeout(()=>{if(permit.authority()!==undefined||closed!==2)throw Error('bad failure');},10);});
`;
const python=String.raw`
import socket,subprocess,sys,time
left,right=socket.socketpair()
p=subprocess.Popen(['node','-e',sys.argv[1],sys.argv[2],sys.argv[3],str(right.fileno())],pass_fds=(right.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
right.close()
def readn(n):
 data=b''
 while len(data)<n:
  b=left.recv(n-len(data))
  if not b: break
  data+=b
 return data
r=readn(108)
if len(r)==108:
 reply=bytearray(b'CRP1'+r[4:]+(1).to_bytes(8,'big')+(500).to_bytes(4,'big'))
 if sys.argv[3]=='wrong': reply[76]^=1
 if sys.argv[3]=='oversize': reply=bytearray(b'x'*65536)
 if sys.argv[3]=='late': time.sleep(.6)
 try: left.sendall(reply)
 except BrokenPipeError: pass
 if sys.argv[3] in ('replay','epoch'):
  second=readn(108)
  if len(second)==108:
   retry=bytearray(b'CRP1'+(r if sys.argv[3]=='replay' else second)[4:]+(2 if sys.argv[3]=='epoch' else 1).to_bytes(8,'big')+(500).to_bytes(4,'big'))
   try: left.sendall(retry)
   except BrokenPipeError: pass
left.close()
out,err=p.communicate(timeout=4)
sys.stdout.buffer.write(out);sys.stderr.buffer.write(err);sys.exit(p.returncode)
`;
for(const mode of ['ok','wrong','late','replay','epoch','oversize']){
 const r=spawnSync('python3',['-c',python,child,path.join(__dirname,'private-owner-permit.js'),mode],{encoding:'utf8',timeout:6000});
 assert.equal(r.status,0,mode+': '+r.stderr);
}
process.stdout.write('PASS: private owner channel positive, wrong challenge, late response, oversized response, replay, epoch change and loss\n');
