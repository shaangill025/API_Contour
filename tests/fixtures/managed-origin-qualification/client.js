'use strict';
const fs=require('node:fs'),https=require('node:https'),readline=require('node:readline');
const mode=process.argv[2],nonce=process.argv[3];
if(!['request','response'].includes(mode)||!/^[0-9a-f]{32}$/.test(nonce||''))process.exit(1);
const expected=Buffer.from('{"result":"owned-pilot-ok"}'),prefix=Buffer.from('{"result":');
let seen=false,done=false,control;
function fail(kind){if(done)return;done=true;process.stderr.write('DIAG '+kind+'\n');process.exitCode=1;req.destroy();}
const req=https.request({host:'pilot-gateway',port:9443,servername:'pilot-destination',path:'/pilot',method:'POST',ca:fs.readFileSync('/pilot/ca.crt'),cert:fs.readFileSync('/pilot/tls/client.crt'),key:fs.readFileSync('/pilot/tls/client.key'),rejectUnauthorized:true,headers:{'content-type':'application/json','x-managed-qual-mode':mode,'x-managed-qual-nonce':nonce}},res=>{
 if(res.statusCode!==200)return fail('STATUS');let parts=[],length=0;
 res.on('data',b=>{length+=b.length;if(length>128)return fail('BODY_LIMIT');parts.push(b);const current=Buffer.concat(parts);if(mode==='response'&&!seen&&current.length>=prefix.length){if(!current.subarray(0,prefix.length).equals(prefix))return fail('PREFIX');seen=true;process.stdout.write('RESPONSE_PREFIX\n');}});
 res.on('error',()=>fail('RESPONSE_ERROR'));res.on('aborted',()=>fail('RESPONSE_ABORTED'));
 res.on('end',()=>{if(done)return;if(!Buffer.concat(parts).equals(expected)||(mode==='response'&&!seen))return fail('BODY_MISMATCH');done=true;if(control)control.close();process.stdout.write('PASS\n');});
});
req.on('error',()=>fail('REQUEST_ERROR'));req.setTimeout(30000,()=>fail('TIMEOUT'));
if(mode==='request'){
 req.write('{"probe":');process.stdout.write('CLIENT_WRITTEN\n');control=readline.createInterface({input:process.stdin});
 control.on('line',line=>{if(line!=='RELEASE_REQUEST'||done)return fail('CONTROL');req.end('true}');});
}else req.end('{"probe":true}');
