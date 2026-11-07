'use strict';
// Run in the owned replica; the parent releases only after rotation/rollback.
const fs=require('node:fs'),https=require('node:https'),readline=require('node:readline');
const mode=process.argv[2];if(!['request','response'].includes(mode))throw Error('mode');
const expected=Buffer.from('{"result":"owned-pilot-ok"}'),prefix=Buffer.from('{"result":');
let responseSeen=false,done=false,control;
function fail(){if(done)return;done=true;process.stderr.write('DIAG fixture\n');process.exitCode=1;req.destroy();}
const req=https.request({host:'pilot-gateway',port:9443,servername:'pilot-destination',path:'/pilot',method:'POST',ca:fs.readFileSync('/pilot/ca.crt'),cert:fs.readFileSync('/pilot/tls/client.crt'),key:fs.readFileSync('/pilot/tls/client.key'),rejectUnauthorized:true,headers:{'content-type':'application/json',...(mode==='response'?{'x-fixture-stream':'response'}:{})}},res=>{
 if(res.statusCode!==200)return fail();let parts=[],length=0;
 res.on('data',b=>{length+=b.length;if(length>128)return fail();parts.push(b);let current=Buffer.concat(parts);if(mode==='response'&&!responseSeen&&current.length>=prefix.length){if(!current.subarray(0,prefix.length).equals(prefix))return fail();responseSeen=true;process.stdout.write('RESPONSE_PREFIX\n');}});
 res.on('error',fail);res.on('end',()=>{if(done)return;if(!Buffer.concat(parts).equals(expected)||(mode==='response'&&!responseSeen))return fail();done=true;if(control)control.close();process.stdout.write('PASS\n');});
});
req.on('error',fail);req.setTimeout(30000,fail);
if(mode==='request'){
 req.write('{"probe":');process.stdout.write('CLIENT_WRITTEN\n');
 control=readline.createInterface({input:process.stdin});control.on('line',line=>{if(line!=='RELEASE_REQUEST'||done)return fail();req.end('true}');});
}else req.end('{"probe":true}');
