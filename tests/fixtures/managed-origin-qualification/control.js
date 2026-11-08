'use strict';
// Fixed loopback control, no caller-chosen destination or payload.
const http=require('node:http');
const nonce=process.argv[2],action=process.argv[3];
if(!/^[0-9a-f]{32}$/.test(nonce||'')||!['status','release'].includes(action))process.exit(1);
const req=http.request({host:'127.0.0.1',port:9445,path:'/v1/'+action+'/'+nonce,method:action==='status'?'GET':'POST',timeout:2000},res=>{
 let data='',size=0;res.on('data',x=>{size+=x.length;if(size>32)req.destroy();else data+=x;});
 res.on('end',()=>{if(action==='release'&&res.statusCode===204&&data==='')return process.stdout.write('RELEASED\n');
  if(action==='status'&&res.statusCode===200&&['PENDING','REQUEST_PREFIX','RESPONSE_PREFIX','DONE','ERROR','UNKNOWN'].includes(data))return process.stdout.write(data+'\n');
  process.exitCode=1;});
});
req.on('timeout',()=>req.destroy());req.on('error',()=>{process.exitCode=1});req.end();
