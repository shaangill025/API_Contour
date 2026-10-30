'use strict';
// Fixed in-container product probe. It emits status and booleans only.
const https = require('node:https');
const fs = require('node:fs');

function probe(client, ca, path, wantedStatus, wantedBody, timeoutMs) {
  return new Promise((resolve) => {
    let done = false;
    let req;
    const finish = (result) => { if (!done) { done = true; clearTimeout(timer); resolve(result); } };
    const timer = setTimeout(() => {
      finish({status:null, expected_body:false, exception:'Deadline'});
      if (req) req.destroy();
    }, timeoutMs);
    try {
      req = client.request({host:'localhost',port:1880,path,method:'GET',servername:'localhost',ca,
        rejectUnauthorized:true,headers:{connection:'close'}}, (response) => {
        let body=Buffer.alloc(0);
        response.on('data', chunk => {
          if (body.length + chunk.length > 1024) {
            req.destroy();
            finish({status:response.statusCode, expected_body:false, exception:'BodyLimit'});
          } else { body=Buffer.concat([body,chunk]); }
        });
        response.on('end', () => finish({status:response.statusCode,
          expected_body:response.statusCode===wantedStatus && body.equals(Buffer.from(wantedBody)),exception:'none'}));
        response.on('error', () => finish({status:response.statusCode,expected_body:false,exception:'ResponseError'}));
      });
      req.on('error', () => finish({status:null,expected_body:false,exception:'RequestError'}));
      req.end();
    } catch (_) { finish({status:null,expected_body:false,exception:'RequestError'}); }
  });
}
module.exports={probe};
if (require.main === module) {
  const mode=process.argv[2];
  const cases={normal:[200,'{"result":"owned-pilot-ok"}'],redirect:[302,'{"result":"redirect"}'],
    'wrong-name':[502,'{"error":"upstream_unavailable"}'],'wrong-ca':[502,'{"error":"upstream_unavailable"}']};
  if (!Object.hasOwn(cases,mode) || process.argv.length!==3) process.exit(2);
  const ca=fs.readFileSync('/pilot/ca.crt');
  (async () => {
    const result=await probe(https,ca,'/pilot',...cases[mode],4000);
    const admin=await probe(https,ca,'/flows',200,'',4000);
    process.stdout.write(JSON.stringify({status:result.status,expected_body:result.expected_body,
      exception:result.exception,admin_status:admin.status,admin_exception:admin.exception})+'\n');
  })().catch(()=>{process.stderr.write('pilot probe failed\n');process.exitCode=1;});
}
