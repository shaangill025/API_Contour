'use strict';
// Run inside each replica with its own mounted credentials. Never print errors or data.
const https = require('node:https');
const fs = require('node:fs');
const key = fs.readFileSync('/pilot/tls/client.key');
const cert = fs.readFileSync('/pilot/tls/client.crt');
const ca = fs.readFileSync('/pilot/ca.crt');
const wrongCA = fs.readFileSync('/pilot/tls/server.crt');
function attempt({name, trust, client, stats=false}) {
  return new Promise((resolve) => {
    let done = false;
    let request;
    const deadline = setTimeout(() => { if (request) request.destroy(); finish(false); }, 4000);
    const finish = (ok) => { if (!done) { done = true; clearTimeout(deadline); resolve(ok); } };
    request = https.request({host:'pilot-destination',port:9443,path:stats?'/control/stats':'/pilot',method:stats?'GET':'POST',
      servername:name,ca:trust,rejectUnauthorized:true,key:client ? key : undefined,
      cert:client ? cert : undefined,headers:stats?{}:{'content-length':'2'}}, (response) => {
      let data=''; response.setEncoding('utf8');
      response.on('data', chunk => { data+=chunk; if (data.length>1024) request.destroy(); });
      response.on('end',()=>finish(response.statusCode===200 && data===(stats?'{"disallowed":0}':'{"result":"owned-pilot-ok"}')));
      response.on('error',()=>finish(false));
    });
    request.on('error',()=>finish(false));
    request.end(stats ? undefined : '{}');
  });
}
(async () => {
  if (process.argv[2] === '--redirect-check' && process.argv.length === 3) {
    if (!(await attempt({name:'pilot-destination',trust:ca,client:true,stats:true}))) throw Error('redirect failed');
  } else {
    if (process.argv.length !== 2) throw Error('invalid mode');
    if (!(await attempt({name:'pilot-destination',trust:ca,client:true}))) throw Error('positive failed');
    if (await attempt({name:'wrong.invalid',trust:ca,client:true})) throw Error('wrong name accepted');
    if (await attempt({name:'pilot-destination',trust:wrongCA,client:true})) throw Error('untrusted server accepted');
    if (await attempt({name:'pilot-destination',trust:ca,client:false})) throw Error('missing client accepted');
  }
  process.stdout.write('PASS\n');
})().catch(()=>{ process.stderr.write('pilot TLS check failed\n'); process.exitCode=1; });
