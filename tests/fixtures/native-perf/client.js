'use strict';
// Run inside the same Node-RED replica in every lane. Only timings and counts leave it.
const fs = require('node:fs');
const https = require('node:https');
const {performance} = require('node:perf_hooks');
const n = Number(process.argv[2]);
if (!Number.isSafeInteger(n) || n < 1 || n > 10000 || process.argv.length !== 3) process.exit(2);
const ca = fs.readFileSync('/pilot/ca.crt');
const fixture = JSON.parse(fs.readFileSync('/pilot/privacy.json'));
const expected = Buffer.from(JSON.stringify({result:fixture.response}));
async function request() {
  return new Promise(resolve => {
    const start = performance.now(); let complete = false; let req;
    const finish = outcome => {
      if (complete) return;
      complete = true; clearTimeout(timer);
      resolve({outcome, ms:performance.now()-start});
    };
    const timer = setTimeout(() => { finish('timeout'); if (req) req.destroy(); }, 4000);
    try {
      req = https.request({host:'localhost',port:1880,path:'/pilot',method:'GET',servername:'localhost',ca,
        rejectUnauthorized:true,agent:false,headers:{connection:'close'}}, res => {
        let body = Buffer.alloc(0);
        res.on('data', chunk => {
          if (body.length + chunk.length > 1024) { finish('error'); req.destroy(); }
          else body = Buffer.concat([body,chunk]);
        });
        res.on('end', () => finish(res.statusCode === 200 && body.equals(expected) ? 'success' : 'error'));
        res.on('error', () => finish('error'));
      });
      req.on('error', () => finish('error'));
      req.end();
    } catch (_) { finish('error'); }
  });
}
(async () => {
  const start = performance.now(), samples = []; let errors = 0, timeouts = 0;
  for (let i=0; i<n; i++) {
    const result = await request();
    if (result.outcome === 'success') samples.push(result.ms);
    else if (result.outcome === 'timeout') timeouts++;
    else errors++;
  }
  process.stdout.write(JSON.stringify({attempted:n,success_ms:samples,errors,timeouts,elapsed_ms:performance.now()-start})+'\n');
})().catch(() => { process.stderr.write('screen client failed\n'); process.exitCode=1; });
