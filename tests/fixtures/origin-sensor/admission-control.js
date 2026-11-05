'use strict';
// One bounded, mutually authenticated synthetic OriginV2 request.
const https = require('https');
const fs = require('fs');
const crypto = require('crypto');
const port = Number(process.argv[2]);
if (!Number.isInteger(port) || port < 1 || port > 65535) process.exit(1);
const body = fs.readFileSync('/fixture/control.json');
if (!body.length || body.length > 1048576) process.exit(1);
const request = https.request({host:'127.0.0.1', port, servername:'localhost', path:'/v2/batches', method:'POST',
  ca:fs.readFileSync('/fixture/ca.crt'), cert:fs.readFileSync('/fixture/http-client.crt'),
  key:fs.readFileSync('/fixture/http-client.key'), rejectUnauthorized:true, timeout:8000,
  headers:{'content-type':'application/json','content-length':body.length,'connection':'close'}}, response => {
  let chunks = [], size = 0;
  response.on('data', chunk => { size += chunk.length; if (size > 65536) request.destroy(); else chunks.push(chunk); });
  response.on('end', () => {
    try {
      const result = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (response.statusCode === 200 && ['accepted','duplicate'].includes(result.status) &&
          typeof result.batch_id === 'string' && typeof result.receipt_id === 'string' && typeof result.accepted_at === 'string') {
        const digest = crypto.createHash('sha256').update(JSON.stringify([result.batch_id,result.receipt_id,result.accepted_at])).digest('hex');
        process.stdout.write(`CONTROL 200 ${result.status} false ${digest}\n`);
      } else if (typeof result.code === 'string' && /^[a-z_]{1,64}$/.test(result.code) && typeof result.retryable === 'boolean') {
        process.stdout.write(`CONTROL ${response.statusCode} ${result.code} ${result.retryable} -\n`);
      } else process.exitCode = 1;
    } catch (_) { process.exitCode = 1; }
  });
});
request.on('timeout', () => request.destroy());
request.on('error', () => { process.exitCode = 1; });
request.end(body);
