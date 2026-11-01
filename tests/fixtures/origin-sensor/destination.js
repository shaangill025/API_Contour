'use strict';
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const digest = (data) => crypto.createHash('sha256').update(data).digest('hex');
const expected = process.env.EXPECTED_CLIENT_SHA256;
if (!/^[0-9a-f]{64}$/.test(expected)) throw Error('invalid expected fingerprint');
const server = https.createServer({key:fs.readFileSync('/fixture/destination.key'), cert:fs.readFileSync('/fixture/destination.crt'), ca:fs.readFileSync('/fixture/ca.crt'), requestCert:true, rejectUnauthorized:true}, (req,res) => {
  const peer=req.socket.getPeerCertificate(true);
  if (!req.socket.authorized || !peer.raw || digest(peer.raw)!==expected || req.method!=='POST' || req.url!=='/pilot' || req.headers['x-contour-origin-witness'] !== undefined) { res.writeHead(403); res.end(); return; }
  let size=0, chunks=[];
  req.on('data', b => { size+=b.length; if (size>1024) req.destroy(); else chunks.push(b); });
  req.on('end', () => {
    if (Buffer.concat(chunks).toString() !== '{"probe":true}' || req.trailers['x-contour-origin-witness'] !== undefined) { res.writeHead(400); res.end(); return; }
    const data='{"id":1,"quantity":2}'; res.writeHead(200,{'content-type':'application/json','content-length':Buffer.byteLength(data)}); res.end(data);
  });
});
server.listen(9444,'127.0.0.1',()=>{process.stdout.write('READY 9444\n');});
