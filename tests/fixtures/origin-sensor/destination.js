'use strict';
const fs = require('fs');
const https = require('https');
const crypto = require('crypto');
const digest = (data) => crypto.createHash('sha256').update(data).digest('hex');
const expected = process.env.EXPECTED_CLIENT_SHA256;
if (!/^[0-9a-f]{64}$/.test(expected)) throw Error('invalid expected fingerprint');
let pending = new Map();
const server = https.createServer({key:fs.readFileSync('/fixture/destination.key'), cert:fs.readFileSync('/fixture/destination.crt'), ca:fs.readFileSync('/fixture/ca.crt'), requestCert:true, rejectUnauthorized:true}, (req,res) => {
  const peer=req.socket.getPeerCertificate(true);
  if (!req.socket.authorized || !peer.raw || digest(peer.raw)!==expected || req.method!=='POST' || req.url!=='/pilot' || req.headers['x-contour-origin-witness'] !== undefined) { res.writeHead(403); res.end(); return; }
  let size=0, chunks=[];
  req.on('data', b => { size+=b.length; if (size>1024) req.destroy(); else chunks.push(b); });
  req.on('end', () => {
    const body=Buffer.concat(chunks).toString();
    if (req.trailers['x-contour-origin-witness'] !== undefined) { res.writeHead(400); res.end(); return; }
    const name=body === '{"probe":[true]}' ? 'a' : body === '{"probe":{"id":1}}' ? 'b' : null;
    if (name) {
      if (pending.has(name)) { res.writeHead(409); res.end(); return; }
      const timer=setTimeout(() => { pending.delete(name); res.writeHead(504); res.end(); }, 4000);
      pending.set(name,{res,timer});
      if (pending.size === 2) {
        const pair=pending; pending=new Map();
        for (const [key, item] of pair) {
          clearTimeout(item.timer);
          const data=key === 'a' ? '{"id":true}' : '{"quantity":[1]}';
          item.res.writeHead(200,{'content-type':'application/json','content-length':Buffer.byteLength(data)}); item.res.end(data);
        }
        process.stdout.write('PAIR a b\n');
      }
      return;
    }
    if (body !== '{"probe":true}') { res.writeHead(400); res.end(); return; }
    const data='{"id":1,"quantity":2}'; res.writeHead(200,{'content-type':'application/json','content-length':Buffer.byteLength(data)}); res.end(data);
  });
});
server.listen(9444,'127.0.0.1',()=>{process.stdout.write('READY 9444\n');});
// PID 1 must explicitly handle Docker's proxied termination signal.
const stop = () => { for (const item of pending.values()) clearTimeout(item.timer); pending.clear(); server.close(() => process.exit(0)); server.closeAllConnections(); };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
