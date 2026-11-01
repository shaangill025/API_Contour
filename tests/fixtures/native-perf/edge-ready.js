'use strict';
// Check only the authenticated downstream edge handshake; emit no TLS details.
const tls=require('node:tls');
const fs=require('node:fs');
const socket=tls.connect({host:'pilot-gateway',port:9443,servername:'pilot-gateway',
  ca:fs.readFileSync('/pilot/ca.crt'),cert:fs.readFileSync('/pilot/tls/client.crt'),
  key:fs.readFileSync('/pilot/tls/client.key'),rejectUnauthorized:true,minVersion:'TLSv1.2'},()=>{
  process.stdout.write('ready\n'); socket.destroy();
});
socket.setTimeout(3000,()=>socket.destroy());
socket.on('error',()=>{});
socket.on('close',()=>process.exit());
