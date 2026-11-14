'use strict';
// Fixed read-only replica probe: TLS 1.2 completes server-side client auth before
// secureConnect. No HTTP request, key material, certificate or error is printed.
const fs=require('node:fs'),tls=require('node:tls'),crypto=require('node:crypto');
function read(path){
 const fd=fs.openSync(path,fs.constants.O_RDONLY|fs.constants.O_NONBLOCK|fs.constants.O_NOFOLLOW);
 try{const st=fs.fstatSync(fd);if(!st.isFile()||st.nlink!==1||st.size<1||st.size>65536)throw Error('input');const b=Buffer.alloc(65537);let n=0,r;while(n<b.length&&(r=fs.readSync(fd,b,n,b.length-n,null))>0)n+=r;if(n!==st.size||n>65536)throw Error('input');return b.subarray(0,n);}finally{fs.closeSync(fd);}
}
try {
 const socket=tls.connect({host:'pilot-gateway',port:9443,servername:'pilot-destination',
  ca:read('/pilot/ca.crt'),cert:read('/pilot/tls/client.crt'),key:read('/pilot/tls/client.key'),
  rejectUnauthorized:true,minVersion:'TLSv1.2',maxVersion:'TLSv1.2'},()=>{
   try{const cert=socket.getPeerCertificate(true);if(!socket.authorized||!cert.raw){socket.destroy();process.exitCode=1;return;}
   const digest=crypto.createHash('sha256').update(cert.raw).digest('hex');socket.end();process.stdout.write(digest+'\n');}catch(_){socket.destroy();process.exitCode=1;}
  });
 const timer=setTimeout(()=>{socket.destroy();process.exit(1);},7000);
 socket.setTimeout(5000,()=>socket.destroy(new Error('timeout')));
 socket.on('close',()=>clearTimeout(timer));socket.on('error',()=>{process.exitCode=1;});
}catch(_){process.exitCode=1;}
