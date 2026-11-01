'use strict';
const fs=require('fs'), http=require('http'), tls=require('tls');
const [mode, port, forged]=process.argv.slice(2);
function fail(){ process.exitCode=1; }
if (mode==='ready') {
  const s=require('net').connect(Number(port),'127.0.0.1',()=>{s.end();process.stdout.write('READY\n');}); s.setTimeout(2000,()=>s.destroy());s.on('error',fail);
} else if (mode==='normal' || mode==='spoof' || mode==='xfcc' || mode==='connection') {
  const r=http.get({host:'127.0.0.1',port:Number(port),path:'/trigger?mode='+mode,timeout:6000},res=>{let data='';res.on('data',b=>{data+=b;if(data.length>4096)r.destroy();});res.on('end',()=>{if(res.statusCode!==200||data!== '{"id":1,"quantity":2}')return fail();process.stdout.write('OK\n');});});r.on('error',fail);r.on('timeout',()=>r.destroy());
} else if (mode==='duplicate' || mode==='wrong-forwarder') {
  const conn=tls.connect({host:'127.0.0.1',port:Number(port),servername:mode==='duplicate'?'pilot-destination':'native-gateway.test',ca:fs.readFileSync('/fixture/ca.crt'),cert:fs.readFileSync('/fixture/client.crt'),key:fs.readFileSync('/fixture/client.key'),rejectUnauthorized:true});
  let data='',secure=false;conn.setTimeout(6000,()=>conn.destroy());
  conn.on('secureConnect',()=>{secure=true;const payload=mode==='duplicate'?'POST /pilot HTTP/1.1\r\nHost: pilot-destination\r\nContent-Type: application/json\r\nContent-Length: 14\r\nConnection: close\r\nx-contour-origin-witness: '+forged+'\r\nX-Contour-Origin-Witness: '+forged+'\r\n\r\n{"probe":true}':'POST /pilot HTTP/1.1\r\nHost: native-gateway.test\r\nContent-Length: 2\r\n\r\n{}';conn.write(payload);});
  conn.on('data',b=>{data+=b;if(data.length>4096)conn.destroy();});
  conn.on('end',()=>{if(mode==='wrong-forwarder' ? !secure || data.length!==0 : !data.startsWith('HTTP/1.1 200 ') || !data.endsWith('{\"id\":1,\"quantity\":2}')) return fail();process.stdout.write('OK\n');});
  conn.on('error',()=>{if(mode==='wrong-forwarder' && secure)process.stdout.write('OK\n');else fail();});
} else fail();
