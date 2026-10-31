'use strict';
// Runs in a disposable pinned Node container sharing only the edge network namespace.
const http=require('node:http');
const req=http.get('http://127.0.0.1:9901/stats?format=json&filter=cluster.upstream.ssl.fail_verify',res=>{
  if (res.statusCode!==200) { res.resume(); process.exitCode=1; return; }
  let data='';
  res.on('data',chunk=>{ data+=chunk; if(data.length>16384) req.destroy(); });
  res.on('end',()=>{ try {
    const stats=JSON.parse(data).stats;
    const result={};
    for(const entry of stats) {
      if (entry.name==='cluster.upstream.ssl.fail_verify_san' || entry.name==='cluster.upstream.ssl.fail_verify_error') result[entry.name]=entry.value;
    }
    process.stdout.write(JSON.stringify(result)+'\n');
  } catch (_) { process.exitCode=1; } });
});
req.setTimeout(5000,()=>req.destroy());
req.on('error',()=>{ process.exitCode=1; });
