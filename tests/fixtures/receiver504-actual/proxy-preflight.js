'use strict';
// Nonsecret fixture-only process; does not launch the proxy or confer authority.
const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','YARN_VERSION'];
// Bit positions follow these fixed lists; values are never inspected or emitted.
const knownExtra=['_','QEMU_EXECVE','QEMU_LD_PREFIX','ROSETTA_ADVERTISE_AVX','ROSETTA_LD_LIBRARY_PATH','LD_PRELOAD','LD_LIBRARY_PATH'];
const names=Object.keys(process.env),extras=names.filter(k=>!allowed.includes(k));
const missing_mask=allowed.reduce((mask,k,i)=>mask|(!names.includes(k)?1<<i:0),0);
const known_mask=knownExtra.reduce((mask,k,i)=>mask|(extras.includes(k)?1<<i:0),0);
const extra_count=Math.min(16,extras.length),unknown_extra=extras.some(k=>!knownExtra.includes(k));
const result={env_keys:names.sort().join(',')===allowed.join(','),missing_mask,extra_count,known_mask,unknown_extra,exec_path:process.execPath==='/usr/local/bin/node',exec_argv:process.execArgv.length===0,pipe_tty:!process.stdin.isTTY&&!process.stdout.isTTY&&!process.stderr.isTTY,argv_probe:JSON.stringify(process.argv)==='["/usr/local/bin/node","/work/tests/fixtures/receiver504-actual/proxy-preflight.js"]',bootstrap:'ok'};
try{require('/adapter/receiver-integration/private-bootstrap-504');}catch(error){result.bootstrap=error&&error.code==='MODULE_NOT_FOUND'?'module_not_found':error&&error.code==='ERR_DLOPEN_FAILED'?'dlopen':error instanceof SyntaxError?'syntax':'other';}
process.stdout.write(JSON.stringify(result)+'\n');
