'use strict';
// Nonsecret fixture-only process; does not launch the proxy or confer authority.
const allowed=['FLOWS','HOME','HOSTNAME','LANG','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','PATH','TZ','YARN_VERSION'];
const result={env_keys:Object.keys(process.env).sort().join(',')===allowed.join(','),exec_path:process.execPath==='/usr/local/bin/node',exec_argv:process.execArgv.length===0,pipe_tty:!process.stdin.isTTY&&!process.stdout.isTTY&&!process.stderr.isTTY,argv_probe:JSON.stringify(process.argv)==='["/usr/local/bin/node","/work/tests/fixtures/receiver504-actual/proxy-preflight.js"]',bootstrap:'ok'};
try{require('/adapter/receiver-integration/private-bootstrap-504');}catch(error){result.bootstrap=error&&error.code==='MODULE_NOT_FOUND'?'module_not_found':error&&error.code==='ERR_DLOPEN_FAILED'?'dlopen':error instanceof SyntaxError?'syntax':'other';}
process.stdout.write(JSON.stringify(result)+'\n');
