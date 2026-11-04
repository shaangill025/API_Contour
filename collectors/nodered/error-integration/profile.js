'use strict';
// Owner-supplied bootstrap and this profile are the external trust roots;
// readonly mounts and their hashes are verified by the owned-container driver.
const FILES=Object.freeze({
    '/adapter/error-integration/bootstrap.js':'76ceb52cdd07bc1ef7a28d387529950c8c1577b66027824bad5588f7f4c2e650',
    '/adapter/error-integration/private-runtime.js':'a08b4196175fa02d6211c6ac4b14c9300612fd841f76d2bb7960166ee3b9abea',
    '/adapter/error-integration/lexical-bridge.js':'ec5d7180dd03f0502fa6ab92d2bf07cfedb7982f0d10266d741028900c427d51',
    '/adapter/error-integration/node-source-transform.js':'62c41177fb9a7645627556baeae7dcd960910586e5b3cb44835427763b1fd0f6',
    '/adapter/error-integration/flow-source-transform.js':'4d089d255ef44c3e296d6dff7657013db73db309c0ea5cfa728ec938e63e5819',
    '/fixture/flows-error.json':'5535f836f3603f7d1cfe62066e634539fd2afcfcf7ed34baafbbf2708984b100',
    '/fixture/image-error-fixture.js':'a58179f18e21b1c2f5aa1820838e919ab261116a1dc98d7146ae7a378010141d',
    '/usr/src/node-red/node_modules/@node-red/util/lib/hooks.js':'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf',
    '/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js':'4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be',
    '/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js':'cc38e231211557d95e68dd7ca3f3845e1715d7129324ce3563a0a5049e323c5a',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/05-tls.js':'f258e441f24bd9391da47618399f2d636849c1081274107456d49946c13f801d',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httprequest.js':'074f654014cfaa359a30e4a897c44764ad636c170350bc8222713562bdb89a3b',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httpin.js':'7d91f1053a85fd8c42b6b94ac9960298b5bf6b29435ce1b0b0557195221232a5'
});
const INGRESS_POINT=Object.freeze({node:'in',method:'POST',url:'/run'});
const ENV=new Set(['PATH','HOME','HOSTNAME','LANG','TZ','NODE_OPTIONS','NODE_PATH','NODE_RED_VERSION','NODE_VERSION','FLOWS','YARN_VERSION']);
function validateLaunch(e) {
    if(e.version!=='24.22.1'||e.executable!=='/usr/local/bin/node'||
       ![['/usr/local/bin/node','/fixture/image-error-fixture.js'],['/usr/local/bin/node','/fixture/image-error-fixture.js','negative']].some(a=>JSON.stringify(e.argv)===JSON.stringify(a))||
       JSON.stringify(e.execArgv)!==JSON.stringify(['--require','/adapter/error-integration/bootstrap.js']))return false;
    const x=e.env;
    if(!x||Object.keys(x).some(k=>!ENV.has(k))||(x.NODE_OPTIONS!==undefined&&x.NODE_OPTIONS!=='')||x.NODE_PATH!=='/usr/src/node-red/node_modules'||x.NODE_VERSION!=='24.22.1'||x.NODE_RED_VERSION!=='v5.0.9'||x.FLOWS!=='flows.json'||x.YARN_VERSION!=='1.22.22'||x.PATH!=='/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')return false;
    return Array.isArray(e.cached)&&e.cached.every(x=>x==='/adapter/error-integration/bootstrap.js'||x==='/adapter/error-integration/profile.js');
}
function validateFiles(hashes){return Object.keys(hashes).length===Object.keys(FILES).length&&Object.entries(FILES).every(([file,hash])=>hashes[file]===hash);}
module.exports={FILES,INGRESS_POINT,validateLaunch,validateFiles};
