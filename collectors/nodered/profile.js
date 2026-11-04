'use strict';
// Immutable owned test profile, not a production deployment policy.
const FILES = Object.freeze({
    '/fixture/flows-tls.json': '5535f836f3603f7d1cfe62066e634539fd2afcfcf7ed34baafbbf2708984b100',
    '/fixture/image-tls-fixture.js': '6269da9c33a67e771677cebaa167e17b50b94e25ee52206d603c84fc51034848',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/05-tls.js': 'f258e441f24bd9391da47618399f2d636849c1081274107456d49946c13f801d',
    '/fixture/flows.json': '28e4cd692dd590b04ae039f470c5b51200823c942bd4cfbe8820428bc87f37f1',
    '/fixture/image-fixture.js': 'b0249a0271b61fe18210fbf8ac2d85e29e06e62ebc311808788d85676679a5e3',
    '/adapter/runtime.js': 'c1fe53a956b693f4be5c60ee88588b0d290937fa57f7089110c469c0961c06e4',
    '/usr/src/node-red/node_modules/@node-red/util/lib/hooks.js': 'e7d1e0496b5399458de55bc9b8ea59e6741869db33cdced0f03ec798c6fa6fcf',
    '/usr/src/node-red/node_modules/@node-red/runtime/lib/nodes/Node.js': '4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be',
    '/usr/src/node-red/node_modules/@node-red/runtime/lib/flows/Flow.js': 'cc38e231211557d95e68dd7ca3f3845e1715d7129324ce3563a0a5049e323c5a',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httprequest.js': '074f654014cfaa359a30e4a897c44764ad636c170350bc8222713562bdb89a3b',
    '/usr/src/node-red/node_modules/@node-red/nodes/core/network/21-httpin.js': '7d91f1053a85fd8c42b6b94ac9960298b5bf6b29435ce1b0b0557195221232a5',
});
const ALLOWED_ENV = new Set(['PATH', 'HOME', 'HOSTNAME', 'LANG', 'TZ',
    'NODE_OPTIONS', 'NODE_PATH', 'NODE_RED_VERSION', 'NODE_VERSION', 'FLOWS', 'YARN_VERSION']);
function validateLaunch(evidence) {
    if (evidence.version !== '24.22.1' || evidence.executable !== '/usr/local/bin/node' ||
        ![ ['/usr/local/bin/node', '/fixture/image-fixture.js'],
            ['/usr/local/bin/node', '/fixture/image-tls-fixture.js'],
            ['/usr/local/bin/node', '/fixture/image-tls-fixture.js', 'negative']
        ].some(argv => JSON.stringify(evidence.argv) === JSON.stringify(argv)) ||
        JSON.stringify(evidence.execArgv) !== JSON.stringify(['--require', '/adapter/bootstrap.js'])) return false;
    const env = evidence.env;
    if (!env || Object.keys(env).some(key => !ALLOWED_ENV.has(key)) ||
        (env.NODE_OPTIONS !== undefined && env.NODE_OPTIONS !== '') ||
        env.NODE_PATH !== '/usr/src/node-red/node_modules' ||
        env.NODE_VERSION !== '24.22.1' || env.NODE_RED_VERSION !== 'v5.0.9' ||
        env.FLOWS !== 'flows.json' || env.YARN_VERSION !== '1.22.22' ||
        env.PATH !== '/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin') return false;
    return Array.isArray(evidence.cached) && evidence.cached.every(
        name => name === '/adapter/bootstrap.js' || name === '/adapter/profile.js');
}
function validateFiles(hashes) {
    return Object.keys(hashes).length === Object.keys(FILES).length &&
        Object.entries(FILES).every(([file, hash]) => hashes[file] === hash);
}
module.exports = { FILES, validateLaunch, validateFiles };
