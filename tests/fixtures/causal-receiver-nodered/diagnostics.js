'use strict';
const phases = new Set(['imports','pki','handoff','flow-file','init','concurrent','rejection','assertions','cleanup','deadline']);
const codes = new Set(['EACCES','EPERM','ENOENT','ENOTDIR','MODULE_NOT_FOUND','ERR_REQUIRE_ESM',
    'ERR_PACKAGE_PATH_NOT_EXPORTED','ERR_UNKNOWN_BUILTIN_MODULE','ERR_DLOPEN_FAILED','ERR_ASSERTION']);
function format(error, phase) {
    let code = 'OTHER';
    try {
        if (error !== null && (typeof error === 'object' || typeof error === 'function')) {
            const descriptor = Object.getOwnPropertyDescriptor(error,'code');
            if (descriptor && Object.hasOwn(descriptor,'value') && typeof descriptor.value === 'string' && codes.has(descriptor.value))
                code = descriptor.value;
        }
    } catch (_) { /* fixed fallback for proxies */ }
    const name = phases.has(phase) ? phase : 'cleanup';
    return `FAIL phase=${name} code=${code}\n`;
}
function state() {
    let failed = false, firstError, firstPhase;
    return Object.freeze({
        mark(error, phase) { if (!failed) { firstError = error; firstPhase = phase; } failed = true; },
        failed() { return failed; },
        diagnostic() { return format(firstError, firstPhase); }
    });
}
module.exports = Object.freeze({format,state});
