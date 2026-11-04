'use strict';
// Trusted composition building block, not an application API or loader. The
// initializer must retain both returned objects solely in compiler closures.
// Call only after authenticating source, hook registry, methods, and identities.
const apply = Reflect.apply;
const intrinsicApply = Function.prototype.apply;
function initialize(control, stock, hooks, trigger, allowedNodes) {
    if (!control || typeof control.claimDelivery !== 'function' || typeof control.bind !== 'function' ||
        typeof control.cancel !== 'function' || typeof control.capture !== 'function' || !stock || !hooks || typeof trigger !== 'function' ||
        !Array.isArray(allowedNodes) || !allowedNodes.length ||
        allowedNodes.some(n => !n || (typeof n !== 'object' && typeof n !== 'function')) ||
        ['receive','emit','input'].some(k => typeof stock[k] !== 'function')) throw Error('unsupported trusted bridge profile');
    const allowed = new WeakSet(allowedNodes);
    const methods = {receive:stock.receive, emit:stock.emit, input:stock.input};
    const active = new WeakSet();
    let pending;
    function take(kind,target) {
        const handoff=pending; pending=undefined;
        return handoff && handoff.kind===kind && handoff.target===target &&
            allowed.has(target) && active.has(handoff.frame) ? handoff.frame : undefined;
    }
    function arm(kind,target,method,applyMethod,frame) {
        if (!frame || !active.has(frame) || !allowed.has(target) || method!==methods[kind] ||
            !Object.prototype.hasOwnProperty.call(methods,kind) ||
            (kind==='input' && applyMethod!==intrinsicApply) || pending) return undefined;
        return pending={kind,target,frame};
    }
    function finish(handle) { if (handle && pending===handle) pending=undefined; }
    function drop(frame) { if (frame && active.delete(frame)) control.cancel(frame); }
    const node=Object.freeze({apply,take,arm,finish,drop,
        trustedHook(object,method) { return object===hooks && method===trigger; },
        bind(frame,target,event,invoke) {
            if (frame && active.has(frame) && allowed.has(target)) {
                active.delete(frame); return control.bind(frame,target,event,invoke);
            }
            drop(frame); return control.bind(undefined,target,event,invoke);
        }
    });
    const flow=Object.freeze({apply,
        claim(event) { const frame=control.claimDelivery(event); if (frame) active.add(frame); return frame; },
        capture(target) { const frame=control.capture(allowed.has(target) ? target : undefined); if (frame) active.add(frame); return frame; },
        arm(target,method,frame) { return arm('receive',target,method,undefined,frame); },
        finish,drop
    });
    return Object.freeze({node,flow});
}
module.exports={initialize};
