'use strict';
// Pure source-data transform; __apicontourFlowBridge must be provided lexically
// by a trusted future compiler. No loader, bridge or runtime authority here.
// capture(target) obtains an owned-parent frame for the stock Catch call.
// claim(event) consumes only the current matching event proof before any stock
// property access; arm(target,method,frame) arms only the fixed stock receive;
// apply is a captured Reflect.apply; finish(handle), drop(frame) are nonthrowing
// and idempotent. None of these requirements are established by this module.
const {createHash} = require('node:crypto');
const PIN = 'cc38e231211557d95e68dd7ca3f3845e1715d7129324ce3563a0a5049e323c5a';
function transform(bytes) {
    if (!Buffer.isBuffer(bytes) || createHash('sha256').update(bytes).digest('hex') !== PIN) throw Error('unsupported Flow.js source');
    let source = bytes.toString('utf8');
    if (source.includes('__apicontourFlow')) throw Error('reserved identifier');
    function once(oldText,newText) {
        const pos=source.indexOf(oldText);
        if (pos < 0 || source.indexOf(oldText,pos+oldText.length) >= 0) throw Error('unsupported Flow.js site');
        source=source.slice(0,pos)+newText+source.slice(pos+oldText.length);
    }
    once('                targetCatchNode.receive(errorMessage);', `                const __apicontourFlowCatchFrame = __apicontourFlowBridge.capture(targetCatchNode);
                try {
                    const __apicontourFlowCatchMethod = targetCatchNode.receive;
                    const __apicontourFlowCatchMessage = errorMessage;
                    const __apicontourFlowCatchArmed = __apicontourFlowBridge.arm(targetCatchNode,__apicontourFlowCatchMethod,__apicontourFlowCatchFrame);
                    try { __apicontourFlowBridge.apply(__apicontourFlowCatchMethod,targetCatchNode,[__apicontourFlowCatchMessage]); }
                    finally { __apicontourFlowBridge.finish(__apicontourFlowCatchArmed); }
                } finally { __apicontourFlowBridge.drop(__apicontourFlowCatchFrame); }`);
    once('function deliverMessageToDestination(sendEvent) {', `function deliverMessageToDestination(sendEvent) {
    var __apicontourFlowFrame = __apicontourFlowBridge.claim(sendEvent);
    try {`);
    once('            sendEvent.destination.node.receive(sendEvent.msg);', `            var __apicontourFlowTarget = sendEvent.destination.node;
            var __apicontourFlowMethod = __apicontourFlowTarget.receive;
            var __apicontourFlowMessage = sendEvent.msg;
            var __apicontourFlowArmed = __apicontourFlowBridge.arm(__apicontourFlowTarget,__apicontourFlowMethod,__apicontourFlowFrame);
            try { __apicontourFlowBridge.apply(__apicontourFlowMethod,__apicontourFlowTarget,[__apicontourFlowMessage]); }
            finally { __apicontourFlowBridge.finish(__apicontourFlowArmed); }`);
    once('    }\n}\nfunction handlePreDeliver(flow,sendEvent, reportError) {', '    }\n    } finally { __apicontourFlowBridge.drop(__apicontourFlowFrame); }\n}\nfunction handlePreDeliver(flow,sendEvent, reportError) {');
    return Buffer.from(source,'utf8');
}
module.exports={transform};
