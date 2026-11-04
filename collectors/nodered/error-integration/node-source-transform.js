'use strict';
// Source-data artifact only. The caller must bind the free identifier
// __apicontourNodeBridge lexically before compiling the returned bytes. This
// module neither creates that binding nor supplies any authority or loader.
// Required trusted bridge contract: take(kind,target) consumes a handoff;
// arm(kind,target,method,apply,cap) arms only a verified stock method (and,
// for input, the intrinsic Function.prototype.apply), returning a cleanup
// handle; finish(handle) and drop(cap) are idempotent and non-throwing; apply
// is a captured intrinsic Reflect.apply; bind(cap,target,event,invoke) binds
// only the fresh event at the protected hook, isolates unqualified invokes,
// and clears its binding in finally. All bridge operations must be lexical,
// inaccessible to application code, and tolerate synchronous reentrancy.
// This data transform does not establish or verify any of those properties.
const {createHash} = require('node:crypto');
const PIN = '4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be';

function transform(bytes) {
    if (!Buffer.isBuffer(bytes) || createHash('sha256').update(bytes).digest('hex') !== PIN) {
        throw new Error('unsupported Node.js source');
    }
    let source = bytes.toString('utf8');
    if (source.includes('__apicontourNode')) throw new Error('reserved identifier');
    function once(oldText, newText) {
        const at = source.indexOf(oldText);
        if (at < 0 || source.indexOf(oldText, at + oldText.length) >= 0) {
            throw new Error('unsupported Node.js site');
        }
        source = source.slice(0, at) + newText + source.slice(at + oldText.length);
    }
    once('Node.prototype.receive = function(msg) {', `Node.prototype.receive = function(msg) {
    var __apicontourNodeCap = __apicontourNodeBridge.take("receive", this);
    try {`);
    once('    this.emit("input",msg);', `    var __apicontourNodeMethod = this.emit;
    var __apicontourNodeArmed = __apicontourNodeBridge.arm("emit", this, __apicontourNodeMethod, undefined, __apicontourNodeCap);
    try { __apicontourNodeBridge.apply(__apicontourNodeMethod, this, ["input",msg]); }
    finally { __apicontourNodeBridge.finish(__apicontourNodeArmed); }`);
    once('    finally { __apicontourNodeBridge.finish(__apicontourNodeArmed); }\n};', '    finally { __apicontourNodeBridge.finish(__apicontourNodeArmed); }\n    } finally { __apicontourNodeBridge.drop(__apicontourNodeCap); }\n};');
    once('Node.prototype.emit = function(event, ...args) {', `Node.prototype.emit = function(event, ...args) {
    var __apicontourNodeCap = __apicontourNodeBridge.take("emit", this);
    try {`);
    once('        this._emitInput.apply(this,args);', `        var __apicontourNodeMethod = this._emitInput;
        var __apicontourNodeApply = __apicontourNodeMethod.apply;
        var __apicontourNodeArmed = __apicontourNodeBridge.arm("input", this, __apicontourNodeMethod, __apicontourNodeApply, __apicontourNodeCap);
        try { __apicontourNodeBridge.apply(__apicontourNodeApply, __apicontourNodeMethod, [this,args]); }
        finally { __apicontourNodeBridge.finish(__apicontourNodeArmed); }`);
    once('        this._emit.apply(this,arguments);\n    }\n}', '        this._emit.apply(this,arguments);\n    }\n    } finally { __apicontourNodeBridge.drop(__apicontourNodeCap); }\n}');
    once('Node.prototype._emitInput = function(arg) {', `Node.prototype._emitInput = function(arg) {
    var __apicontourNodeCap = __apicontourNodeBridge.take("input", this);
    try {`);
    once('    hooks.trigger("onReceive",receiveEvent,(err) => {', `    var __apicontourNodeTrigger = hooks.trigger;
    var __apicontourNodeCallback = (err) => {`);
    once('        }\n    });\n}\n\n/**\n * An internal reference to the original EventEmitter.removeListener()', '        }\n    };\n    if (__apicontourNodeBridge.trustedHook(hooks, __apicontourNodeTrigger)) {\n        __apicontourNodeBridge.bind(__apicontourNodeCap, this, receiveEvent, () => __apicontourNodeBridge.apply(__apicontourNodeTrigger, hooks, ["onReceive",receiveEvent,__apicontourNodeCallback]));\n    } else {\n        __apicontourNodeBridge.apply(__apicontourNodeTrigger, hooks, ["onReceive",receiveEvent,__apicontourNodeCallback]);\n    }\n    } finally { __apicontourNodeBridge.drop(__apicontourNodeCap); }\n}\n\n/**\n * An internal reference to the original EventEmitter.removeListener()');
    return Buffer.from(source, 'utf8');
}
module.exports = {transform};
