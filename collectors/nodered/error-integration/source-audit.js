'use strict';
// Quarantined source-audit artifact only: no source rewriting or activation.
const fs = require('node:fs');
const crypto = require('node:crypto');
const files = [
    {arg:process.argv[2], hash:'cc38e231211557d95e68dd7ca3f3845e1715d7129324ce3563a0a5049e323c5a', sites:[
        'targetCatchNode.receive(errorMessage);'
    ]},
    {arg:process.argv[3], hash:'4931ee2e41d4246d51b42c55bb9d7d020ac84601a9e70dff6e70946c23fdf4be', sites:[
        'Node.prototype.receive = function(msg) {',
        'this.emit("input",msg);',
        'this._emitInput.apply(this,args);',
        'Node.prototype._emitInput = function(arg) {',
        'hooks.trigger("onReceive",receiveEvent,(err) => {'
    ]}
];
try {
    for (const file of files) {
        const bytes = fs.readFileSync(file.arg);
        if (crypto.createHash('sha256').update(bytes).digest('hex') !== file.hash) throw Error();
        const text = bytes.toString('utf8');
        for (const site of file.sites) {
            if (text.split(site).length !== 2) throw Error();
        }
    }
    process.stdout.write('PASS: pinned bytes and candidate site counts only; integration is not activated\n');
} catch (_) {
    process.stderr.write('FAIL: unsupported source or site count\n');
    process.exitCode = 1;
}
