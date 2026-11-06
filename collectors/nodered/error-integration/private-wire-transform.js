'use strict';
// Only the reviewed exact CJS source can be transformed. The caller must own
// loading and the private second argument; this module activates nothing.
const {createHash}=require('node:crypto');
const DIGEST='074f654014cfaa359a30e4a897c44764ad636c170350bc8222713562bdb89a3b';
function transform(bytes){
    if(!Buffer.isBuffer(bytes)||createHash('sha256').update(bytes).digest('hex')!==DIGEST)throw Error('unsupported source');
    let source=bytes.toString('utf8');
    const replace=(old,value)=>{if(source.split(old).length!==2)throw Error('unsupported source');source=source.replace(old,value);};
    replace('module.exports = async function(RED) {','module.exports = async function(RED,__privateWire) {');
    replace('        this.on("close",function() {\n            node.status({});', '        this.on("close",function() {\n            __privateWire.closeNode(node);\n            node.status({});');
    replace('            got(url,opts).then(res => {',"            const __wireScope=__privateWire.begin(node,opts);\n            let __wirePromise;\n            try { __wirePromise=got(url,opts); } catch (__wireError) { __wireScope.close(); throw __wireError; }\n            __wirePromise.then(res => {\n                __wireScope.close();");
    replace('            }).catch(err => {', '            }).catch(err => {\n                __wireScope.close();');
    return source;
}
module.exports=Object.freeze({transform});
