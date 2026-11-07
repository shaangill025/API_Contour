'use strict';
// Private idempotent aggregate cleanup. Failure of one close never skips another.
function create(){let closed=false;const actions=[];return Object.freeze({
 add(action){if(typeof action!=='function')throw Error('invalid closer');if(closed){try{action();}catch(_){}return;}actions.push(action);},
 close(){if(closed)return;closed=true;for(const action of actions.splice(0))try{action();}catch(_){}},
 closed(){return closed;}
});}
function requireEpoch(authority,epoch){if(!authority||authority.allowed!==true||typeof authority.epoch!=='bigint'||authority.epoch!==BigInt(epoch)||!Number.isFinite(authority.deadline)||authority.deadline<=require('node:perf_hooks').performance.now())throw Error('permit epoch');}
async function awaitFirst(permit,epoch,timeout=2000){if(!permit||!Number.isSafeInteger(timeout)||timeout<1||timeout>2000)throw Error('permit startup');let timer;try{await Promise.race([permit.ready,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('permit deadline')),timeout);})]);requireEpoch(permit.authority(),epoch);}finally{clearTimeout(timer);}}
module.exports=Object.freeze({create,requireEpoch,awaitFirst});
