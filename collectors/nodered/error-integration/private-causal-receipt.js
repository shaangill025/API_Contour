'use strict';
// Strict, flat receipt parser: preserve the decimal epoch without IEEE-754 conversion.
const {TextDecoder}=require('node:util');
const MAX=(1n<<64n)-1n, names=new Set(['batch_id','runtime_id','session_epoch','batch_digest','receipt_id','accepted_at','status']);
function parse(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length>4096)throw Error('receipt');
 const s=new TextDecoder('utf-8',{fatal:true}).decode(bytes);let i=0;const ws=()=>{while(/[\x20\t\r\n]/.test(s[i]||'\0'))i++;};
 function string(){if(s[i++]!=='"')throw Error('receipt');const start=i-1;while(i<s.length){const c=s.charCodeAt(i++);if(c===34){const value=JSON.parse(s.slice(start,i));if(typeof value!=='string')throw Error('receipt');return value;}if(c<32)throw Error('receipt');if(c===92){if(i>=s.length)throw Error('receipt');i++;}}throw Error('receipt');}
 ws();if(s[i++]!=='{')throw Error('receipt');const out=Object.create(null);ws();
 for(let count=0;;count++){if(count){if(s[i++]!==',')throw Error('receipt');ws();}const key=string();if(!names.has(key)||Object.hasOwn(out,key))throw Error('receipt');ws();if(s[i++]!==':')throw Error('receipt');ws();
 if(key==='session_epoch'){const match=/^(0|[1-9][0-9]*)/.exec(s.slice(i));if(!match||match[0].length>20)throw Error('receipt');i+=match[0].length;out[key]=BigInt(match[0]);if(out[key]<1n||out[key]>MAX)throw Error('receipt');}else out[key]=string();
 ws();if(s[i]==='}'){i++;break;}}
 ws();if(i!==s.length||Object.keys(out).length!==7)throw Error('receipt');return out;
}
module.exports=Object.freeze({parse});
