'use strict';
// Data-only codec tests. Golden values are normative fixture bytes/digests.
const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),crypto=require('node:crypto');
const {encodeBatch}=require('../../../collectors/nodered/causal-codec');
// Quote wide numeric tokens before JSON.parse, while respecting JSON strings.
// This avoids ever parsing normative wide numbers through an IEEE-754 number.
function lossless(text){let out='', quoted=false, escape=false;
    for(let i=0;i<text.length;){const c=text[i];
        if(quoted){out+=c;i++;if(escape)escape=false;else if(c==='\\')escape=true;else if(c==='"')quoted=false;continue;}
        if(c==='"'){quoted=true;out+=c;i++;continue;}
        if(c>='0'&&c<='9'){let j=i+1;while(j<text.length&&text[j]>='0'&&text[j]<='9')j++;const token=text.slice(i,j);out+=token.length>15?'"'+token+'"':token;i=j;continue;}
        out+=c;i++;
    }return JSON.parse(out);
}
const fixtures=lossless(fs.readFileSync(path.join(__dirname,'../../../docs/specification/fixtures/causal-events.json'),'utf8'));
const numeric=new Set(['wire_version','session_epoch','first_seq','last_seq','seq','first_missing_seq','last_missing_seq']);
function restore(v){if(Array.isArray(v))return v.map(restore);if(v&&typeof v==='object'){for(const k of Object.keys(v))v[k]=numeric.has(k)&&typeof v[k]==='string'&&/^\d+$/.test(v[k])?BigInt(v[k]):restore(v[k]);}return v;}
for(const f of fixtures){
    const body=restore(f.body);
    if(f.expected==='accept'){
        const got=encodeBatch(body);
        assert.equal(got.canonical,f.canonical,f.id);assert.equal(Buffer.byteLength(got.canonical),f.bytes,f.id);assert.equal(got.sha256,f.sha256,f.id);
        assert.deepEqual(got.events,f.events.map(x=>({canonical:x.canonical,sha256:x.sha256})),f.id);
        assert.equal(got.sha256,crypto.createHash('sha256').update('apicontour/causal-events/1\n').update(got.canonical).digest('hex'));
        for(const event of got.events)assert.equal(event.sha256,crypto.createHash('sha256').update('apicontour/causal-event/1\n').update(event.canonical).digest('hex'));
    } else assert.throws(()=>encodeBatch(body),undefined,f.id);
}
const original=fixtures.find(f=>f.id==='all_variants').body;
const clone=()=>structuredClone(original);
let b=clone(); b.session_epoch=Number.MAX_SAFE_INTEGER+1;assert.throws(()=>encodeBatch(b));
b=clone();b.session_epoch=18446744073709551615n;assert(encodeBatch(b).canonical.includes('18446744073709551615'));
b=clone();b.session_epoch=18446744073709551616n;assert.throws(()=>encodeBatch(b));
b=clone();b.session_epoch=-1;assert.throws(()=>encodeBatch(b));
let getters=0;
b=clone();Object.defineProperty(b.events[0],'root',{get(){getters++;return 'a'.repeat(32);}});assert.throws(()=>encodeBatch(b));
b=clone();Object.defineProperty(b,'extra',{get(){getters++;return 'anything';}});assert.throws(()=>encodeBatch(b));
b=clone();Object.defineProperty(b.events,'0',{get(){getters++;return {};}});assert.throws(()=>encodeBatch(b));
b=clone();b.events[0]=Object.assign(Object.create({extra:'x'}),b.events[0]);assert.throws(()=>encodeBatch(b));
b=clone();b.events[0][Symbol('unknown')]=1;assert.throws(()=>encodeBatch(b));
b=clone();b.events[0]=new Proxy(b.events[0],{getOwnPropertyDescriptor(){getters++;throw Error();}});assert.throws(()=>encodeBatch(b));
assert.equal(getters,0);
b=clone();b.events[0].root='ü'.repeat(32);assert.throws(()=>encodeBatch(b));
b=clone();b.events[0].root='a'.repeat(31)+'\n';assert.throws(()=>encodeBatch(b));
b=clone();b.events[0].root='a'.repeat(1048577);assert.throws(()=>encodeBatch(b));
b=clone();b.events=Array.from({length:500},(_,i)=>({kind:'root',event_id:(i+1).toString(16).padStart(32,'0'),seq:i+1,root:(i+501).toString(16).padStart(32,'0')}));b.first_seq=1;b.last_seq=500;
assert.equal(encodeBatch(b).events.length,500);b.events.push({kind:'root',event_id:'f'.repeat(32),seq:501,root:'e'.repeat(32)});b.last_seq=501;assert.throws(()=>encodeBatch(b));
process.stdout.write('PASS: causal canonical fixture/digests, u64, limits and closed-input checks\n');
