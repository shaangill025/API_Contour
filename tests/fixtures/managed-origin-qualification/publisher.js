'use strict';
// Qualification-only fixed publisher. It commits the same SDS bytes as the
// ordinary publisher, then records remote commit before holding its final ACK.
const fs=require('node:fs'),crypto=require('node:crypto');
const digest=process.argv[2],nonce=process.argv[3],temp='/watch/.pending-'+nonce,marker='/watch/.qualification-commit-'+nonce;
if(!/^[0-9a-f]{64}$/.test(digest||'')||!/^[0-9a-f]{32}$/.test(nonce||''))process.exit(1);
let input,output,owned;
try{
 input=fs.openSync('/watch/sds.json',fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
 const st=fs.fstatSync(input);if(!st.isFile()||st.nlink!==1||(st.mode&0o777)!==0o600||st.size>65536)throw Error();
 const buffer=Buffer.alloc(65537);let count=0,n;while(count<buffer.length&&(n=fs.readSync(input,buffer,count,buffer.length-count,null))>0)count+=n;
 const data=buffer.subarray(0,count);if(count>65536||count!==st.size||crypto.createHash('sha256').update(data).digest('hex')!==digest)throw Error();
 fs.closeSync(input);input=undefined;process.stdout.write('DOC_VERIFIED\n');
 output=fs.openSync(temp,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);owned=fs.fstatSync(output);
 fs.writeFileSync(output,data);fs.fsyncSync(output);fs.closeSync(output);output=undefined;
 fs.renameSync(temp,'/watch/sds.json');let dir=fs.openSync('/watch',fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
 const mark=fs.openSync(marker,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
 try{fs.writeFileSync(mark,digest+'\n');fs.fsyncSync(mark)}finally{fs.closeSync(mark)}
 dir=fs.openSync('/watch',fs.constants.O_RDONLY|fs.constants.O_DIRECTORY|fs.constants.O_NOFOLLOW);
 try{fs.fsyncSync(dir)}finally{fs.closeSync(dir)}
 // Bounded test hold. Observer must prove this exact marker and exec identity;
 // the marker is evidence only and never authorizes controller reconciliation.
 Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5000);
 process.stdout.write('PUBLISHED\n');
}catch(_){process.exitCode=1}finally{
 if(input!==undefined)fs.closeSync(input);if(output!==undefined)fs.closeSync(output);
 if(owned){try{const now=fs.lstatSync(temp);if(now.dev!==owned.dev||now.ino!==owned.ino)throw Error();fs.unlinkSync(temp)}catch(e){if(e.code!=='ENOENT')process.exitCode=1}}
}
