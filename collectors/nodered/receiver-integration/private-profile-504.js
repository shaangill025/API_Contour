'use strict';
// Partial source-only artifact checker: no manifest, deployment or authority.
const fs=require('node:fs'),crypto=require('node:crypto');
const ARTIFACT_SHA='707e7b359fb757c668d8a22c999e067556b5f2a785f9c3333c12fca7debfa660';
const NODE='/usr/local/bin/node';
const BINARIES=Object.freeze({
 arm64:Object.freeze({size:128247648,sha256:'f6a453bcbfd0d866cabbc7b02fa5b173931ca08ddbfdca866fe71253b8b583d5'}),
 x64:Object.freeze({size:132502712,sha256:'7e027679034844bb06f53bead732673553cf5bb0de424bbbd257b35c989d34b0'})
});
function validateArtifact(bytes){
 if(!Buffer.isBuffer(bytes)||bytes.length<1||bytes.length>4096||crypto.createHash('sha256').update(bytes).digest('hex')!==ARTIFACT_SHA)throw Error('artifact mismatch');
 let artifact;try{artifact=JSON.parse(bytes.toString('utf8'));}catch(_){throw Error('artifact mismatch');}
 if(!Buffer.from(JSON.stringify(artifact)).equals(bytes))throw Error('artifact mismatch');
 return true;
}
function binarySpec(arch){if(!Object.hasOwn(BINARIES,arch))throw Error('unsupported architecture');return BINARIES[arch];}
function same(a,b){return a.dev===b.dev&&a.ino===b.ino&&a.mode===b.mode&&a.uid===b.uid&&a.gid===b.gid&&a.nlink===b.nlink&&a.size===b.size&&a.mtimeMs===b.mtimeMs&&a.ctimeMs===b.ctimeMs;}
function validStat(s,expected){return s.isFile()&&s.uid===0&&s.gid===0&&(s.mode&0o7777)===0o755&&s.nlink===1&&s.size===expected.size;}
function verifyRuntime(){
 const expected=binarySpec(process.arch);
 if(process.versions.node!=='24.22.3'||process.execPath!==NODE||process.execArgv.length!==0||fs.realpathSync(NODE)!==NODE)throw Error('runtime mismatch');
 let fd;try{
  const pathBefore=fs.lstatSync(NODE);if(!validStat(pathBefore,expected))throw Error('runtime mismatch');
  fd=fs.openSync(NODE,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  const before=fs.fstatSync(fd);if(!validStat(before,expected)||!same(pathBefore,before))throw Error('runtime mismatch');
  const hash=crypto.createHash('sha256'),buffer=Buffer.alloc(65536);let total=0;
  for(;;){const n=fs.readSync(fd,buffer,0,Math.min(buffer.length,expected.size-total+1),null);if(!n)break;total+=n;if(total>expected.size)throw Error('runtime mismatch');hash.update(buffer.subarray(0,n));}
  const after=fs.fstatSync(fd),pathAfter=fs.lstatSync(NODE);
  if(total!==expected.size||!same(before,after)||!same(before,pathAfter)||fs.realpathSync(NODE)!==NODE||hash.digest('hex')!==expected.sha256)throw Error('runtime mismatch');
  return true;
 }finally{if(fd!==undefined)fs.closeSync(fd);}
}
module.exports=Object.freeze({validateArtifact,binarySpec,verifyRuntime});
