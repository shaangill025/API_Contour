'use strict';
// Inactive owned-image helper. The caller supplies independently pinned bytes,
// transformed sources and private facades; no capability is exported by the
// target CJS module. This is not an application or production loader.
const Module=require('node:module');
const path=require('node:path');
const vm=require('node:vm');
const apply=Reflect.apply,{types}=require('node:util');
function boundedTransform(value){
    if(typeof value!=='string'&&!Buffer.isBuffer(value))throw Error('unsupported transformed source');
    const bytes=Buffer.isBuffer(value)?Buffer.from(value):Buffer.from(value,'utf8');
    if(bytes.length>4*1024*1024||(typeof value==='string'&&bytes.toString('utf8')!==value))throw Error('unsupported transformed source');
    return bytes;
}
// Terminal on any loss of authority or integrity; no authority is exported.
function makeLiveGate({ready,gate,integrity,invalidate}){
    let terminal=false;
    return ()=>{if(terminal)return false;try{if(ready()&&gate()&&integrity())return true;}catch(_){}terminal=true;invalidate();return false;};
}
function scrubHeaders(opts){
    if(!opts||typeof opts!=='object'||types.isProxy(opts))return false;
    const descriptor=Object.getOwnPropertyDescriptor(opts,'headers'),headers=descriptor&&'value'in descriptor&&descriptor.value;
    if(!headers||typeof headers!=='object'||types.isProxy(headers)||(Object.getPrototypeOf(headers)!==Object.prototype&&Object.getPrototypeOf(headers)!==null))return false;
    for(const name of Reflect.ownKeys(headers)){if(typeof name!=='string')return false;const d=Object.getOwnPropertyDescriptor(headers,name);if(!d||!('value'in d))return false;if(name.toLowerCase().startsWith('x-apicontour-')&&(!d.configurable||!delete headers[name]))return false;}
    return true;
}
function localRequire(parent){
    function req(name){return parent.require(name);}
    req.resolve=(name,options)=>Module._resolveFilename(name,parent,false,options);
    req.resolve.paths=name=>Module._resolveLookupPaths(name,parent);
    req.main=process.mainModule;req.extensions=Module._extensions;req.cache=Module._cache;
    return req;
}
function install({targets,wirePath,wireFacade,invalidate}){
    if(!(targets instanceof Map)||targets.size!==3||!targets.has(wirePath)||!wireFacade||typeof invalidate!=='function')throw Error('unsupported loader');
    const previous=Module.prototype._compile, seen=new Set(),compiledTargets=new Map();let restored=false, registered=false, started=false, registration, wrapper;
    for(const [file,item] of targets){
        if(typeof file!=='string'||!path.isAbsolute(file)||!item||!Buffer.isBuffer(item.original)||!Buffer.isBuffer(item.transformed)||require.cache[file])throw Error('target unavailable');
    }
    function restore(){if(restored)return;restored=true;if(Module.prototype._compile===intercept)Module.prototype._compile=previous;else invalidate();}
    function fail(){invalidate();restore();}
    function intercept(content,filename){
        if(!targets.has(filename))return apply(previous,this,arguments);
        try{
            if(restored||seen.has(filename)||!Buffer.from(content,'utf8').equals(targets.get(filename).original))throw Error('target mismatch');
            seen.add(filename);const item=targets.get(filename);
            if(!vm.constants?.USE_MAIN_CONTEXT_DEFAULT_LOADER)throw Error('unsupported dynamic import');
            const compiled=vm.compileFunction(item.transformed.toString('utf8'),['exports','require','module','__filename','__dirname',item.binding],{filename,importModuleDynamically:vm.constants.USE_MAIN_CONTEXT_DEFAULT_LOADER});
            const result=apply(compiled,this.exports,[this.exports,localRequire(this),this,filename,path.dirname(filename),item.facade]);
            if(filename===wirePath){
                registration=this.exports;if(typeof registration!=='function')throw Error('registration');
                wrapper=function(RED){if(started){fail();throw Error('repeated registration');}started=true;let result;try{result=apply(registration,this,[RED,wireFacade]);}catch(error){fail();throw error;}if(result&&typeof result.then==='function')return Promise.resolve(result).then(value=>{registered=true;return value;},error=>{fail();throw error;});registered=true;return result;};
                this.exports=wrapper;
            }
            compiledTargets.set(filename,{module:this,exports:this.exports});
            if(seen.size===targets.size)restore();
            return result;
        }catch(error){fail();throw error;}
    }
    function cacheIntact(){return [...compiledTargets].every(([name,item])=>require.cache[name]===item.module&&item.module.exports===item.exports);}
    Module.prototype._compile=intercept;
    return Object.freeze({
        finish(){if(seen.size!==targets.size||!registered||!wrapper||!cacheIntact()||require.cache[wirePath]?.exports!==wrapper){fail();return false;}restore();return true;},
        intact(){if(!restored||seen.size!==targets.size||!registered||!cacheIntact()||require.cache[wirePath]?.exports!==wrapper){fail();return false;}return true;},
        cancel(){fail();}
    });
}
module.exports=Object.freeze({install,scrubHeaders,boundedTransform,makeLiveGate});
