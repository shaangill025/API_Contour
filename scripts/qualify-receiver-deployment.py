#!/usr/bin/env python3
"""Owned, fixed receiver 504 inert deployment qualifier; never activates a session."""
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import secrets
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
HEX = re.compile(r'[0-9a-f]{64}\Z')
PHASES = frozenset(('input','source','tools','build','network','probe','cleanup','receipt'))
LABEL = 'org.apicontour.fixture-owner'
LIMIT = 32768
CURRENT_OWNER = None
CURRENT_PHASE = 'input'

def pairs(items):
    result = {}
    for key, value in items:
        if key in result: raise ValueError('duplicate field')
        result[key] = value
    return result

def parse(raw):
    if len(raw) > LIMIT: raise ValueError('input size')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(ValueError('number')))

def input_schema(value):
    fields = {'docker','docker_sha256','socket','docker_config','python','python_sha256','openssl','openssl_sha256','source_root','stage_root','image_sha256','architecture','owner_sha256','material','grant_public','policy_public','grant','policy','peer','ids','nonce','issue_dir','journal_dir','source_identity','key_identity','network','network_name','network_owner'}
    material = {'marker_seed','product_cert','product_key','export_cert','export_key','server_cert','server_key','evidence_cert','evidence_key','ca','server_name'}
    if type(value) is not dict or set(value) != fields or type(value['material']) is not dict or set(value['material']) != material: raise ValueError('input schema')
    if any(type(v) is not str for k,v in value.items() if k not in ('material','ids')) or any(type(v) is not str for v in value['material'].values()): raise ValueError('input types')
    if type(value['ids']) is not list or len(value['ids']) != 10 or any(type(v) is not str for v in value['ids']): raise ValueError('input ids')
    if value['architecture'] not in ('arm64','amd64'): raise ValueError('architecture')
    for key in ('docker_sha256','python_sha256','openssl_sha256','image_sha256','owner_sha256','peer','source_identity','key_identity'):
        if not HEX.fullmatch(value[key]): raise ValueError('digest')
    return value

def snapshot_file(path, limit, mode=None, executable=False):
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts or any(p.is_symlink() for p in (path,*path.parents)): raise ValueError('unsafe file')
    fd = os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        before=os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or before.st_uid not in (0,os.geteuid()) or before.st_mode & 0o022 or (mode is not None and stat.S_IMODE(before.st_mode)!=mode) or (executable and not before.st_mode & 0o111) or not 0<before.st_size<=limit: raise ValueError('unsafe file')
        chunks=[]; remaining=before.st_size
        while remaining:
            part=os.read(fd,min(remaining,1048576))
            if not part: raise ValueError('short file')
            chunks.append(part); remaining-=len(part)
        after=os.fstat(fd); current=os.lstat(path)
        fields=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
        ident=tuple(getattr(before,k) for k in fields)
        if ident!=tuple(getattr(after,k) for k in fields) or ident!=tuple(getattr(current,k) for k in fields): raise ValueError('file changed')
        raw=b''.join(chunks)
        return raw, (ident,hashlib.sha256(raw).hexdigest())
    finally: os.close(fd)

def tool(path, expected):
    if not HEX.fullmatch(expected): raise ValueError('tool digest')
    _, snap=snapshot_file(path,268435456,executable=True)
    if snap[1]!=expected: raise ValueError('tool drift')
    return snap

def select_artifact(lines, target):
    found=[]; source=str(ROOT/'crates/contour-ingress/examples/receiver_deployment_probe.rs')
    for line in lines.splitlines():
        item=json.loads(line,object_pairs_hook=pairs)
        t=item.get('target') or {}
        if item.get('reason')=='compiler-artifact' and t.get('name')=='receiver_deployment_probe' and t.get('kind')==['example'] and t.get('src_path')==source and (item.get('profile') or {}).get('test') is False:
            path=Path(item.get('executable') or '')
            if not path.is_absolute() or '..' in path.parts or any(x.is_symlink() for x in (path,*path.parents)): raise ValueError('artifact path')
            path.relative_to(target)
            found.append((path,snapshot_file(path,268435456,executable=True)[1]))
    if len(found)!=1: raise ValueError('artifact selection')
    return found[0]

def inspect_one(raw):
    item=json.loads(raw,object_pairs_hook=pairs)
    if type(item) is not list or len(item)!=1 or type(item[0]) is not dict: raise ValueError('inspection')
    return item[0]

def validate_network(item, ident, name, token, members):
    if item.get('Id')!=ident or item.get('Name')!=name or item.get('Internal') is not True or item.get('Driver')!='bridge' or (item.get('Labels') or {}).get(LABEL)!=token or type(item.get('Containers')) is not dict or set(item['Containers'])!=set(members): raise ValueError('network drift')

def journal_records(intent, cid, image, network):
    prefix=b'apicontour/local-create-intent/1\n'
    if len(intent)!=len(prefix)+160 or not intent.startswith(prefix): raise ValueError('intent')
    payload=intent[len(prefix):]
    if payload[32:64].hex()!=image or payload[64:96].hex()!=network or not any(payload[:32]): raise ValueError('intent association')
    if len(cid)!=41 or not cid.startswith(b'CCI-CID1\n') or not any(cid[9:]): raise ValueError('cid')
    return payload[:32].hex(),cid[9:].hex()

def validate_container(item,cid,token,image,name,network,config_digest,started=None):
    cfg=item.get('Config') or {}; host=item.get('HostConfig') or {}; state=item.get('State') or {}
    if item.get('Id')!=cid or item.get('Name')!='/contour-causal-'+token or item.get('Image')!=config_digest or cfg.get('Image')!='sha256:'+image or (cfg.get('Labels') or {}).get('org.apicontour.causal.owner')!=token or host.get('NetworkMode')!=name: raise ValueError('container ownership')
    settings=item.get('NetworkSettings') or {}; networks=settings.get('Networks')
    if type(networks) is not dict or set(networks)!={name}: raise ValueError('container topology')
    endpoint=networks[name]
    if type(endpoint) is not dict or endpoint.get('NetworkID') not in ('',network): raise ValueError('endpoint')
    status=state.get('Status'); running=state.get('Running'); stamp=state.get('StartedAt')
    if started is None:
        if status!='created' or running is not False or state.get('Pid')!=0 or stamp!='0001-01-01T00:00:00Z': raise ValueError('unknown start')
    elif (stamp!=started or status not in ('running','exited') or
          (status=='running' and (running is not True or type(state.get('Pid')) is not int or state['Pid']<1)) or
          (status=='exited' and (running is not False or state.get('Pid')!=0))): raise ValueError('generation changed')


def record(owner,name,value):
    if name not in ('network-intent.json','network-id.json','probe-input.json','inspect-before.json','inspect-after.json','receipt.json'): raise ValueError('record')
    owner.verify()
    raw=json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()+b'\n'
    if len(raw)>1048576: raise ValueError('record size')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=owner.fd)
    with os.fdopen(fd,'wb') as f: f.write(raw);f.flush();os.fsync(f.fileno())
    os.fsync(owner.fd);owner.verify()

def fresh_dir(owner,name):
    if name not in ('target','stage','issue','journal'): raise ValueError('directory')
    owner.verify();os.mkdir(name,0o700,dir_fd=owner.fd);os.fsync(owner.fd);owner.verify()
    path=owner.path/name
    st=os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid!=os.geteuid() or stat.S_IMODE(st.st_mode)!=0o700: raise ValueError('directory')
    return path,(st.st_dev,st.st_ino,st.st_mode,st.st_uid)

def probe_result(raw):
    # Runner log consists of stdout, one separator newline, then stderr.
    if not raw.endswith(b'\n'): raise ValueError('probe log')
    lines=raw[:-1].splitlines(); image=[]; result=[]
    for line in lines:
        if line.startswith(b'receiver504_image_config='):
            text=line[len(b'receiver504_image_config='):].decode('ascii')
            if not re.fullmatch(r'sha256:[0-9a-f]{64}',text): raise ValueError('probe config')
            image.append(text)
        if line==b'receiver504_deployment=pass': result.append(('pass',None))
        elif line.startswith(b'receiver504_deployment=fail phase='):
            phase=line.split(b'=')[-1].decode('ascii')
            if phase not in ('input','request','docker','runtime','image','sources','material','preflight','network','create','verify_created','start'): raise ValueError('probe phase')
            result.append(('fail',phase))
    if len(result)!=1 or len(image)>1 or len(lines)!=len(result)+len(image) or (result[0][0]=='pass' and len(image)!=1): raise ValueError('probe result')
    return result[0], image[0] if image else None

def execute_probe(runner, artifact, input_path, owner, timeout):
    if timeout <= 0: raise TimeoutError('probe deadline')
    # Fixed shell only supplies private stdin and reports the child's actual exit.
    # Runner retains the leader while checking its process group; exceptions
    # propagate and leave any remote mutation quarantined.
    shell='"$1" < "$2"; receiver_probe_status=$?; printf "\\nreceiver504_probe_exit=%s\\n" "$receiver_probe_status"'
    runner(['/usr/bin/env','-i','LC_ALL=C','/bin/sh','-c',shell,'receiver504-probe',str(artifact),str(input_path)],cwd=ROOT,timeout=timeout,log=owner.path/'qualification.log')
    raw,_=snapshot_file(owner.path/'qualification.log',16777216,mode=0o600)
    match=re.search(rb'\nreceiver504_probe_exit=(0|[1-9][0-9]{0,2})\n\n\Z',raw)
    if match is None: raise ValueError('probe trailer or stderr')
    status=int(match.group(1))
    if status>255: raise ValueError('probe exit')
    parsed,config=probe_result(raw[:match.start()]+b'\n')
    if (parsed[0]=='pass') != (status==0): raise ValueError('probe exit status')
    return parsed,config


def main(path):
    global CURRENT_OWNER, CURRENT_PHASE
    phase='input'; output=None; network_id=None; network_attempted=False; probe_attempted=False
    probe_ok=False; config_digest=None; outcome='fail'; cleanup='not_attempted'; result_phase='input'
    start=time.monotonic(); deadline=start+600
    raw, original=snapshot_file(path,LIMIT,mode=0o600); data=input_schema(parse(raw))
    if Path(data['source_root'])!=ROOT: raise ValueError('source root')
    parent=Path(path).parent
    pst=os.lstat(parent)
    if not stat.S_ISDIR(pst.st_mode) or pst.st_uid!=os.geteuid() or stat.S_IMODE(pst.st_mode)!=0o700 or any(p.is_symlink() for p in (parent,*parent.parents)): raise ValueError('private parent')
    phase='source';CURRENT_PHASE=phase
    # No repository helper runs until its source is clean and tracked at HEAD.
    check=subprocess.run(['git','status','--porcelain','--untracked-files=all'],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15,check=True)
    if check.stdout or check.stderr: raise ValueError('dirty source')
    helper_names=('scripts/qualify-origin21-onboarding.py','scripts/test-origin21-onboarding.py','deploy/local/docker_metadata.py','crates/contour-ingress/examples/receiver_deployment_probe.rs','scripts/qualify-receiver-deployment.py')
    check=subprocess.run(['git','ls-files','--error-unmatch','--',*helper_names],cwd=ROOT,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,timeout=15)
    if check.returncode or check.stderr: raise ValueError('untracked source')
    helper=runpy.run_path(str(ROOT/'scripts/qualify-origin21-onboarding.py'))
    fixture=runpy.run_path(str(ROOT/'scripts/test-origin21-onboarding.py'))
    meta=runpy.run_path(str(ROOT/'deploy/local/docker_metadata.py'))
    root_name='receiver504-qualification-'+secrets.token_hex(16)
    os.mkdir(parent/root_name,0o700)
    output=helper['OwnedDirectory'](parent/root_name)
    CURRENT_OWNER=output
    runner=helper['Runner'](deadline,output)
    def run(args,timeout=30,log=None): return runner(args,cwd=ROOT,timeout=min(timeout,max(0.001,deadline-time.monotonic())),log=log)
    def git(args): return run(args,timeout=15).strip()
    head=fixture['clean_head'](git); source=fixture['tracked_snapshot'](git)
    if any(name not in source for name in helper_names): raise ValueError('missing source')
    phase='tools';CURRENT_PHASE=phase
    envtools={}
    for key in ('PYTHON','CARGO','RUSTC'):
        pathvar=os.environ.get('RECEIVER_'+key+'_PATH',''); digestvar=os.environ.get('RECEIVER_'+key+'_SHA256','')
        envtools[key]=(pathvar,digestvar,tool(pathvar,digestvar),tuple(meta['_path'](pathvar)))
    if Path(envtools['PYTHON'][0])!=Path(sys.executable) or Path(data['python'])!=Path(sys.executable) or data['python_sha256']!=envtools['PYTHON'][1]: raise ValueError('python binding')
    input_chain=tuple(meta['_path'](path))
    supplied=[(data['docker'],data['docker_sha256']),(data['openssl'],data['openssl_sha256'])]
    tools=[(p,h,tool(p,h),tuple(meta['_path'](p))) for p,h in supplied]
    socket=tuple(meta['_socket'](data['socket'])); config=tuple(meta['_config'](data['docker_config']))
    filepaths=[data[k] for k in ('grant_public','policy_public','grant','policy')]+[v for k,v in data['material'].items() if k!='server_name']
    snapshots=[(p,snapshot_file(p,1048576)[1],tuple(meta['_path'](p))) for p in filepaths]
    target,target_id=fresh_dir(output,'target'); stage,stage_id=fresh_dir(output,'stage'); issue,issue_id=fresh_dir(output,'issue'); journal,journal_id=fresh_dir(output,'journal')
    dirs=[(target,target_id),(stage,stage_id),(issue,issue_id),(journal,journal_id)]
    owned_inputs=[]
    def fences():
        output.verify()
        if time.monotonic()>=deadline or snapshot_file(path,LIMIT,mode=0o600)[1]!=original or tuple(meta['_path'](path))!=input_chain or fixture['clean_head'](git)!=head or fixture['tracked_snapshot'](git)!=source: raise ValueError('source/input drift')
        for p,expected,snap,chain in tools:
            if tool(p,expected)!=snap or tuple(meta['_path'](p))!=chain: raise ValueError('tool drift')
        for p,h,snap,chain in envtools.values():
            if tool(p,h)!=snap or tuple(meta['_path'](p))!=chain: raise ValueError('tool drift')
        if tuple(meta['_socket'](data['socket']))!=socket or tuple(meta['_config'](data['docker_config']))!=config: raise ValueError('docker context drift')
        for p,snap,chain in snapshots:
            if snapshot_file(p,1048576)[1]!=snap or tuple(meta['_path'](p))!=chain: raise ValueError('input drift')
        for p,ident in owned_inputs:
            if snapshot_file(p,LIMIT,mode=0o600)[1]!=ident: raise ValueError('owned input drift')
        for p,ident in dirs:
            st=os.lstat(p)
            if (st.st_dev,st.st_ino,st.st_mode,st.st_uid)!=ident or p.is_symlink(): raise ValueError('owned directory drift')
    def docker(args):
        fences()
        cmd=[data['docker'],'--host','unix://'+data['socket'],'--config',data['docker_config'],*args]
        value=run(['/usr/bin/env','-i','LC_ALL=C',*cmd],timeout=30).strip()
        fences();return value
    def inspect(args): return inspect_one(docker(args))
    phase='build';CURRENT_PHASE=phase;fences()
    cargo=envtools['CARGO'][0];rustc=envtools['RUSTC'][0]
    env=['/usr/bin/env','-i','LC_ALL=C','HOME='+os.environ.get('HOME',''), 'PATH=/usr/bin:/bin','RUSTC='+rustc,'CARGO_TARGET_DIR='+str(target)]
    if os.environ.get('CARGO_HOME'): env.append('CARGO_HOME='+os.environ['CARGO_HOME'])
    build=run([*env,cargo,'build','-p','contour-ingress','--example','receiver_deployment_probe','--locked','--offline','--message-format=json'],timeout=540,log=output.path/'build.log')
    fences();artifact,artifact_id=select_artifact(build,target)
    token=secrets.token_hex(32); name='contour-receiver504-'+secrets.token_hex(16)
    record(output,'network-intent.json',{'version':1,'head':head,'name':name,'owner':token})
    phase='network';CURRENT_PHASE=phase;fences();network_attempted=True
    network_id=docker(['network','create','--internal','--driver','bridge','--label',LABEL+'='+token,name]).decode('ascii')
    if not HEX.fullmatch(network_id): network_id=None;raise ValueError('network receipt')
    record(output,'network-id.json',{'id':network_id})
    validate_network(inspect(['network','inspect',network_id]),network_id,name,token,[])
    data.update(stage_root=str(stage),issue_dir=str(issue),journal_dir=str(journal),network=network_id,network_name=name,network_owner=token)
    record(output,'probe-input.json',data)
    owned_inputs.append((output.path/'probe-input.json',snapshot_file(output.path/'probe-input.json',LIMIT,mode=0o600)[1]))
    if snapshot_file(artifact,268435456,executable=True)[1]!=artifact_id: raise ValueError('probe drift')
    fences(); phase='probe';CURRENT_PHASE=phase;probe_attempted=True
    (status,result_phase),config_digest=execute_probe(runner,artifact,output.path/'probe-input.json',output,min(540,deadline-time.monotonic()))
    fences()
    if snapshot_file(artifact,268435456,executable=True)[1]!=artifact_id: raise ValueError('probe drift')
    probe_ok=status=='pass';outcome=status
    if not probe_ok and result_phase in ('create','start'): raise ValueError('unknown mutation')
    phase='cleanup';CURRENT_PHASE=phase
    # Unknown outcomes are quarantined: no CID adoption or cleanup on start failure.
    intent_path=journal/'create.intent';cid_path=journal/'create.cid';start_path=journal/'create.start'
    if intent_path.exists():
        if not cid_path.exists() or not config_digest: raise ValueError('unknown create')
        intent,intent_id=snapshot_file(intent_path,512,mode=0o600);cid_raw,cid_id=snapshot_file(cid_path,128,mode=0o600)
        owner_token,cid=journal_records(intent,cid_raw,data['image_sha256'],network_id)
        owned_inputs.extend([(intent_path,intent_id),(cid_path,cid_id)])
        if start_path.exists():
            start_raw,start_id=snapshot_file(start_path,128,mode=0o600)
            owned_inputs.append((start_path,start_id))
            if start_raw!=b'CCI-START1\n'+bytes.fromhex(cid) or not probe_ok: raise ValueError('unknown start')
        first=inspect(['container','inspect',cid]);record(output,'inspect-before.json',first)
        stamp=(first.get('State') or {}).get('StartedAt') if start_path.exists() else None
        if stamp is not None and (not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z',str(stamp)) or stamp.startswith('0001-')): raise ValueError('generation')
        if stamp is not None:
            import datetime
            try: datetime.datetime.fromisoformat(stamp.replace('Z','+00:00'))
            except ValueError: raise ValueError('generation') from None
        validate_container(first,cid,owner_token,data['image_sha256'],name,network_id,config_digest,stamp)
        second=inspect(['container','inspect',cid]);validate_container(second,cid,owner_token,data['image_sha256'],name,network_id,config_digest,stamp)
        if any(first.get(k)!=second.get(k) for k in ('Id','Name','Image','Config','HostConfig','Mounts')): raise ValueError('container changed')
        if snapshot_file(intent_path,512,mode=0o600)[1]!=intent_id or snapshot_file(cid_path,128,mode=0o600)[1]!=cid_id: raise ValueError('journal drift')
        members=[cid] if (second.get('State') or {}).get('Running') is True else []
        validate_network(inspect(['network','inspect',network_id]),network_id,name,token,members)
        if (second.get('State') or {}).get('Running') is True: docker(['stop','--time','2',cid])
        stopped=inspect(['container','inspect',cid]);validate_container(stopped,cid,owner_token,data['image_sha256'],name,network_id,config_digest,stamp)
        record(output,'inspect-after.json',stopped);docker(['container','rm',cid])
        if docker(['container','ls','-a','--no-trunc','--filter','id='+cid,'--format','{{.ID}}']): raise ValueError('container removal unknown')
    elif cid_path.exists() or start_path.exists(): raise ValueError('incomplete journal')
    validate_network(inspect(['network','inspect',network_id]),network_id,name,token,[])
    docker(['network','rm',network_id])
    if docker(['network','ls','--no-trunc','--filter','id='+network_id,'--format','{{.ID}}']): raise ValueError('network removal unknown')
    cleanup='complete'
    phase='receipt';CURRENT_PHASE=phase;fences()
    record(output,'receipt.json',{'version':1,'head':head,'outcome':outcome,'phase':result_phase,'cleanup':cleanup})
    return {'status':outcome,'phase':result_phase,'cleanup':cleanup,'output':str(output.path)}

def entry():
    os.umask(0o077);sys.dont_write_bytecode=True
    if len(sys.argv)!=3 or sys.argv[1]!='--run-owned': raise ValueError('arguments')
    return main(sys.argv[2])

def failure_diagnostic(error):
    allowed={'ValueError','RuntimeError','TimeoutError','OSError','PermissionError','FileNotFoundError','TypeError','KeyError','IndexError','AttributeError','ExceptionGroup','BaseExceptionGroup'}
    codes={'invalid owner record':'owner_record','owner identity changed':'owner_identity',
           'clean reviewed source required':'source_not_clean','source/input drift':'source_input_drift',
           'process output bound':'process_output_bound','process deadline':'process_deadline'}
    filenames={__file__:'qualify-receiver-deployment.py',
        str(ROOT/'scripts/qualify-origin21-onboarding.py'):'qualify-origin21-onboarding.py',
        str(ROOT/'scripts/test-origin21-onboarding.py'):'test-origin21-onboarding.py',
        str(ROOT/'deploy/local/docker_metadata.py'):'docker_metadata.py'}
    kind=type(error).__name__
    if kind not in allowed: kind='OtherError'
    frames=[]; trace=error.__traceback__
    while trace is not None:
        name=filenames.get(trace.tb_frame.f_code.co_filename)
        if name is not None and 1 <= trace.tb_lineno <= 999999:
            frames.append({'file':name,'line':trace.tb_lineno})
        trace=trace.tb_next
    return kind,frames[-4:],codes.get(str(error))


def report(run=entry):
    try:
        value=run()
    except BaseException as error:
        kind,frames,code=failure_diagnostic(error)
        value={'status':'fail','phase':CURRENT_PHASE,'cleanup':'unknown','failure_type':kind,'source_frames':frames}
        if code is not None: value['failure_code']=code
        if CURRENT_OWNER is not None:
            value['output']=str(CURRENT_OWNER.path)
            try: record(CURRENT_OWNER,'receipt.json',{'version':1,**value})
            except BaseException: pass
    print(json.dumps(value,sort_keys=True,separators=(',',':')))
    return 0 if value['status']=='pass' else 1

if __name__=='__main__':
    sys.exit(report())
