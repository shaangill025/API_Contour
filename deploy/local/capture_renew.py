"""Explicit synthetic policy renewal. Never logs policy, keys or SQL."""
import base64
import datetime
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import sys

ROOT = Path(__file__).resolve().parents[2]
CAPTURE = ROOT / '.local-mvp/capture'
sys.path.insert(0, str(Path(__file__).resolve().parent))
import capture_profiles
spec = importlib.util.spec_from_file_location('capture_provision', ROOT/'deploy/local/capture_provision.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)
MAX_ENVELOPE = 16384
MAX_JOURNAL = 2 * ((MAX_ENVELOPE + 2) // 3) * 4 + 1024
DOMAIN = b'apicontour/policy/1\n'
FIELDS = dict(tenant_id=p.TENANT, collector_id=p.COLLECTOR, enabled=True, service_ids=[p.SERVICE],
    techniques=['gateway'], approved_names=['GET','POST','id','name','status'], denied_templates=[],
    inspection_bytes=65536, depth_limit=32, queue_bytes=1048576, queue_ttl_seconds=3600,
    durable_queue_enabled=False, approved_route_segments=['orders'], parser_profiles=['http_json_v1'])


def pairs(values):
    result={}
    for key,value in values:
        if key in result: raise ValueError('duplicate field')
        result[key]=value
    return result


def exact_json(data):
    return json.loads(data,object_pairs_hook=pairs,parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))


def safe_dir(path):
    info=os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077:
        raise ValueError('unsafe private directory')


def read_file(path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        info=os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode & 0o077 or info.st_nlink!=1 or not 1<=info.st_size<=maximum:
            raise ValueError('unsafe private file')
        chunks=[]; left=maximum+1
        while left:
            part=os.read(fd,min(left,65536))
            if not part: break
            chunks.append(part); left-=len(part)
        data=b''.join(chunks)
        if not 1<=len(data)<=maximum: raise ValueError('private file size')
        return data
    finally: os.close(fd)


def replace_durable(path,data):
    fd,name=tempfile.mkstemp(prefix='.renew-',dir=path.parent)
    try:
        os.fchmod(fd,0o600)
        with os.fdopen(fd,'wb') as file:
            file.write(data); file.flush(); os.fsync(file.fileno())
        os.replace(name,path)
        dfd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(dfd)
        finally: os.close(dfd)
    finally:
        if os.path.exists(name): os.unlink(name)


def remove_durable(path):
    os.unlink(path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try: os.fsync(fd)
    finally: os.close(fd)


def encoded(raw): return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')
def decoded(value):
    if not isinstance(value,str) or not value or any(c not in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_' for c in value): raise ValueError('encoding')
    raw=base64.urlsafe_b64decode(value+'='*(-len(value)%4))
    if encoded(raw)!=value: raise ValueError('encoding')
    return raw


def crypt(op, key, message, signature=None, profile=None, scratch=None):
    # OpenSSL only receives temporary files with private modes; optional scratch
    # lets a read-only state preflight keep those files outside the profile.
    directory_root = scratch if scratch is not None else (CAPTURE if profile is None else profile.capture)/'private'
    with tempfile.TemporaryDirectory(prefix='.renew-crypto-',dir=directory_root) as directory:
        directory=Path(directory); keyfile=directory/'key'; msg=directory/'message'
        keyfile.write_bytes(key); msg.write_bytes(message)
        os.chmod(keyfile,0o600); os.chmod(msg,0o600)
        if op=='public': args=['openssl','pkey','-in',str(keyfile),'-pubout','-outform','DER']
        elif op=='sign': args=['openssl','pkeyutl','-sign','-rawin','-inkey',str(keyfile),'-in',str(msg)]
        else:
            sig=directory/'signature'; sig.write_bytes(signature); os.chmod(sig,0o600)
            args=['openssl','pkeyutl','-verify','-rawin','-pubin','-keyform','DER','-inkey',str(keyfile),'-in',str(msg),'-sigfile',str(sig)]
        result=subprocess.run(args,capture_output=True,timeout=10)
        if result.returncode: raise ValueError('cryptographic check failed')
        return result.stdout


def checked_envelope(raw, public, profile=None, scratch=None):
    if len(raw)>MAX_ENVELOPE: raise ValueError('envelope limit')
    envelope=exact_json(raw)
    if json.dumps(envelope,separators=(',',':')).encode()!=raw: raise ValueError('noncanonical envelope')
    if not isinstance(envelope,dict) or set(envelope)!={'key_id','signature_profile','payload_base64url','signature_base64url'} or envelope['key_id']!='local' or envelope['signature_profile']!='ed25519-v1': raise ValueError('envelope')
    payload=decoded(envelope['payload_base64url']); signature=decoded(envelope['signature_base64url'])
    if len(signature)!=64: raise ValueError('signature')
    crypt('verify',public,DOMAIN+payload,signature,profile,scratch)
    policy=exact_json(payload)
    if json.dumps(policy,separators=(',',':')).encode()!=payload: raise ValueError('noncanonical policy')
    fields = FIELDS if profile is None else dict(FIELDS, collector_id=profile.collector, approved_names=list(profile.approved_names), approved_route_segments=list(profile.approved_route_segments))
    if not isinstance(policy,dict) or set(policy)!=set(fields)|{'revision','issued_at','expires_at'}: raise ValueError('policy fields')
    for key,value in fields.items():
        if policy[key]!=value or type(policy[key]) is not type(value): raise ValueError('policy scope')
    revision=policy['revision']
    if type(revision) is not int or not 1<=revision<=18446744073709551615: raise ValueError('revision')
    issued=datetime.datetime.fromisoformat(policy['issued_at'].replace('Z','+00:00'))
    expires=datetime.datetime.fromisoformat(policy['expires_at'].replace('Z','+00:00'))
    if issued.tzinfo is None or expires.tzinfo is None or not datetime.timedelta(0)<expires-issued<=datetime.timedelta(minutes=15): raise ValueError('lease')
    return policy


def signed_policy(old,key,now,profile=None):
    if old['revision']>=18446744073709551615: raise ValueError('revision exhausted')
    policy=dict(old,revision=old['revision']+1,
        issued_at=(now-datetime.timedelta(seconds=30)).isoformat(timespec='microseconds').replace('+00:00','Z'),
        expires_at=(now+datetime.timedelta(minutes=14)).isoformat(timespec='microseconds').replace('+00:00','Z'))
    payload=json.dumps(policy,separators=(',',':')).encode()
    signature=crypt('sign',key,DOMAIN+payload,profile=profile)
    if len(signature)!=64: raise ValueError('signature')
    return json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=encoded(payload),signature_base64url=encoded(signature)),separators=(',',':')).encode()


def locked_transaction(base_bytes,base_revision,proposal,proposal_revision,issued,expires,preflight,profile=None):
    q=p.base.sql_quote
    profile = profile or capture_profiles.DEFAULT
    if profile not in (capture_profiles.DEFAULT, capture_profiles.PILOT): raise ValueError('unknown capture profile')
    t,c,src,project,service,env,dep,instance,nonce=map(q,[p.TENANT,profile.collector,profile.source,p.PROJECT,p.SERVICE,p.ENVIRONMENT,profile.deployment,profile.instance,profile.nonce])
    # Preflight runs under the same collector lock and authorization checks as
    # commit. It emits only a closed state token, never envelope contents.
    if preflight:
        base_action=f"""IF EXISTS (SELECT 1 FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c} AND revision={proposal_revision}) THEN RAISE EXCEPTION 'proposal revision exists'; END IF;
        IF pg_catalog.clock_timestamp() >= {q(expires)}::timestamptz THEN PERFORM set_config('apicontour.renew_state','base_expired',true);
        ELSE PERFORM set_config('apicontour.renew_state','base_live',true); END IF;"""
        committed_action="PERFORM set_config('apicontour.renew_state','committed',true);"
        result_query="SELECT current_setting('apicontour.renew_state');"
    else:
        base_action=f"""IF pg_catalog.clock_timestamp() < {q(issued)}::timestamptz OR pg_catalog.clock_timestamp() >= {q(expires)}::timestamptz THEN RAISE EXCEPTION 'proposal expired'; END IF;
        INSERT INTO contour.policy_revisions VALUES ({t},{c},{proposal_revision},decode('{proposal.hex()}','hex'));
        UPDATE contour.collector_authorization SET active_revision={proposal_revision} WHERE tenant_id={t} AND collector_id={c} AND enabled AND revoked_at IS NULL AND active_revision={base_revision};
        GET DIAGNOSTICS affected=ROW_COUNT;
        IF affected<>1 THEN RAISE EXCEPTION 'head changed'; END IF;"""
        committed_action="NULL;"
        result_query=""
    # All identity checks and both head comparisons execute after collector lock,
    # through one transaction. No dynamic values are used as SQL identifiers.
    sql=f'''BEGIN;
SELECT set_config('apicontour.tenant_id',{t},true),set_config('statement_timeout','15s',true),set_config('lock_timeout','5s',true),set_config('idle_in_transaction_session_timeout','15s',true);
SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector({t},{c});
DO $$ DECLARE current_revision numeric; current_envelope bytea; affected integer; BEGIN
 IF NOT EXISTS (SELECT 1 FROM contour.collector_authorization WHERE tenant_id={t} AND collector_id={c} AND enabled AND revoked_at IS NULL)
 OR (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep} AND source_nonce={nonce} AND binding_mode='instance')<>1
 OR (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND technique='gateway' AND parser_profiles=ARRAY['http_json_v1'])<>1
 OR (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep} AND instance_id={instance})<>1
 OR (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep})<>1
 THEN RAISE EXCEPTION 'local authorization drift'; END IF;
 SELECT a.active_revision,r.signed_envelope INTO current_revision,current_envelope FROM contour.collector_authorization a JOIN contour.policy_revisions r ON r.tenant_id=a.tenant_id AND r.collector_id=a.collector_id AND r.revision=a.active_revision WHERE a.tenant_id={t} AND a.collector_id={c};
 IF current_revision={base_revision} AND current_envelope=decode('{base_bytes.hex()}','hex') THEN
   {base_action}
 ELSIF current_revision={proposal_revision} AND current_envelope=decode('{proposal.hex()}','hex') THEN
   {committed_action}
 ELSE RAISE EXCEPTION 'head changed'; END IF;
END $$;
{result_query}
COMMIT;'''
    output=p.base.psql(sql)
    if preflight:
        state=output.splitlines()[-1] if output else ''
        if state not in ('base_live','base_expired','committed'): raise ValueError('preflight state')
        return state


def database_state(base_bytes,base_revision,proposal,proposal_revision,issued,expires,profile=None):
    return locked_transaction(base_bytes,base_revision,proposal,proposal_revision,issued,expires,True,profile)


def database_commit(base_bytes,base_revision,proposal,proposal_revision,issued,expires,profile=None):
    locked_transaction(base_bytes,base_revision,proposal,proposal_revision,issued,expires,False,profile)


def renew(now=None, profile=None):
    if profile not in (None, capture_profiles.DEFAULT, capture_profiles.PILOT): raise ValueError('unknown capture profile')
    if profile == capture_profiles.DEFAULT: profile = None
    capture = CAPTURE if profile is None else profile.capture
    now=now or datetime.datetime.now(datetime.timezone.utc)
    private=capture/'private'; runtime=capture/'runtime'
    for directory in (capture.parent,capture,private,runtime): safe_dir(directory)
    lockfd=os.open(private/'renew.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        info=os.fstat(lockfd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077 or info.st_nlink!=1: raise ValueError('lock')
        fcntl.flock(lockfd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        key=read_file(private/'policy.key',16384); raw_public=read_file(runtime/'policy.raw',32)
        public=crypt('public',key,b'',profile=profile)
        if len(public)!=44 or public[-32:]!=raw_public: raise ValueError('signer mismatch')
        policy_path=private/'policy.json'; journal_path=private/'renew.pending'
        current=read_file(policy_path,MAX_ENVELOPE); current_policy=checked_envelope(current,public,profile)
        if os.path.lexists(journal_path):
            journal_bytes=read_file(journal_path,MAX_JOURNAL)
            journal=exact_json(journal_bytes)
            if json.dumps(journal,separators=(',',':')).encode()!=journal_bytes: raise ValueError('noncanonical journal')
            if not isinstance(journal,dict) or set(journal)!={'version','base','proposal'} or type(journal['version']) is not int or journal['version']!=1: raise ValueError('journal')
            base=decoded(journal['base']); proposal=decoded(journal['proposal'])
            old=checked_envelope(base,public,profile); new=checked_envelope(proposal,public,profile)
            if new['revision']!=old['revision']+1 or current not in (base,proposal): raise ValueError('journal mismatch')
            args=(base,old['revision'],proposal,new['revision'],new['issued_at'],new['expires_at'])
            state=database_state(*args) if profile is None else database_state(*args,profile=profile)
            if state=='base_expired':
                if current!=base: raise ValueError('journal mismatch')
                # The old proposal has been proven absent while the exact base
                # is locked. Replace the durable journal before any mutation.
                proposal=signed_policy(old,key,now,profile); new=checked_envelope(proposal,public,profile)
                replacement=json.dumps(dict(version=1,base=encoded(base),proposal=encoded(proposal)),separators=(',',':')).encode()
                replace_durable(journal_path,replacement)
        else:
            base=current; old=current_policy
            proposal=signed_policy(old,key,now,profile); new=checked_envelope(proposal,public,profile)
            journal=json.dumps(dict(version=1,base=encoded(base),proposal=encoded(proposal)),separators=(',',':')).encode()
            replace_durable(journal_path,journal)
        args=(base,old['revision'],proposal,new['revision'],new['issued_at'],new['expires_at'])
        if profile is None: database_commit(*args)
        else: database_commit(*args,profile=profile)
        if current!=proposal: replace_durable(policy_path,proposal)
        remove_durable(journal_path)
    finally:
        os.close(lockfd)


def main(profile=None):
    os.umask(0o077)
    try: renew(profile=profile)
    except Exception:
        print('Synthetic policy renewal failed; existing state and pending journal retained.',file=__import__('sys').stderr)
        raise SystemExit(1)
    print('Synthetic policy renewal reconciled.')

if __name__=='__main__': main(capture_profiles.arguments(sys.argv[1:]))
