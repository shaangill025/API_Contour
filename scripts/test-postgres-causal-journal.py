#!/usr/bin/env python3
"""Synthetic PostgreSQL TLS journal recovery; no ambiguous COMMIT injection."""
import hashlib
import os
from pathlib import Path
import re
import runpy
import signal
import sys
import time

ROOT=Path(__file__).absolute().parent.parent


def safe_source(relative):
    path=ROOT/relative
    for part in (path,*path.parents):
        if part.is_symlink(): raise ValueError('symlink in qualification source')
    if not path.is_file(): raise ValueError('qualification source unavailable')
    return path


def load_helpers():
    names=('scripts/test-postgres-causal-bridge.py','scripts/test-postgres-causal-https.py','scripts/test-postgres-causal-inbox.py')
    hashes={name:hashlib.sha256(safe_source(name).read_bytes()).hexdigest() for name in names}
    modules=[runpy.run_path(str(safe_source(name))) for name in names]
    if any(hashlib.sha256(safe_source(name).read_bytes()).hexdigest()!=digest for name,digest in hashes.items()):
        raise RuntimeError('qualification helper changed while loading')
    return modules[0],modules[1],modules[2],hashes


def line(monitor,index,pattern):
    deadline=time.monotonic()+30
    while time.monotonic()<deadline:
        with monitor.lock:
            output=bytes(monitor.buffers['out']); error=bytes(monitor.buffers['err']); overflow=monitor.overflow
        if overflow or error: raise RuntimeError('probe output invalid')
        lines=output.splitlines(keepends=True)
        if len(lines)>index and lines[index].endswith(b'\n'):
            value=lines[index][:-1]
            if not re.fullmatch(pattern,value): raise RuntimeError('probe stage invalid')
            return value
        if monitor.child.poll() is not None: raise RuntimeError('probe exited before stage')
        time.sleep(.02)
    raise TimeoutError('probe stage deadline')


def send(monitor):
    monitor.child.stdin.write(b'GO\n'); monitor.child.stdin.flush()



def stop(monitor,pattern):
    """Kill the owned group, then require the complete expected protocol output."""
    monitor.stop(False)
    with monitor.lock:
        output=bytes(monitor.buffers['out']); error=bytes(monitor.buffers['err']); overflow=monitor.overflow
    if overflow or error or not re.fullmatch(pattern,output):
        raise RuntimeError('probe final output invalid')
    if monitor.child.returncode != -signal.SIGKILL:
        raise RuntimeError('probe did not reach the controlled kill boundary')


def run_cases(base,work,env,counts,state):
    journal=work/'journal'; journal.mkdir(mode=0o700)
    journal=journal.resolve(strict=True)
    args=base+[str(journal)]
    def start(mode): return ProbeProcess(args+[mode],env)
    def no_writes(expected):
        if counts()!=expected+'|0|0|0|0|0': raise AssertionError('journal session count mismatch')
    def stage(name): state['stages'].append(name)
    def refused(mode,expected):
        result=run_process(args+[mode],env=env,timeout=30,limit=1024)
        if result.returncode==0 or result.stdout or result.stderr!=expected+b'\n': raise AssertionError('journal refusal missing')
    def live_busy():
        refused('normal',b'BUSY')
    no_writes('0')
    monitor=start('normal')
    try:
        line(monitor,0,b'PREPARED'); live_busy(); no_writes('0')
    finally: stop(monitor,rb'PREPARED\n')
    no_writes('0'); stage('killed_after_prepared')
    for mode in ('nonce','envelope','source','config'):
        refused(mode,b'MISMATCH'); no_writes('0'); stage('refuse_'+mode)
    monitor=start('issue_error')
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUE_ERROR')
        live_busy(); no_writes('0'); stage('locked_after_error')
    finally: stop(monitor,rb'PREPARED\nISSUE_ERROR\n')
    monitor=start('normal')
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUED')
        no_writes('1'); live_busy(); stage('locked_after_success')
        # The parent has received only a stage marker, not the session values.
    finally: stop(monitor,rb'PREPARED\nISSUED\n')
    no_writes('1'); stage('killed_after_confirmed_issue')
    cid=state['container_id']
    sql=['docker','exec','-i',cid,'psql','-XqAt','-v','ON_ERROR_STOP=1','-v','VERBOSITY=verbose','-U','postgres','-d','contour_fixture']
    query=b"SELECT epoch::text||' '||floor(extract(epoch FROM issued_at)*1000000)::bigint::text||' '||floor(extract(epoch FROM expires_at)*1000000)::bigint::text FROM contour.causal_sessions;"
    stored=command(sql,data=query,timeout=30).strip()
    if not re.fullmatch(rb'1 [0-9]{1,20} [0-9]{1,20}',stored): raise AssertionError('stored session invalid')
    monitor=start('normal')
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUED'); send(monitor)
        session=line(monitor,2,rb'SESSION [0-9]{1,20} [0-9]{1,20} [0-9]{1,20}')
        if session!=b'SESSION '+stored: raise AssertionError('recovered session differs')
        live_busy(); no_writes('1'); stage('exact_reopen')
    finally: stop(monitor,rb'PREPARED\nISSUED\nSESSION [0-9]{1,20} [0-9]{1,20} [0-9]{1,20}\n')
    monitor=start('wrong_key')
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUE_ERROR')
        live_busy(); no_writes('1'); stage('current_key_rejection')
    finally: stop(monitor,rb'PREPARED\nISSUE_ERROR\n')
    later=work/'later-journal'; later.mkdir(mode=0o700)
    later=later.resolve(strict=True)
    monitor=ProbeProcess(base+[str(later),'later'],env)
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUED')
        no_writes('2'); stage('separate_later_intent')
    finally: stop(monitor,rb'PREPARED\nISSUED\n')
    still_live=b"SELECT (expires_at>clock_timestamp()+interval '10 seconds' AND (claim).grant_expires>clock_timestamp()+interval '10 seconds' AND (claim).policy_expires>clock_timestamp()+interval '10 seconds')::text FROM contour.causal_sessions WHERE epoch=1;"
    if command(sql,data=still_live,timeout=30).strip()!=b'true': raise AssertionError('original lease no longer isolates epoch rejection')
    monitor=start('old_rejected')
    try:
        line(monitor,0,b'PREPARED'); send(monitor); line(monitor,1,b'ISSUE_ERROR')
        no_writes('2'); stage('old_epoch_rejected')
    finally: stop(monitor,rb'PREPARED\nISSUE_ERROR\n')
    if command(sql,data=still_live,timeout=30).strip()!=b'true': raise AssertionError('original lease expired during epoch rejection')
    state['limitations']=['Lost application reply after a confirmed issue; no ambiguous database COMMIT fault was injected.', 'Synthetic PostgreSQL TLS and peer pin; no production activation or producer attestation.']
    state.pop('current_case',None); state['status']='passed'


def install_helpers(bridge,https,inbox,hashes):
    global ProbeProcess, run_process, command
    ProbeProcess=https['ProbeProcess']; run_process=bridge['run_process']; command=bridge['command']
    bg=bridge['main'].__globals__; original_snapshot=bridge['snapshot']; original_build=bridge['build_probe']
    def snapshot():
        for name,digest in hashes.items():
            if hashlib.sha256(safe_source(name).read_bytes()).hexdigest()!=digest: raise RuntimeError('qualification helper changed after loading')
        result={'inbox:'+key:value for key,value in inbox['source_snapshot']().items()}
        result.update({'bridge:'+key:value for key,value in original_snapshot().items()})
        source=ROOT/'crates/contour-ingress/src'
        if source.is_symlink() or not source.is_dir(): raise ValueError('qualification source unavailable')
        def walk_error(error): raise error
        for parent,dirs,files in os.walk(source,followlinks=False,onerror=walk_error):
            if any((Path(parent)/name).is_symlink() for name in dirs+files): raise ValueError('symlink in qualification source')
        paths=list(source.rglob('*.rs'))+list(hashes)+['scripts/test-postgres-causal-journal.py','tests/fixtures/causal-journal/test_journal_driver.py','crates/contour-ingress/examples/causal_journal_probe.rs']
        for path in paths:
            path=Path(path)
            if path.is_absolute(): path=path.relative_to(ROOT)
            result['journal:'+str(path)]=bridge['digest_file'](safe_source(path))
        return result
    def scenario(base,work,env,counts,state,execute):
        state['boundary']='PostgreSQL TLS journal recovery; synthetic inputs; no ambiguous COMMIT or production activation'
        run_cases(base,work,env,counts,state)
    bg.update({'snapshot':snapshot,'build_probe':lambda target:original_build(target,'contour-ingress','causal_journal_probe'),'run_scenario':scenario})


def main():
    if len(sys.argv)!=1: raise ValueError('qualification accepts no arguments')
    bridge,https,inbox,hashes=load_helpers(); install_helpers(bridge,https,inbox,hashes); bridge['main']()


if __name__=='__main__':
    try: main()
    except Exception as error:
        print('FAIL:',type(error).__name__,file=sys.stderr)
        raise SystemExit(1) from None
