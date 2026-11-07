"""Closed local operator SQL transport. Never print SQL or credentials.

No commands execute on import. Authentication uses loopback TLS and SCRAM,
not the local trust socket. Sensitive sessions disable statement/error logging
via startup options before any SQL is parsed and check those settings first.
"""
import os
import re
import selectors
import signal
import subprocess
import time
from deploy.local import origin21_profile

ROOT=origin21_profile.ROOT
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/local/compose.yaml')]
OPTIONS=('-c log_statement=none -c log_min_duration_statement=-1 '
         '-c log_min_duration_sample=-1 -c log_min_error_statement=panic '
         '-c log_min_messages=panic -c log_duration=off '
         '-c log_statement_sample_rate=0 -c log_transaction_sample_rate=0')
GUARD="""DO $$ BEGIN IF current_setting('log_statement')<>'none'
 OR current_setting('log_min_duration_statement')<>'-1'
 OR current_setting('log_min_duration_sample')<>'-1'
 OR current_setting('log_min_error_statement')<>'panic'
 OR current_setting('log_min_messages')<>'panic'
 OR current_setting('log_duration')<>'off'
 OR current_setting('log_statement_sample_rate')::numeric<>0
 OR current_setting('log_transaction_sample_rate')::numeric<>0
 THEN RAISE EXCEPTION 'unsafe private session settings'; END IF; END $$;
"""
MAX=8*1024*1024


def _run(args, data, deadline=60, env=None):
    raw=data.encode('utf-8')
    if len(raw)>MAX: raise ValueError('operator input bound')
    process=subprocess.Popen(args,cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,start_new_session=True,env=env)
    selector=selectors.DefaultSelector(); output=bytearray(); offset=0; end=time.monotonic()+deadline
    os.set_blocking(process.stdin.fileno(),False); os.set_blocking(process.stdout.fileno(),False)
    selector.register(process.stdin,selectors.EVENT_WRITE); selector.register(process.stdout,selectors.EVENT_READ)
    complete=False
    try:
        while selector.get_map():
            left=end-time.monotonic()
            if left<=0: raise TimeoutError('operator transport deadline')
            for key,_ in selector.select(left):
                if key.fileobj is process.stdin:
                    if offset==len(raw): selector.unregister(process.stdin); process.stdin.close(); continue
                    try: offset+=os.write(process.stdin.fileno(),raw[offset:offset+65536])
                    except BrokenPipeError: selector.unregister(process.stdin); process.stdin.close()
                else:
                    chunk=os.read(process.stdout.fileno(),min(65536,MAX+1-len(output)))
                    if not chunk: selector.unregister(process.stdout)
                    else:
                        output.extend(chunk)
                        if len(output)>MAX: raise RuntimeError('operator output bound')
        result=process.wait(timeout=max(.01,end-time.monotonic()))
        complete=True
        if result or offset!=len(raw): raise RuntimeError('operator database command failed')
        return bytes(output).decode('utf-8').strip()
    finally:
        selector.close()
        if not complete:
            try: os.killpg(process.pid,signal.SIGKILL)
            except ProcessLookupError: pass
        try:
            if process.poll() is None: process.wait(timeout=5)
        finally:
            if not process.stdin.closed: process.stdin.close()
            process.stdout.close()


def admin(sql):
    if not isinstance(sql,str): raise ValueError('invalid SQL')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run((GUARD+sql).encode('utf-8'),'sql','postgres')


def sensitive(sql):
    if not isinstance(sql,str): raise ValueError('invalid SQL')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run((GUARD+sql).encode('utf-8'),'sql','postgres')


def authenticate(role,password):
    if role not in (origin21_profile.PROFILE.ingress_login,origin21_profile.PROFILE.worker_login): raise ValueError('unsupported role')
    if not isinstance(password,str) or not re.fullmatch('[A-Za-z0-9_-]{32,4096}',password): raise ValueError('invalid credential')
    from deploy.local import origin21_sql_runner
    return origin21_sql_runner.production().run(password.encode('ascii'),'auth',role)==role
