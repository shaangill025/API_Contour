"""Bounded checks against an already running owned pilot; no payload logging."""
import argparse
import contextlib
import http.client
import os
from pathlib import Path
import signal
import ssl
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/pilot/compose.yaml')]


class Deadline(Exception): pass


@contextlib.contextmanager
def absolute_timeout(seconds):
    previous=signal.getsignal(signal.SIGALRM)
    if signal.getitimer(signal.ITIMER_REAL)!=(0.0,0.0): raise RuntimeError('deadline timer already active')
    def expired(_signal,_frame): raise Deadline()
    signal.signal(signal.SIGALRM,expired)
    try:
        signal.setitimer(signal.ITIMER_REAL,seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL,0)
        signal.signal(signal.SIGALRM,previous)


def run(command,timeout=20):
    result=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout)
    if result.returncode: raise RuntimeError('owned pilot check command failed')
    return result.stdout


def request(port,path,context,timeout=5):
    # The timer covers DNS, TLS, headers and all response chunks, not inactivity.
    with absolute_timeout(timeout):
        conn=http.client.HTTPSConnection('localhost',port,context=context,timeout=timeout)
        try:
            conn.request('GET',path,headers={'Connection':'close'})
            response=conn.getresponse(); data=response.read(1025)
            if len(data)>1024: raise RuntimeError('pilot response limit')
            return response.status,data
        finally: conn.close()


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--expect',choices=['normal','wrong-name','wrong-ca','redirect'],default='normal')
    mode=parser.parse_args().expect
    os.environ['LOCAL_UID']=str(os.getuid()); os.environ['LOCAL_GID']=str(os.getgid())
    context=ssl.create_default_context(cafile=str(ROOT/'.local-mvp/ca.crt'))
    for name,port in [('replica1',18811),('replica2',18812)]:
        version=run(COMPOSE+['exec','-T',name,'node','-p',"require('/usr/src/node-red/node_modules/node-red/package.json').version"])
        if version.strip()!=b'5.0.9': raise RuntimeError('unexpected Node-RED version')
        end=time.monotonic()+30; last_status=None; last_match=False; last_exception='none'
        while time.monotonic()<end:
            try:
                status,body=request(port,'/pilot',context,timeout=min(5,max(.001,end-time.monotonic())))
                wanted_status=200 if mode=='normal' else 302 if mode=='redirect' else 502
                wanted_body=b'{"result":"owned-pilot-ok"}' if mode=='normal' else b'{"result":"redirect"}' if mode=='redirect' else b'{"error":"upstream_unavailable"}'
                last_status=status; last_match=(body==wanted_body); last_exception='none'
                if status==wanted_status and last_match: break
            except (OSError,ssl.SSLError,http.client.HTTPException,Deadline) as error:
                last_exception=type(error).__name__
            if time.monotonic()<end: time.sleep(min(.25,end-time.monotonic()))
        else:
            raise RuntimeError('pilot readiness failed: status=%s expected_body=%s exception=%s' % (last_status,last_match,last_exception))
        status,_=request(port,'/flows',context)
        if status==200: raise RuntimeError('admin API unexpectedly enabled')
        if mode=='normal':
            if run(COMPOSE+['exec','-T',name,'node','/pilot/check_tls.js']).strip()!=b'PASS':
                raise RuntimeError('pilot TLS check failed')
        if mode=='redirect':
            if run(COMPOSE+['exec','-T',name,'node','/pilot/check_tls.js','--redirect-check']).strip()!=b'PASS':
                raise RuntimeError('redirect reached disallowed endpoint')
    print('Both owned replicas passed the selected bounded pilot check.')

if __name__=='__main__': main()
