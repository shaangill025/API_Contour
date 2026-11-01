"""Bounded checks against the already running owned private-network pilot."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time

ROOT=Path(__file__).resolve().parents[2]
COMPOSE=['docker','compose','-f',str(ROOT/'deploy/pilot/compose.yaml')]


def run(command,timeout=20):
    result=subprocess.run(command,cwd=ROOT,capture_output=True,timeout=timeout)
    if result.returncode: raise RuntimeError('owned pilot check command failed')
    return result.stdout


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--expect',choices=['normal','wrong-name','wrong-ca','redirect'],default='normal')
    mode=parser.parse_args().expect
    os.environ['LOCAL_UID']=str(os.getuid()); os.environ['LOCAL_GID']=str(os.getgid())
    for name in ['replica1','replica2']:
        version=run(COMPOSE+['exec','-T',name,'node','-p',"require('/usr/src/node-red/node_modules/node-red/package.json').version"])
        if version.strip()!=b'5.0.9': raise RuntimeError('unexpected Node-RED version')
        end=time.monotonic()+30; last={'status':None,'expected_body':False,'exception':'not_started'}
        while time.monotonic()<end:
            try:
                raw=run(COMPOSE+['exec','-T',name,'node','/pilot/probe.js',mode],timeout=min(10,max(.1,end-time.monotonic())))
                if len(raw)>1024: raise RuntimeError('probe result limit')
                last=json.loads(raw)
                if last.get('expected_body') and last.get('admin_status') in (400,404) and last.get('admin_exception')=='none': break
            except (subprocess.TimeoutExpired,ValueError,RuntimeError) as error:
                last={'status':None,'expected_body':False,'exception':type(error).__name__}
            if time.monotonic()<end: time.sleep(min(.25,end-time.monotonic()))
        else:
            # Never print response contents, URLs, identities or credentials.
            raise RuntimeError('pilot readiness failed: status=%s expected_body=%s exception=%s' %
                (last.get('status'),last.get('expected_body'),last.get('exception')))
        if mode=='normal':
            if run(COMPOSE+['exec','-T',name,'node','/pilot/check_tls.js']).strip()!=b'PASS':
                raise RuntimeError('pilot TLS check failed')
        if mode=='redirect':
            if run(COMPOSE+['exec','-T',name,'node','/pilot/check_tls.js','--redirect-check']).strip()!=b'PASS':
                raise RuntimeError('redirect reached disallowed endpoint')
    print('Both owned replicas passed the selected bounded pilot check.')

if __name__=='__main__': main()
