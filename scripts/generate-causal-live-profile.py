#!/usr/bin/env python3
"""Reproduce the closed candidate 503 assets; this does not qualify a runtime."""
import hashlib
import json
from pathlib import Path
import sys

ROOT=Path(__file__).resolve().parents[1]
LIVE=ROOT/'collectors/nodered/live-integration'
IMAGE='docker.io/nodered/node-red:5.0.9@sha256:e085d4a06591fd0aca2ea2a91364d27f1a0e31e885675f77935e10f95412a963'
ERROR_FILES=('causal-marker.js','flow-source-transform.js','lexical-bridge.js','node-source-transform.js','private-causal-exporter.js','private-causal-receipt.js','private-handoff.js','private-owner-permit.js','private-producer-runtime.js','private-wire-dispatch.js','private-wire-transform.js','wire-v2-loader.js')
LIVE_FILES=('credential-check.js','lifecycle.js','live-main.js','live-profile.js','private-bootstrap.js','private-launch-proxy.js')
def sha(b):return hashlib.sha256(b).hexdigest()
def canonical(x):return json.dumps(x,ensure_ascii=True,separators=(',',':')).encode('ascii')
def assets():
    flow=json.loads((ROOT/'tests/fixtures/nodered-causal/flows-wire-v2.json').read_bytes())
    for node in flow:
        if node['id']=='tab':node['label']='APIContour causal pilot'
        if node['id']=='request':node['url']='https://pilot-gateway:9443/pilot'
        if node['type']=='tls-config':
            node.update(cert='/run/apicontour/live/product.pem',key='/run/apicontour/live/product.key',ca='/run/apicontour/live/ca.pem',servername='pilot-gateway',name='APIContour product identity')
    flow_bytes=canonical(flow)
    sources=['/adapter/causal-codec.js']+['/adapter/error-integration/'+n for n in ERROR_FILES]+['/adapter/live-integration/'+n for n in LIVE_FILES]
    files={path:sha((ROOT/'collectors/nodered'/path.removeprefix('/adapter/')).read_bytes()) for path in sorted(sources)}
    trees={}
    for arch,name in [('arm64','wire-v2-image-manifest.json'),('x64','wire-v2-image-manifest-x64.json')]:
        trees[arch]={'path':'/adapter/live-integration/tree-'+arch+'.json','sha256':sha((ROOT/'collectors/nodered/error-integration'/name).read_bytes())}
    env=dict(FLOWS='flows.json',HOME='/data',HOSTNAME='causal-live',LANG='C.UTF-8',NODE_PATH='/usr/src/node-red/node_modules',NODE_RED_VERSION='v5.0.9',NODE_VERSION='24.22.1',PATH='/usr/src/node-red/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',TZ='UTC',YARN_VERSION='1.22.22')
    mounts=dict(ca='/run/apicontour/live/ca.pem',export_cert='/run/apicontour/live/export.pem',export_key='/run/apicontour/live/export.key',product_cert='/run/apicontour/live/product.pem',product_key='/run/apicontour/live/product.key',server_cert='/run/apicontour/live/server.pem',server_key='/run/apicontour/live/server.key')
    m=dict(arch_trees=trees,capture=dict(method='POST',node='in',url='/run'),env=env,export_endpoint='https://causal-ingress:8443/v1/causal-events',files=files,flow_sha256=sha(flow_bytes),image=IMAGE,mounts=mounts,node='24.22.1',nodes=[[n['id'],n['type']] for n in flow if n['type'] not in ('tab','tls-config')],product_endpoint='https://pilot-gateway:9443/pilot',profile_id='00000000-0000-4000-8000-000000000503',profile_name='nodered_5_0_9_wire_v1',version=1)
    return {'flows.json':flow_bytes,'manifest.json':canonical(m)}
def main():
    if sys.argv[1:] not in ([],['--check']):raise SystemExit('usage: generate-causal-live-profile.py [--check]')
    generated=assets()
    if sys.argv[1:]:
        for name,data in generated.items():
            if (LIVE/name).read_bytes()!=data:raise SystemExit('candidate asset drift: '+name)
    else:
        for name,data in generated.items():(LIVE/name).write_bytes(data)
    print('candidate503 manifest SHA256 '+sha(generated['manifest.json']))
if __name__=='__main__':main()
