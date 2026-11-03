"""Opt-in Envoy edge configuration for the owned native pilot.

This produces configuration only; certificate provisioning and execution are
separate operator actions. It never reads credentials or payloads.
"""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from deploy.gateway.config import IMAGE, config as base_config


def config(*, origin_v2=False):
    if type(origin_v2) is not bool:
        raise ValueError("invalid origin profile")
    result = base_config('native-gateway', 9443, 'native-gateway.test',
                         ca='/run/forwarder/observer-ca.pem', listen_port=9443)
    chain = result['static_resources']['listeners'][0]['filter_chains'][0]
    tls = chain['transport_socket']['typed_config']
    common = tls['common_tls_context']
    common['tls_certificates'] = [{'certificate_chain': {'filename': '/run/forwarder/edge.pem'},
                                   'private_key': {'filename': '/run/forwarder/edge.key'}}]
    common['validation_context'] = {'trusted_ca': {'filename': '/run/forwarder/pilot-ca.pem'}}
    tls['require_client_certificate'] = True
    manager = chain['filters'][0]['typed_config']
    manager['route_config']['virtual_hosts'][0]['domains'] = ['*']
    manager['forward_client_cert_details'] = 'SANITIZE'
    if origin_v2:
        manager['route_config']['request_headers_to_add'] = [{
            'header': {'key': 'x-contour-origin-witness', 'value': '%DOWNSTREAM_PEER_FINGERPRINT_256%'},
            'append_action': 'OVERWRITE_IF_EXISTS_OR_ADD', 'keep_empty_value': True}]
    cluster = result['static_resources']['clusters'][0]
    upstream = cluster['transport_socket']['typed_config']['common_tls_context']
    upstream['tls_certificates'] = [{'certificate_chain': {'filename': '/run/forwarder/forwarder.pem'},
                                      'private_key': {'filename': '/run/forwarder/forwarder.key'}}]
    upstream['alpn_protocols'] = ['http/1.1']
    return result


if __name__ == '__main__':
    if len(sys.argv) != 1:
        raise SystemExit('no arguments expected')
    print(json.dumps(config(), separators=(',', ':')))
