"""Construct the owned pilot gateway configuration without reading secrets."""
import ipaddress
import re
import uuid


def _address(host, port):
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError('invalid port')
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        labels = host.split('.')
        if len(host) > 253 or any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', label) for label in labels):
            raise ValueError('invalid hostname') from None
        return f'{host}:{port}'
    return f'[{address}]:{port}' if address.version == 6 else f'{address}:{port}'


def _id(value):
    parsed = uuid.UUID(value)
    if str(parsed) != value:
        raise ValueError('ID must be a canonical UUID')
    return value


def config(*, upstream_ip, delivery_ip, delivery_name, tenant, collector, source,
           workload, policy_key_id, slots=4, records_per_slot=16, bytes_per_slot=16384):
    if len(workload) != 4 or not 1 <= slots <= 8 or records_per_slot <= 0 or bytes_per_slot <= 0:
        raise ValueError('invalid capture scope or pool size')
    if not delivery_name or not policy_key_id:
        raise ValueError('invalid delivery configuration')
    return {
        'listen': '0.0.0.0:9443',
        'server_certificate_der': '/run/native/server.der',
        'server_key_der': '/run/native/server-key.der',
        'forwarder_ca_der': '/run/native/forwarder-ca.der',
        'forwarder_leaf_der': '/run/native/forwarder.der',
        'upstream_address': _address(upstream_ip, 9443),
        'upstream_name': 'pilot-destination',
        'upstream_ca_der': '/run/native/upstream-ca.der',
        'upstream_client_certificate_der': '/run/native/upstream-client.der',
        'upstream_client_key_der': '/run/native/upstream-client-key.der',
        'delivery_address': _address(delivery_ip, 9445),
        'delivery_name': delivery_name,
        'delivery_ca_der': '/run/native/delivery-ca.der',
        'delivery_client_certificate_der': '/run/native/collector.der',
        'delivery_client_key_der': '/run/native/collector-key.der',
        'tenant': _id(tenant), 'collector': _id(collector), 'source': _id(source),
        'workload': [_id(item) for item in workload],
        'policy_key_id': policy_key_id,
        'policy_key_file': '/run/native/policy-public-key.bin',
        'method': 'POST', 'path': '/pilot', 'route': '/pilot',
        'parser_profile': 'http_json_v1', 'slots': slots,
        'records_per_slot': records_per_slot, 'bytes_per_slot': bytes_per_slot,
    }
