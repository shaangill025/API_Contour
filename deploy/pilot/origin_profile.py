"""Closed, source-only configuration for the future local origin pilot.

These builders do not provision credentials, authorize origins, or start services.
The leaf paths describe operator-owned DER inputs, not platform attestation.
"""
from deploy.local import capture_profiles, capture_provision
from deploy.pilot import native_envoy, native_gateway_config


def configs(profile=capture_profiles.ORIGIN_PILOT):
    # No caller-supplied identities, paths or role names are accepted.
    if profile is not capture_profiles.ORIGIN_PILOT:
        raise ValueError('unsupported origin profile')
    capture = profile.capture
    ingress = capture_provision.runtime_configs(capture.collector)
    ingress['ingress.json']['database_user'] = profile.ingress_login
    ingress['ingress.json']['ingestion_profile'] = 'origin_v2'
    ingress['worker.json']['database_user'] = profile.worker_login
    tenant, project, service, environment = capture_provision.base.IDS
    gateway = native_gateway_config.config(
        upstream_ip='pilot-destination', delivery_ip='origin-capture-ingress',
        delivery_name='ingress', tenant=tenant, collector=capture.collector,
        source=capture.source, workload=[project, service, environment, capture.deployment],
        policy_key_id='local')
    gateway['capture_wire_version'] = 'v2'
    return {'capture': ingress, 'gateway': gateway,
            'envoy': native_envoy.config(origin_v2=True)}
