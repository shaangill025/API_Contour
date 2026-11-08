"""Closed v21 runtime configuration builder; this does not start a service.

Enrollment, credentials and readiness remain unavailable until their respective
operator-owned controllers and independently captured references exist.
"""
from deploy.local import capture_provision, origin21_profile
from deploy.pilot import native_envoy, native_gateway_config


def configs(profile=origin21_profile.PROFILE):
    context=origin21_profile.context_for_profile(profile)
    ingress=capture_provision.runtime_configs(profile.collector)
    ingress['ingress.json']['database_user']=profile.ingress_login
    ingress['ingress.json']['ingestion_profile']='origin_v2'
    ingress['worker.json']['database_user']=profile.worker_login
    tenant,project,service,environment=capture_provision.base.IDS
    gateway=native_gateway_config.config(upstream_ip='pilot-destination',delivery_ip='origin21-capture-ingress',
        delivery_name='ingress',tenant=tenant,collector=profile.collector,source=profile.source,
        workload=[project,service,environment,profile.deployment],policy_key_id='local')
    gateway['capture_wire_version']='v2'
    return {'capture':ingress,'gateway':gateway,'envoy':native_envoy.config(origin_v2=True,managed_edge=context is origin21_profile.MANAGED)}
