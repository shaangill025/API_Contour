"""Closed descriptor for a future separate local version-21 origin pilot.

A descriptor grants no enrollment or permission. This module performs no I/O.
"""
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp' / 'origin21-pilot'


class Origin(NamedTuple):
    deployment: str
    instance: str
    lifecycle: str
    credential: str
    grant: str
    leaf_der: Path


class Profile(NamedTuple):
    name: str
    state: Path
    capture: Path
    collector: str
    source: str
    deployment: str
    instance: str
    nonce: str
    approved_names: tuple
    approved_route_segments: tuple
    ingress_login: str
    worker_login: str
    origins: tuple


PROFILE = Profile(
    'origin21-pilot', STATE, STATE/'capture',
    '00000000-0000-4000-8000-00000000f201',
    '00000000-0000-4000-8000-00000000f202',
    '00000000-0000-4000-8000-00000000f203',
    '00000000-0000-4000-8000-00000000f204',
    '00000000-0000-4000-8000-00000000f205', ('POST','probe','result'), ('pilot',),
    'contour_local_origin21_ingress', 'contour_local_origin21_worker',
    (Origin('00000000-0000-4000-8000-00000000f211',
            '00000000-0000-4000-8000-00000000f212',
            '00000000-0000-4000-8000-00000000f213',
            '00000000-0000-4000-8000-00000000f214',
            '00000000-0000-4000-8000-00000000f215', STATE/'replica1'/'client.crt.der'),
     Origin('00000000-0000-4000-8000-00000000f221',
            '00000000-0000-4000-8000-00000000f222',
            '00000000-0000-4000-8000-00000000f223',
            '00000000-0000-4000-8000-00000000f224',
            '00000000-0000-4000-8000-00000000f225', STATE/'replica2'/'client.crt.der')))

# Immutable shape expected by the audited origin operation helpers. It is
# distinct from ORIGIN_PILOT and is never installed into that module's globals.
from deploy.local import capture_profiles as _legacy_profiles
_CAPTURE = _legacy_profiles.Profile(PROFILE.name, PROFILE.capture, PROFILE.collector, PROFILE.source,
    PROFILE.deployment, PROFILE.instance, PROFILE.nonce, PROFILE.approved_names, PROFILE.approved_route_segments)
BOUND = _legacy_profiles.OriginPilot(_CAPTURE, PROFILE.state, PROFILE.ingress_login, PROFILE.worker_login,
    'contour_origin_ingress', 'contour_catalog_worker', PROFILE.origins)

# Only these fixed contexts are authorities; equal reconstructed tuples are not.
class Context(NamedTuple):
    profile: Profile
    bound: _legacy_profiles.OriginPilot
    project: str
    network: str
    owner: Path
    compose: Path
    edge: Path


MANAGED_STATE = ROOT / '.local-mvp-managed' / 'origin21-pilot'
MANAGED_PROFILE = PROFILE._replace(
    name='origin21-managed-pilot', state=MANAGED_STATE, capture=MANAGED_STATE/'capture',
    origins=tuple(slot._replace(leaf_der=MANAGED_STATE/('replica'+str(i))/'client.crt.der')
                  for i,slot in enumerate(PROFILE.origins,1)))
_MANAGED_CAPTURE = _legacy_profiles.Profile(MANAGED_PROFILE.name,MANAGED_PROFILE.capture,MANAGED_PROFILE.collector,
    MANAGED_PROFILE.source,MANAGED_PROFILE.deployment,MANAGED_PROFILE.instance,MANAGED_PROFILE.nonce,
    MANAGED_PROFILE.approved_names,MANAGED_PROFILE.approved_route_segments)
MANAGED_BOUND = _legacy_profiles.OriginPilot(_MANAGED_CAPTURE,MANAGED_PROFILE.state,MANAGED_PROFILE.ingress_login,
    MANAGED_PROFILE.worker_login,'contour_origin_ingress','contour_catalog_worker',MANAGED_PROFILE.origins)
STATIC = Context(PROFILE,BOUND,'apicontour-origin21','apicontour-origin21_default',STATE.parent/'origin21-products',
                 ROOT/'deploy/local/origin21-compose.yaml',STATE.parent/'unused-static-edge')
MANAGED = Context(MANAGED_PROFILE,MANAGED_BOUND,'apicontour-origin21-managed','apicontour-origin21-managed_default',
                  MANAGED_STATE.parent/'origin21-products',ROOT/'deploy/local/origin21-managed-compose.yaml',MANAGED_STATE.parent/'managed-edge')


HUMAN_STATE = ROOT / '.local-mvp-managed-human' / 'origin21-pilot'
HUMAN_PROFILE = PROFILE._replace(
    name='origin21-managed-human-pilot', state=HUMAN_STATE, capture=HUMAN_STATE/'capture',
    origins=tuple(slot._replace(leaf_der=HUMAN_STATE/('replica'+str(i))/'client.crt.der')
                  for i,slot in enumerate(PROFILE.origins,1)))
_HUMAN_CAPTURE = _legacy_profiles.Profile(HUMAN_PROFILE.name,HUMAN_PROFILE.capture,HUMAN_PROFILE.collector,
    HUMAN_PROFILE.source,HUMAN_PROFILE.deployment,HUMAN_PROFILE.instance,HUMAN_PROFILE.nonce,
    HUMAN_PROFILE.approved_names,HUMAN_PROFILE.approved_route_segments)
HUMAN_BOUND = _legacy_profiles.OriginPilot(_HUMAN_CAPTURE,HUMAN_PROFILE.state,HUMAN_PROFILE.ingress_login,
    HUMAN_PROFILE.worker_login,'contour_origin_ingress','contour_catalog_worker',HUMAN_PROFILE.origins)
HUMAN = Context(HUMAN_PROFILE,HUMAN_BOUND,'apicontour-origin21-managed-human',
                'apicontour-origin21-managed-human_default',HUMAN_STATE.parent/'origin21-products',
                ROOT/'deploy/local/origin21-managed-human-compose.yaml',HUMAN_STATE.parent/'managed-edge')


def require_context(context):
    if context is not STATIC and context is not MANAGED and context is not HUMAN: raise ValueError('unsupported origin21 context')
    return context


def context_for_profile(profile):
    if profile is PROFILE: return STATIC
    if profile is MANAGED_PROFILE: return MANAGED
    if profile is HUMAN_PROFILE: return require_context(HUMAN)
    raise ValueError('unsupported origin21 profile')


def context_for_bound(profile):
    if profile is BOUND: return STATIC
    if profile is MANAGED_BOUND: return MANAGED
    if profile is HUMAN_BOUND: return require_context(HUMAN)
    raise ValueError('unsupported origin21 bound profile')


def context_for_capture(profile):
    if profile is BOUND.capture: return STATIC
    if profile is MANAGED_BOUND.capture: return MANAGED
    if profile is HUMAN_BOUND.capture: return require_context(HUMAN)
    raise ValueError('unsupported origin21 capture profile')
