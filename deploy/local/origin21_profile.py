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
