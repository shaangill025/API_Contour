"""Closed local capture profiles; no operator-supplied identities or paths."""
from pathlib import Path
from typing import NamedTuple

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'


class Profile(NamedTuple):
    name: str
    capture: Path
    collector: str
    source: str
    deployment: str
    instance: str
    nonce: str
    approved_names: tuple
    approved_route_segments: tuple


DEFAULT = Profile('default', STATE / 'capture',
    '00000000-0000-4000-8000-000000000201', '00000000-0000-4000-8000-000000000202',
    '00000000-0000-4000-8000-000000000203', '00000000-0000-4000-8000-000000000204',
    '00000000-0000-4000-8000-000000000205', ('GET','POST','id','name','status'), ('orders',))
PILOT = Profile('pilot', STATE / 'pilot' / 'capture',
    '00000000-0000-4000-8000-000000000301', '00000000-0000-4000-8000-000000000302',
    '00000000-0000-4000-8000-000000000303', '00000000-0000-4000-8000-000000000304',
    '00000000-0000-4000-8000-000000000305', ('POST','probe','result'), ('pilot',))


def select(name):
    if name == 'default': return DEFAULT
    if name == 'pilot': return PILOT
    raise ValueError('unknown capture profile')


def arguments(argv):
    if not argv: return DEFAULT
    if len(argv) == 2 and argv[0] == '--profile': return select(argv[1])
    raise ValueError('expected --profile default or --profile pilot')

# Source-only descriptor. It is deliberately excluded from select()/arguments()
# until the separate journaled setup and reconciliation path exists.
class OriginSlot(NamedTuple):
    deployment: str
    instance: str
    lifecycle: str
    credential: str
    grant: str
    leaf_der: Path


class OriginPilot(NamedTuple):
    capture: Profile
    state: Path
    ingress_login: str
    worker_login: str
    ingress_group: str
    worker_group: str
    origins: tuple


ORIGIN_STATE = STATE / 'origin-pilot'
ORIGIN_PILOT = OriginPilot(
    Profile('origin-pilot', ORIGIN_STATE / 'capture',
        '00000000-0000-4000-8000-000000000401', '00000000-0000-4000-8000-000000000402',
        '00000000-0000-4000-8000-000000000403', '00000000-0000-4000-8000-000000000404',
        '00000000-0000-4000-8000-000000000405', ('POST','probe','result'), ('pilot',)),
    ORIGIN_STATE, 'contour_local_origin_ingress', 'contour_local_origin_worker',
    'contour_origin_ingress', 'contour_catalog_worker',
    (OriginSlot('00000000-0000-4000-8000-000000000411', '00000000-0000-4000-8000-000000000412',
        '00000000-0000-4000-8000-000000000413', '00000000-0000-4000-8000-000000000414',
        '00000000-0000-4000-8000-000000000415', ORIGIN_STATE / 'replica1' / 'client.crt.der'),
     OriginSlot('00000000-0000-4000-8000-000000000421', '00000000-0000-4000-8000-000000000422',
        '00000000-0000-4000-8000-000000000423', '00000000-0000-4000-8000-000000000424',
        '00000000-0000-4000-8000-000000000425', ORIGIN_STATE / 'replica2' / 'client.crt.der')))
