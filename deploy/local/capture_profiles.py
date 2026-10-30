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
