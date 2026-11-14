"""Explicit operator-only stages for the separate local origin21 pilot.

Docker inspection establishes only the owned local deployment identity; it is
not hardware attestation. No command claims pilot or UI readiness.
"""
import os
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
from deploy.local import origin21_products, origin21_ready, origin21_setup, origin21_transport


def main(argv):
    if os.getuid()==0: raise RuntimeError('nonroot required')
    os.umask(0o077)
    if argv==['identities']:
        origin21_setup.prepare_identities(); return 'identities reconciled'
    if len(argv)==5 and argv[0] in ('products','companions'):
        _,image,head,receipt,digest=argv
        args=dict(app_image_id=image,build_head=head,build_receipt=receipt,build_receipt_sha256=digest)
        if argv[0]=='products': origin21_products.start_products(**args)
        else: origin21_products.start_companions(**args,psql=origin21_transport.admin,sensitive_execute=origin21_transport.sensitive,authenticate=origin21_transport.authenticate)
        return argv[0]+' reconciled'
    if len(argv)==3 and argv[0]=='--check-capture' and all(re.fullmatch('[0-9a-f]{64}',x) for x in argv[1:]):
        origin21_ready.check(tuple(bytes.fromhex(x) for x in argv[1:]),psql=origin21_transport.admin,
            sensitive_execute=origin21_transport.sensitive,authenticate=origin21_transport.authenticate)
        return 'capture qualification passed (UI not verified)'
    if len(argv)==3 and argv[0] in ('enroll','renew') and all(re.fullmatch('[0-9a-f]{64}',x) for x in argv[1:]):
        origin21_setup.prepare(psql=origin21_transport.admin,sensitive_execute=origin21_transport.sensitive,
            authenticate=origin21_transport.authenticate,inspect_slot=origin21_products.inspect_slot,
            expected_evidence=tuple(bytes.fromhex(x) for x in argv[1:]),renew=argv[0]=='renew')
        return argv[0]+' reconciled'
    raise ValueError('invalid origin21 command')


if __name__=='__main__':
    try: print('Origin21 '+main(sys.argv[1:])+'; no pilot readiness claim.')
    except Exception:
        print('Origin21 operation failed; state retained for operator inspection.',file=sys.stderr)
        raise SystemExit(1)
