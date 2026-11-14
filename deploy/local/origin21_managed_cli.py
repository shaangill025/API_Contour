"""Explicit one-shot managed Origin21 operator path.

Requires a separately owned managed PostgreSQL deployment and exact build
receipt. No operation runs on import. Unknown outcomes remain operator-blocked.
"""
import os
import re
import sys
from deploy.local import origin21_profile,origin21_products,origin21_ready,origin21_setup,origin21_transport


def main(argv,*,qualification=None):
    if os.getuid()==0: raise RuntimeError('nonroot required')
    os.umask(0o077); selected=origin21_profile.MANAGED
    from deploy.local.origin21_managed_qualification import require_matching
    require_matching(qualification)
    if len(argv)==5 and argv[0]=='up':
        _,image,head,receipt,digest=argv
        if not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not re.fullmatch(r'[0-9a-f]{40}',head) or not re.fullmatch(r'[0-9a-f]{64}',digest) or not os.path.isabs(receipt): raise ValueError('invalid managed build receipt')
        args={'app_image_id':image,'build_head':head,'build_receipt':receipt,'build_receipt_sha256':digest}
        deployment=origin21_products._build_receipt(image,head,receipt,digest,selected=selected)
        origin21_products._capture_network(deployment,selected=selected)
        origin21_setup.prepare_identities(selected=selected,**({'qualification':qualification} if qualification is not None else {}))
        expected=origin21_products.start_products(**args,selected=selected,**({'qualification':qualification} if qualification is not None else {}))
        transport=origin21_transport.managed_transport(image_id=image,head=head,receipt=receipt,digest=digest,**({'qualification':qualification} if qualification is not None else {}))
        origin21_setup.prepare(transport=transport,expected_evidence=expected,selected=selected)
        origin21_products.start_companions(**args,selected=selected,transport=transport)
        result=origin21_ready.check(expected,selected=selected,transport=transport)
        if result!={'product_tls_and_catalog_verified':True,'ui_verified':False}: raise RuntimeError('managed capture check failed')
        return 'managed Origin21 capture verified; UI not verified'
    if argv in (['renew-edge'],['rollback-edge']):
        from deploy.local import origin21_managed_controller
        with origin21_managed_controller.open_edge(**({'qualification':qualification} if qualification is not None else {})) as owner:
            if argv[0]=='renew-edge': owner.renew()
            else: owner.rollback()
        return 'managed edge transition confirmed'
    raise ValueError('invalid managed command')


if __name__=='__main__':
    try: print(main(sys.argv[1:]))
    except Exception:
        print('managed Origin21 operation failed; state retained',file=sys.stderr)
        raise SystemExit(1) from None
