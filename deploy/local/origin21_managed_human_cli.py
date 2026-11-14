"""One-shot closed managed-human pilot; partial state is retained."""
import os
import re
import sys
from deploy.local import (origin21_managed_human_services, origin21_managed_init, origin21_products,
                          origin21_profile, origin21_setup, origin21_transport)


def main(argv):
    selected=origin21_profile.HUMAN
    origin21_profile.require_context(selected)
    if os.getuid()==0: raise ValueError('nonroot required')
    if len(argv)!=4: raise ValueError('expected reviewed build evidence')
    image,head,receipt,digest=argv
    if (not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not re.fullmatch('[0-9a-f]{40}',head) or
        not os.path.isabs(receipt) or not re.fullmatch('[0-9a-f]{64}',digest)):
        raise ValueError('invalid reviewed build evidence')
    path,runtime_digest=origin21_managed_init.initialize(image_id=image,head=head,build_receipt=receipt,
        build_receipt_sha256=digest,selected=selected)
    args={'app_image_id':image,'build_head':head,'build_receipt':str(path),'build_receipt_sha256':runtime_digest,'selected':selected}
    origin21_setup.prepare_identities(selected=selected)
    expected=origin21_products.start_products(**args)
    transport=origin21_transport.managed_transport(image_id=image,head=head,receipt=str(path),digest=runtime_digest,selected=selected)
    origin21_setup.prepare(transport=transport,expected_evidence=expected,selected=selected)
    origin21_products.start_companions(**args,transport=transport)
    return origin21_managed_human_services.start(expected,transport)


if __name__=='__main__':
    try: print(main(sys.argv[1:]))
    except Exception:
        print('Managed human pilot failed; private state retained.',file=sys.stderr)
        raise SystemExit(1) from None
