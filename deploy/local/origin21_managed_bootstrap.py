"""One-shot managed Origin21 bootstrap from exact reviewed build evidence.

No work runs on import. Unknown outcomes retain the separate managed state.
"""
import os
import re
import sys
from deploy.local import origin21_managed_cli,origin21_managed_init,origin21_state

SOURCE='deploy/local/origin21_managed_bootstrap.py'


def main(argv):
    if os.getuid()==0: raise RuntimeError('nonroot required')
    if SOURCE not in origin21_state.MANAGED_SOURCE_FILES: raise RuntimeError('managed bootstrap source not pinned')
    if len(argv)!=4: raise ValueError('expected build evidence')
    image,head,receipt,digest=argv
    if not re.fullmatch(r'sha256:[0-9a-f]{64}',image) or not re.fullmatch(r'[0-9a-f]{40}',head) or not os.path.isabs(receipt) or not re.fullmatch(r'[0-9a-f]{64}',digest): raise ValueError('invalid build evidence')
    path,runtime_digest=origin21_managed_init.initialize(image_id=image,head=head,build_receipt=receipt,build_receipt_sha256=digest)
    return origin21_managed_cli.main(['up',image,head,str(path),runtime_digest])


if __name__=='__main__':
    try: print(main(sys.argv[1:]))
    except Exception:
        print('managed Origin21 bootstrap failed; private state retained',file=sys.stderr)
        raise SystemExit(1) from None
