"""Create one owned pilot credential set; never replace existing state."""
import os
from pathlib import Path
import secrets
import subprocess

ROOT = Path(__file__).resolve().parents[2]
STATE = ROOT / '.local-mvp'
PILOT = STATE / 'pilot'


def openssl(*args):
    result = subprocess.run(['openssl', *map(str,args)],capture_output=True,timeout=30)
    if result.returncode:
        raise RuntimeError('pilot certificate generation failed; partial state retained')


def main():
    os.umask(0o077)
    if not (STATE/'ca.crt').is_file() or not (STATE/'ca.key').is_file():
        raise RuntimeError('existing local development CA is required')
    PILOT.mkdir(mode=0o700)  # Do not overwrite or silently regenerate identity.
    scratch=PILOT/'issuer-work'; scratch.mkdir(mode=0o700)
    (scratch/'request.cnf').write_text('[req]\ndistinguished_name=dn\n[dn]\n')
    def certificate(directory, name, purpose, san):
        ext=scratch/(name+'.cnf')
        ext.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage='+purpose+'\nsubjectAltName='+san+'\n')
        key=directory/(name+'.key'); csr=scratch/(name+'.csr'); cert=directory/(name+'.crt')
        openssl('req','-new','-newkey','rsa:3072','-nodes','-sha256','-config',scratch/'request.cnf',
                '-subj','/CN=local-owned-pilot','-keyout',key,'-out',csr)
        openssl('x509','-req','-sha256','-in',csr,'-CA',STATE/'ca.crt','-CAkey',STATE/'ca.key',
                '-set_serial',str(secrets.randbits(127)+1),'-days','7','-extfile',ext,'-out',cert)
    for name in ['replica1','replica2']:
        directory=PILOT/name; directory.mkdir(mode=0o700)
        certificate(directory,'client','clientAuth','DNS:'+name)
        certificate(directory,'server','serverAuth','DNS:localhost,DNS:'+name+',IP:127.0.0.1')
    destination=PILOT/'destination'; destination.mkdir(mode=0o700)
    certificate(destination,'server','serverAuth','DNS:pilot-destination')
    print('Owned pilot credentials created; private keys remain in local state.')

if __name__=='__main__': main()
