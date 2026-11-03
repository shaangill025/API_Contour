"""Synthetic fixture hook; caller supplies an owned temporary profile and CA.

No containers, connections or CA creation. Caller owns and removes all fixture
material; this hook never prints identity bytes, passwords or keys.
"""
import hashlib
import os
import tempfile
from pathlib import Path
from unittest import mock
from deploy.local import capture_profiles
from deploy.pilot import origin_credentials as credentials, origin_setup_state as journal


class _SchemaPhase:
    def __init__(self): self.value=journal.ABSENT
    def inspect(self): return self.value
    def apply(self): self.value=journal.EXACT


def _issue_fixture(ca_cert, ca_key, key_bytes, *, san, purpose, start, end):
    """Issue one disposable variant using only the caller's synthetic CA."""
    with tempfile.TemporaryDirectory(prefix='origin-variant-') as directory:
        d=Path(directory); (d/'new').mkdir(); (d/'index').write_text(''); (d/'serial').write_text('01\n')
        key=d/'key.pem'; key.write_bytes(key_bytes); os.chmod(key,0o600)
        request=d/'request.cnf'; request.write_text('[req]\ndistinguished_name=dn\n[dn]\n')
        csr=d/'request.csr'
        credentials._run('req','-new','-sha256','-key',key,'-config',request,'-subj','/CN=local-origin-fixture','-out',csr)
        config=d/'ca.cnf'
        config.write_text('[ca]\ndefault_ca=fixture\n[fixture]\ndatabase='+str(d/'index')+
            '\nnew_certs_dir='+str(d/'new')+'\nserial='+str(d/'serial')+
            '\ndefault_md=sha256\npolicy=policy\nunique_subject=no\n[policy]\ncommonName=supplied\n[leaf]\n'
            'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n'
            'extendedKeyUsage='+purpose+'\nsubjectAltName='+san+'\n')
        cert=d/'cert.pem'
        credentials._run('ca','-batch','-notext','-config',config,'-cert',ca_cert,'-keyfile',ca_key,
            '-in',csr,'-out',cert,'-extensions','leaf','-startdate',start,'-enddate',end)
        return cert.read_bytes(),credentials._run('x509','-in',cert,'-outform','DER')


def run_cases(profile, ca_cert, ca_key, wrong_ca_cert=None):
    with mock.patch.object(capture_profiles,'ORIGIN_PILOT',profile):
        op=credentials.Credentials(profile,ca_cert,ca_key)
        ops={name:_SchemaPhase() for name in journal.SCHEMA_PHASES}; ops['credentials']=op
        real_apply=op.apply
        def lost_ack():
            real_apply()
            raise RuntimeError('fixture lost ack')
        op.apply=lost_ack
        try: journal.run(profile,ops,through_credentials=True)
        except RuntimeError as error:
            if str(error)!='fixture lost ack': raise
        else: raise AssertionError('fixture expected lost ACK')
        if op.inspect()!=journal.EXACT: raise AssertionError('generated bundle rejected')
        before=op.commitment(); op.apply=real_apply
        journal.run(profile,ops,through_credentials=True)
        if op.commitment()!=before: raise AssertionError('bundle identity changed on retry')
        journal.run(profile,ops,through_credentials=True)
        if op.commitment()!=before: raise AssertionError('bundle identity changed on restart')
        root=profile.state
        def changed(path,data):
            original=path.read_bytes()
            try:
                path.write_bytes(data)
                if op.inspect()!=journal.DRIFT: raise AssertionError('credential drift accepted')
            finally: path.write_bytes(original)
        changed(root/'replica1/client.crt',(root/'replica2/client.crt').read_bytes())
        changed(root/'capture/runtime/server.crt.der',b'wrong copy')
        changed(root/'capture/runtime/policy.raw',b'x'*32)
        changed(root/'capture/private/collector.key',(root/'capture/private/server.key').read_bytes())
        # Replace replica2 coherently (key, PEM and DER), so these tests do not
        # pass merely because copies or key/cert mismatch.
        cert_path=root/'replica2/client.crt'; key_path=root/'replica2/client.key'; der_path=root/'replica2/client.crt.der'
        original={path:path.read_bytes() for path in (cert_path,key_path,der_path)}
        replica1_key=(root/'replica1/client.key').read_bytes()
        def variant(key_bytes, *, san='DNS:replica2', purpose='clientAuth', start='200101000000Z', end='490101000000Z', expected=None):
            cert,der=_issue_fixture(ca_cert,ca_key,key_bytes,san=san,purpose=purpose,start=start,end=end)
            try:
                cert_path.write_bytes(cert); key_path.write_bytes(key_bytes); der_path.write_bytes(der)
                if op.inspect()!=journal.DRIFT: raise AssertionError('credential variant accepted')
                if expected is not None:
                    try: op._verify()
                    except ValueError as error:
                        if str(error)!=expected: raise AssertionError('variant failed for unexpected reason') from None
                    else: raise AssertionError('variant unexpectedly verified')
            finally:
                for path,data in original.items(): path.write_bytes(data)
        # A different leaf certificate with the same SPKI must fail on the
        # explicit unique-key rule, after all per-leaf checks have passed.
        variant(replica1_key, expected='duplicate identity')
        replica2_key=original[key_path]
        variant(replica2_key,san='DNS:wrong-replica',expected='leaf SAN drift')
        variant(replica2_key,purpose='serverAuth',expected='credential cryptographic validation failed')
        variant(replica2_key,start='200101000000Z',end='210101000000Z',expected='credential cryptographic validation failed')
        variant(replica2_key,start='480101000000Z',end='490101000000Z',expected='credential cryptographic validation failed')
        if wrong_ca_cert is not None:
            wrong=credentials.Credentials(profile,wrong_ca_cert,ca_key)
            if wrong.inspect()!=journal.DRIFT: raise AssertionError('wrong CA accepted')
        target=root/'replica1/client.crt'
        os.chmod(target,0o644)
        try:
            if op.inspect()!=journal.DRIFT: raise AssertionError('unsafe mode accepted')
        finally: os.chmod(target,0o600)
        saved=target.read_bytes()
        target.unlink(); target.symlink_to(root/'replica2/client.crt')
        try:
            if op.inspect()!=journal.DRIFT: raise AssertionError('symlink accepted')
        finally:
            target.unlink(); target.write_bytes(saved); os.chmod(target,0o600)
        target.unlink(); os.link(root/'replica2/client.crt',target)
        try:
            if op.inspect()!=journal.DRIFT: raise AssertionError('hardlink accepted')
        finally:
            target.unlink(); target.write_bytes(saved); os.chmod(target,0o600)
        extra=root/'unexpected'; extra.write_bytes(b'fixture'); os.chmod(extra,0o600)
        try:
            if op.inspect()!=journal.DRIFT: raise AssertionError('unexpected file accepted')
        finally: extra.unlink()
        if op.inspect()!=journal.EXACT or op.commitment()!=before: raise AssertionError('fixture failed to restore')
    with tempfile.TemporaryDirectory(prefix='origin-partial-') as directory:
        partial_root=Path(directory)/'origin-pilot'; partial_root.mkdir(mode=0o700)
        partial_profile=profile._replace(state=partial_root)
        with mock.patch.object(capture_profiles,'ORIGIN_PILOT',partial_profile):
            partial=credentials.Credentials(partial_profile,ca_cert,ca_key)
            phases={name:_SchemaPhase() for name in journal.SCHEMA_PHASES}; phases['credentials']=partial
            original_write=credentials._write; writes=[]
            def fail_second(path,data):
                if partial_root in path.parents:
                    writes.append(path)
                    if len(writes)==2: raise OSError('fixture interrupted')
                original_write(path,data)
            with mock.patch.object(credentials,'_write',side_effect=fail_second):
                try: journal.run(partial_profile,phases,through_credentials=True)
                except OSError: pass
                else: raise AssertionError('partial generation did not stop')
            if partial.inspect()!=journal.DRIFT: raise AssertionError('partial bundle accepted')
            first=writes[0]; digest=hashlib.sha256(first.read_bytes()).digest()
            try: journal.run(partial_profile,phases,through_credentials=True)
            except ValueError: pass
            else: raise AssertionError('partial bundle reissued')
            if hashlib.sha256(first.read_bytes()).digest()!=digest: raise AssertionError('partial identity overwritten')
    return 'synthetic origin credential fixture passed'
