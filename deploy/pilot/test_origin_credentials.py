"""Offline closed-bundle shape, permissions, and journal checks."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
from deploy.local import capture_profiles
from deploy.pilot import origin_credentials as credentials, origin_setup_state as journal


class Bundle(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'origin-pilot'; self.root.mkdir(mode=0o700)
        self.profile=capture_profiles.ORIGIN_PILOT._replace(state=self.root)
        patch=mock.patch.object(capture_profiles,'ORIGIN_PILOT',self.profile); patch.start(); self.addCleanup(patch.stop)
        self.op=credentials.Credentials(self.profile, self.root/'ca-cert',self.root/'ca-key')

    def create_shape(self):
        for path in sorted(credentials.DIRS,key=lambda x:(x.count('/'),x)): (self.root/path).mkdir(mode=0o700)
        for path in credentials.FILES:
            p=self.root/path; p.write_bytes(b'fixture'); p.chmod(0o600)

    def test_empty_partial_unexpected_and_closed_inventory(self):
        self.assertEqual(self.op.inspect(),journal.ABSENT)
        (self.root/'unexpected').write_bytes(b'fixture'); (self.root/'unexpected').chmod(0o600)
        self.assertEqual(self.op.inspect(),journal.DRIFT)
        (self.root/'unexpected').unlink()
        (self.root/'capture').mkdir(mode=0o700)
        self.assertEqual(self.op.inspect(),journal.DRIFT)

    def test_closed_shape_mode_links_and_commitment(self):
        self.create_shape()
        with mock.patch.object(self.op,'_verify'):
            self.assertEqual(self.op.inspect(),journal.EXACT)
            before=self.op.commitment()
            target=self.root/'replica1/client.crt'; target.write_bytes(b'changed')
            self.assertNotEqual(self.op.commitment(),before)
            target.chmod(0o644); self.assertEqual(self.op.inspect(),journal.DRIFT); target.chmod(0o600)
            target.unlink(); target.symlink_to(self.root/'replica2/client.crt'); self.assertEqual(self.op.inspect(),journal.DRIFT)
            target.unlink(); os.link(self.root/'replica2/client.crt',target); self.assertEqual(self.op.inspect(),journal.DRIFT)

    def test_phase_is_closed_and_defers_policy_and_roles(self):
        self.assertNotIn('capture/private/policy.json',credentials.FILES)
        self.assertIn('capture/private/policy.key',credentials.FILES)
        self.assertIn('capture/runtime/ingress.password',credentials.FILES)
        self.assertIn('capture/runtime/worker.password',credentials.FILES)
        self.assertTrue(set(credentials.FILES).isdisjoint({'ca.key','capture/runtime/policy.key'}))
        with self.assertRaises(ValueError): credentials.Credentials(capture_profiles.DEFAULT,'x','y')

    def test_ca_mismatch_prevents_any_bundle_creation(self):
        # Construction/order test only; the owned OpenSSL fixture verifies crypto.
        with mock.patch.object(credentials,'_file',side_effect=[b'fixture-ca',b'fixture-key']), \
             mock.patch.object(credentials,'_run',side_effect=[b'cert-public',b'other-public']):
            with self.assertRaisesRegex(ValueError,'CA key mismatch'): self.op.apply()
        self.assertFalse(any((self.root/name).exists() for name in ('capture','replica1','replica2','destination','native')))

    def test_completed_journal_detects_changed_bundle_commitment(self):
        class Fake:
            def __init__(self): self.value=journal.ABSENT; self.digest='a'*64
            def inspect(self): return self.value
            def apply(self): self.value=journal.EXACT
            def commitment(self): return self.digest
        ops={name:Fake() for name in journal.CREDENTIAL_PHASES}
        journal.run(self.profile,ops,through_credentials=True)
        ops['credentials'].digest='b'*64
        with self.assertRaisesRegex(ValueError,'credential commitment drift'):
            journal.run(self.profile,ops,through_credentials=True)

    def test_combined_inspection_rejects_missing_duplicate_and_trailing_sections(self):
        valid=(b'-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n'
               b'X509v3 Extended Key Usage: \n    TLS Web Server Authentication\n'
               b'X509v3 Subject Alternative Name: \n    DNS:example\n'
               b'Certificate will not expire\n')
        parse=credentials._parse_leaf_inspection
        self.assertEqual(parse(valid, 'serverAuth', 'DNS:example'),
                         b'-----BEGIN PUBLIC KEY-----\nQUJD\n-----END PUBLIC KEY-----\n')
        for bad in (valid+b'extra\n', valid.replace(b'Certificate will not expire\n',b''),
                    valid.replace(b'X509v3 Extended Key Usage: \n    TLS Web Server Authentication\n',b''),
                    valid.replace(b'X509v3 Subject Alternative Name:',b'unknown:'),
                    valid+valid, valid.replace(b'DNS:example',b'DNS:other'),
                    valid.replace(b'TLS Web Server Authentication',b'TLS Web Client Authentication'),
                    valid.replace(b'QUJD',b'bad!'), valid.replace(b'\n',b'\r\n'), b'x'*65537):
            with self.subTest(length=len(bad)):
                with self.assertRaises(ValueError): parse(bad, 'serverAuth', 'DNS:example')


class SyntheticInspection(unittest.TestCase):
    def test_combined_matches_original_checks_for_synthetic_certificates(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)
            def openssl(*args):
                return subprocess.run(['openssl',*map(str,args)],stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,timeout=30,check=True).stdout
            ca=root/'ca.pem'; ca_key=root/'ca.key'; other=root/'other.pem'; other_key=root/'other.key'
            for cert,key in ((ca,ca_key),(other,other_key)):
                openssl('req','-x509','-newkey','rsa:2048','-nodes','-days','2',
                        '-subj','/CN=synthetic test CA','-keyout',key,'-out',cert)
            key=root/'leaf.key'; csr=root/'leaf.csr'
            openssl('req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=synthetic',
                    '-keyout',key,'-out',csr)
            (root/'index').write_text(''); (root/'serial').write_text('01\n'); (root/'newcerts').mkdir()
            config=root/'ca.cnf'
            config.write_text('[ca]\ndefault_ca=issuer\n[issuer]\n'
                              f'database={root}/index\nserial={root}/serial\nnew_certs_dir={root}/newcerts\n'
                              f'certificate={ca}\nprivate_key={ca_key}\ndefault_md=sha256\n'
                              'policy=policy\n[policy]\ncommonName=supplied\n')
            certs={}
            for name,eku,san,start,end in (
                ('valid','serverAuth','DNS:example','20200101000000Z','20990101000000Z'),
                ('wrong_purpose','clientAuth','DNS:example','20200101000000Z','20990101000000Z'),
                ('wrong_san','serverAuth','DNS:other','20200101000000Z','20990101000000Z'),
                ('expired','serverAuth','DNS:example','20200101000000Z','20210101000000Z'),
                ('future','serverAuth','DNS:example','20900101000000Z','20990101000000Z')):
                ext=root/'ext.cnf'; ext.write_text('[leaf]\nbasicConstraints=CA:FALSE\n'
                    f'extendedKeyUsage={eku}\nsubjectAltName={san}\n')
                cert=root/(name+'.pem')
                (root/'index').write_text('')
                openssl('ca','-batch','-notext','-config',config,'-in',csr,'-out',cert,
                        '-startdate',start,'-enddate',end,'-extfile',ext,'-extensions','leaf')
                certs[name]=cert

            def checked(cert, trust, private_key, combined):
                calls=0
                def run(*args):
                    nonlocal calls
                    calls+=1
                    return openssl(*args)
                try:
                    if combined:
                        info=run('x509','-in',cert,'-pubkey','-ext',
                                     'extendedKeyUsage,subjectAltName','-checkend','0','-noout')
                        public=credentials._parse_leaf_inspection(info,'serverAuth','DNS:example')
                    else:
                        public=run('x509','-in',cert,'-pubkey','-noout')
                    if public!=run('pkey','-in',private_key,'-pubout'): return False,calls
                    run('pkey','-in',private_key,'-pubout','-outform','DER')
                    run('verify','-CAfile',trust,'-purpose','sslserver',cert)
                    if not combined:
                        run('x509','-in',cert,'-checkend','0','-noout')
                        eku=run('x509','-in',cert,'-noout','-ext','extendedKeyUsage').decode().splitlines()
                        san=run('x509','-in',cert,'-noout','-ext','subjectAltName').decode().splitlines()
                        if len(eku)!=2 or eku[1].strip()!='TLS Web Server Authentication': return False,calls
                        if len(san)!=2 or san[1].strip()!='DNS:example': return False,calls
                    run('x509','-in',cert,'-outform','DER')
                    run('pkcs8','-topk8','-nocrypt','-in',private_key,'-outform','DER')
                    return True,calls
                except (ValueError,subprocess.SubprocessError):
                    return False,calls
            for name,cert in certs.items():
                with self.subTest(certificate=name):
                    expected=name=='valid'
                    old=checked(cert,ca,key,False); new=checked(cert,ca,key,True)
                    self.assertEqual(old[0],expected)
                    self.assertEqual(new[0],expected)
                    if expected:
                        # Four bundle-wide checks are unchanged: 13 versus 10.
                        self.assertEqual((old[1]+4,new[1]+4),(13,10))
            for trust,private_key in ((other,key),(ca,other_key)):
                self.assertFalse(checked(certs['valid'],trust,private_key,False)[0])
                self.assertFalse(checked(certs['valid'],trust,private_key,True)[0])

            # Exercise the real verifier with one synthetic identity; a second
            # call must re-read and reject a changed certificate and mode.
            bundle=root/'bundle'; bundle.mkdir(mode=0o700)
            for path in ('capture/private','capture/runtime'):
                (bundle/path).mkdir(mode=0o700,parents=True,exist_ok=True)
            for target,source in (('leaf.pem',certs['valid']),('leaf.key',key)):
                (bundle/target).write_bytes(source.read_bytes()); (bundle/target).chmod(0o600)
            for target,data in (('leaf.der',openssl('x509','-in',certs['valid'],'-outform','DER')),
                                ('leaf-key.der',openssl('pkcs8','-topk8','-nocrypt','-in',key,'-outform','DER')),
                                ('ca.der',openssl('x509','-in',ca,'-outform','DER')),
                                ('ca.pem',ca.read_bytes())):
                (bundle/target).write_bytes(data); (bundle/target).chmod(0o600)
            ca.chmod(0o600); ca_key.chmod(0o600)
            signer=bundle/'capture/private/policy.key'
            openssl('genpkey','-algorithm','ED25519','-out',signer); signer.chmod(0o600)
            raw=openssl('pkey','-in',signer,'-pubout','-outform','DER')
            for target,data in (('capture/runtime/policy.raw',raw[-32:]),
                                ('capture/runtime/ingress.password',b'a'*32),
                                ('capture/runtime/worker.password',b'b'*32)):
                (bundle/target).write_bytes(data); (bundle/target).chmod(0o600)
            profile=capture_profiles.ORIGIN_PILOT._replace(state=bundle)
            entry=('one','leaf.key','leaf.pem','serverAuth','DNS:example',('leaf.der',),('leaf-key.der',))
            with mock.patch.object(capture_profiles,'ORIGIN_PILOT',profile), \
                 mock.patch.object(credentials,'CERTS',(entry,)), \
                 mock.patch.object(credentials,'CA_DER',('ca.der',)), mock.patch.object(credentials,'CA_PEM',('ca.pem',)), \
                 mock.patch.object(credentials,'COPIES',{}):
                op=credentials.Credentials(profile,ca,ca_key)
                original=credentials._run
                old_count=[0]
                def count_old(*args):
                    old_count[0]+=1
                    return original(*args)
                def original_leaf_calls(*args):
                    if '-checkend' not in args: return count_old(*args)
                    cert=args[args.index('-in')+1]
                    public=count_old('x509','-in',cert,'-pubkey','-noout')
                    expiry=count_old('x509','-in',cert,'-checkend','0','-noout')
                    eku=count_old('x509','-in',cert,'-noout','-ext','extendedKeyUsage')
                    san=count_old('x509','-in',cert,'-noout','-ext','subjectAltName')
                    return public+eku+san+expiry
                with mock.patch.object(credentials,'_run',side_effect=original_leaf_calls): op._verify()
                self.assertEqual(old_count[0],13)
                with mock.patch.object(credentials,'_run',wraps=credentials._run) as calls:
                    op._verify()
                self.assertEqual(calls.call_count,10)
                (bundle/'leaf.pem').write_bytes(certs['wrong_san'].read_bytes())
                with self.assertRaises(ValueError): op._verify()
                (bundle/'leaf.pem').write_bytes(certs['valid'].read_bytes())
                (bundle/'leaf.key').write_bytes(other_key.read_bytes())
                with self.assertRaises(ValueError): op._verify()
                (bundle/'leaf.key').write_bytes(key.read_bytes())
                ca_before=ca.read_bytes(); ca.write_bytes(other.read_bytes())
                with self.assertRaises(ValueError): op._verify()
                ca.write_bytes(ca_before)
                der_before=(bundle/'leaf.der').read_bytes(); (bundle/'leaf.der').write_bytes(b'changed')
                with self.assertRaises(ValueError): op._verify()
                (bundle/'leaf.der').write_bytes(der_before)
                with mock.patch.object(credentials,'CERTS',(entry,entry)):
                    with self.assertRaisesRegex(ValueError,'duplicate identity'): op._verify()
                (bundle/'leaf.key').chmod(0o644)
                with self.assertRaises(ValueError): op._verify()
                (bundle/'leaf.key').chmod(0o600)
                def fail_combined(*args):
                    if '-checkend' in args: raise subprocess.TimeoutExpired('openssl',30)
                    return original(*args)
                with mock.patch.object(credentials,'_run',side_effect=fail_combined):
                    with self.assertRaises(subprocess.TimeoutExpired): op._verify()


if __name__ == '__main__': unittest.main()
