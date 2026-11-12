"""Synthetic local prototype checks; requires the explicitly qualified host tool."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from deploy.pilot.receiver_ca import inspect_local_ca

TOOL = Path(os.environ['CONTOUR_QUALIFIED_OPENSSL'])
FIXTURE = Path(__file__).resolve().parent.parent / 'causal-receiver-material/ca.pem'


class ReceiverCaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.cert = self.root / 'ca.pem'
        shutil.copyfile(FIXTURE, self.cert)
        self.cert.chmod(0o600)

    def run_tool(self, *args):
        subprocess.run([str(TOOL), *map(str, args)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_positive_and_receipt_drift(self):
        receipt = inspect_local_ca(self.cert, TOOL)
        self.assertEqual(len(receipt.revalidate()), 32)
        self.cert.chmod(0o644)
        with self.assertRaisesRegex(ValueError, 'unsafe CA snapshot'): receipt.revalidate()
        self.cert.chmod(0o600)
        self.cert.write_bytes(self.cert.read_bytes().replace(b'CERTIFICATE', b'XERTIFICATE', 1))
        with self.assertRaisesRegex(ValueError, 'invalid CA PEM'): receipt.revalidate()

    def test_parent_symlink_writable_and_replacement_are_rejected(self):
        receipt = inspect_local_ca(self.cert, TOOL)
        self.root.chmod(0o777)
        with self.assertRaisesRegex(ValueError, 'unsafe CA parent'): receipt.revalidate()
        self.root.chmod(0o700)
        replacement = self.root.parent / (self.root.name + '-old')
        self.root.rename(replacement)
        self.addCleanup(lambda: replacement.rename(self.root) if replacement.exists() and not self.root.exists() else None)
        self.root.mkdir(mode=0o700)
        self.addCleanup(lambda: shutil.rmtree(self.root, ignore_errors=True))
        shutil.copyfile(replacement/'ca.pem', self.cert)
        self.cert.chmod(0o600)
        with self.assertRaisesRegex(ValueError, 'CA receipt drift'): receipt.revalidate()
        link = self.root / 'link'
        link.symlink_to(replacement, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'unsafe CA path'): inspect_local_ca(link/'ca.pem', TOOL)

    def test_rejects_non_ca_and_missing_key_usage(self):
        for extension in ('basicConstraints=critical,CA:FALSE', 'basicConstraints=critical,CA:TRUE'):
            with self.subTest(extension=extension):
                self.run_tool('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', self.root/'key',
                              '-out', self.cert, '-days', '1', '-subj', '/CN=synthetic', '-addext', extension)
                self.cert.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'invalid CA constraints' if extension.endswith('FALSE') else 'invalid CA key usage'): inspect_local_ca(self.cert, TOOL)
                self.run_tool('req', '-x509', '-key', self.root/'key', '-out', self.cert, '-days', '1', '-subj', '/CN=synthetic', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
                self.cert.chmod(0o600)
                self.assertEqual(len(inspect_local_ca(self.cert, TOOL).revalidate()), 32)

    def test_rejects_expired_and_not_yet_valid_ca(self):
        key, csr = self.root/'key', self.root/'request'
        self.run_tool('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', key, '-out', csr, '-subj', '/CN=synthetic')
        (self.root/'index').write_text('')
        (self.root/'serial').write_text('01\n')
        config = self.root/'ca.cnf'
        config.write_text('[ca]\ndefault_ca=local\n[local]\ndatabase='+str(self.root/'index')+'\nserial='+str(self.root/'serial')+'\nnew_certs_dir='+str(self.root)+'\nprivate_key='+str(key)+'\ndefault_md=sha256\npolicy=policy\nx509_extensions=ext\n[policy]\ncommonName=supplied\n[ext]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n')
        for start, end in (('20200101000000Z', '20210101000000Z'), ('20400101000000Z', '20410101000000Z')):
            with self.subTest(start=start):
                (self.root/'index').write_text('')
                self.run_tool('ca', '-batch', '-selfsign', '-config', config, '-in', csr, '-out', self.cert, '-startdate', start, '-enddate', end, '-notext')
                self.cert.chmod(0o600)
                with self.assertRaisesRegex(ValueError, 'CA outside validity'): inspect_local_ca(self.cert, TOOL)
                self.run_tool('req', '-x509', '-key', key, '-out', self.cert, '-days', '1', '-subj', '/CN=synthetic', '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign')
                self.cert.chmod(0o600)
                self.assertEqual(len(inspect_local_ca(self.cert, TOOL).revalidate()), 32)


if __name__ == '__main__': unittest.main()
