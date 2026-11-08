"""Offline checks for the qualification-only private control protocol."""
import subprocess
import hashlib
import os
import signal
import tempfile
import time
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parent

class FixtureTests(unittest.TestCase):
    def test_fixed_nonce_is_required_and_reuse_rejected(self):
        script="""const x=require(process.argv[1]);const a='a'.repeat(32),b='b'.repeat(32);
if(!x.nonceValid(a)||x.nonceValid('bad')||!x.begin(a,'request')||x.begin(a,'request')||x.begin(b,'response')||x.status(a)!=='PENDING'||x.status(b)!=='UNKNOWN'||x.release(a)||x.release(b))process.exit(1);process.exit(0);"""
        result=subprocess.run(['node','-e',script,str(ROOT/'destination.js')],capture_output=True,timeout=5)
        self.assertEqual((result.returncode,result.stdout,result.stderr),(0,b'',b''))
    def test_publisher_commit_marker_precedes_ack_and_survives_local_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); data=b'fixed-document'; document=root/'sds.json'; document.write_bytes(data); document.chmod(0o600)
            original=document.stat().st_ino; digest=hashlib.sha256(data).hexdigest(); nonce='a'*32
            source=(ROOT/'publisher.js').read_text().replace('/watch',str(root))
            child=subprocess.Popen(['node','-e',source,'fixture-publisher',digest,nonce],stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            try:
                marker=root/('.qualification-commit-'+nonce); deadline=time.monotonic()+4
                while not marker.exists() and time.monotonic()<deadline:
                    if child.poll() is not None: self.fail('publisher exited before commit marker')
                    time.sleep(.01)
                self.assertTrue(marker.exists()); self.assertIsNone(child.poll())
                self.assertEqual(marker.read_bytes(),digest.encode()+b'\n'); self.assertEqual(document.read_bytes(),data); self.assertNotEqual(document.stat().st_ino,original)
                os.killpg(child.pid,signal.SIGKILL); out,err=child.communicate(timeout=5)
                self.assertEqual(out,b'DOC_VERIFIED\n'); self.assertEqual(err,b''); self.assertNotEqual(child.returncode,0)
                self.assertTrue(marker.exists())
            finally:
                if child.poll() is None: os.killpg(child.pid,signal.SIGKILL); child.wait(timeout=5)

    def test_publisher_wrong_hash_and_foreign_marker_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); document=root/'sds.json'; document.write_bytes(b'fixed'); document.chmod(0o600)
            source=(ROOT/'publisher.js').read_text().replace('/watch',str(root)); nonce='b'*32
            result=subprocess.run(['node','-e',source,'fixture-publisher','0'*64,nonce],capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0); self.assertFalse((root/('.qualification-commit-'+nonce)).exists()); self.assertEqual(document.read_bytes(),b'fixed')
            marker=root/('.qualification-commit-'+nonce); marker.write_bytes(b'foreign'); marker.chmod(0o600)
            digest=hashlib.sha256(b'fixed').hexdigest(); result=subprocess.run(['node','-e',source,'fixture-publisher',digest,nonce],capture_output=True,timeout=5)
            self.assertNotEqual(result.returncode,0); self.assertEqual(marker.read_bytes(),b'foreign')

    def test_scripts_have_no_syntax_errors(self):
        for name in ('destination.js','client.js','control.js','publisher.js'):
            with self.subTest(name=name):
                result=subprocess.run(['node','--check',str(ROOT/name)],capture_output=True,timeout=5)
                self.assertEqual((result.returncode,result.stderr),(0,b''))

if __name__=='__main__': unittest.main()
