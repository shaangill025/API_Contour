"""Offline one-command managed bootstrap ordering controls."""
import unittest
from pathlib import Path
from unittest import mock
from deploy.local import origin21_managed_bootstrap as bootstrap

class BootstrapTests(unittest.TestCase):
    def test_source_guard_precedes_initializer(self):
        with mock.patch.object(bootstrap.os,'getuid',return_value=501),mock.patch.object(bootstrap.origin21_state,'MANAGED_SOURCE_FILES',()),mock.patch.object(bootstrap.origin21_managed_init,'initialize') as init:
            with self.assertRaises(RuntimeError): bootstrap.main(['sha256:'+'a'*64,'b'*40,'/private/build','c'*64])
            init.assert_not_called()
    def test_only_actual_initializer_receipt_reaches_managed_up(self):
        receipt=Path('/private/managed/runtime-receipt.json'); runtime='d'*64
        with mock.patch.object(bootstrap.os,'getuid',return_value=501),mock.patch.object(bootstrap.origin21_state,'MANAGED_SOURCE_FILES',(bootstrap.SOURCE,)),mock.patch.object(bootstrap.origin21_managed_init,'initialize',return_value=(receipt,runtime)) as init,mock.patch.object(bootstrap.origin21_managed_cli,'main',return_value='done') as cli:
            result=bootstrap.main(['sha256:'+'a'*64,'b'*40,'/private/build','c'*64])
        self.assertEqual(result,'done'); init.assert_called_once(); cli.assert_called_once_with(['up','sha256:'+'a'*64,'b'*40,str(receipt),runtime])
    def test_initializer_failure_never_calls_managed_up(self):
        with mock.patch.object(bootstrap.os,'getuid',return_value=501),mock.patch.object(bootstrap.origin21_state,'MANAGED_SOURCE_FILES',(bootstrap.SOURCE,)),mock.patch.object(bootstrap.origin21_managed_init,'initialize',side_effect=TimeoutError('unknown')),mock.patch.object(bootstrap.origin21_managed_cli,'main') as cli:
            with self.assertRaises(TimeoutError): bootstrap.main(['sha256:'+'a'*64,'b'*40,'/private/build','c'*64])
            cli.assert_not_called()

if __name__=='__main__': unittest.main()
