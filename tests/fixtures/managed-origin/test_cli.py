"""Offline sequencing checks; no Docker, database or credentials."""
import unittest
from unittest import mock
from deploy.local import origin21_managed_cli as cli,origin21_profile as profiles

class ManagedCLITests(unittest.TestCase):
    def test_up_uses_only_managed_bound_operations(self):
        events=[]; expected=(b'a'*32,b'b'*32); transport=object(); deployment={'fixture':'managed'}
        def step(name,value):
            def run(*args,**kwargs):
                events.append((name,kwargs)); return value
            return run
        with mock.patch.object(cli.os,'getuid',return_value=501),mock.patch.object(cli.products if hasattr(cli,'products') else cli.origin21_products,'_build_receipt',side_effect=step('receipt',deployment)),mock.patch.object(cli.origin21_products,'_capture_network',side_effect=step('database',None)),mock.patch.object(cli.origin21_setup,'prepare_identities',side_effect=step('identities',None)),mock.patch.object(cli.origin21_products,'start_products',side_effect=step('products',expected)),mock.patch.object(cli.origin21_transport,'managed_transport',side_effect=step('transport',transport)),mock.patch.object(cli.origin21_setup,'prepare',side_effect=step('enrollment',None)),mock.patch.object(cli.origin21_products,'start_companions',side_effect=step('companions',None)),mock.patch.object(cli.origin21_ready,'check',side_effect=step('capture',{'product_tls_and_catalog_verified':True,'ui_verified':False})):
            result=cli.main(['up','sha256:'+'a'*64,'b'*40,'/private/receipt','c'*64])
        self.assertEqual([x[0] for x in events],['receipt','database','identities','products','transport','enrollment','companions','capture'])
        for name,kwargs in events:
            if name!='transport': self.assertIs(kwargs['selected'],profiles.MANAGED)
        self.assertIn('capture verified',result)

    def test_rejected_managed_target_stops_before_credentials(self):
        with mock.patch.object(cli.os,'getuid',return_value=501),mock.patch.object(cli.origin21_products,'_build_receipt',side_effect=ValueError('bad')),mock.patch.object(cli.origin21_setup,'prepare_identities') as identities:
            with self.assertRaises(ValueError): cli.main(['up','sha256:'+'a'*64,'b'*40,'/private/receipt','c'*64])
            identities.assert_not_called()

if __name__=='__main__': unittest.main()
