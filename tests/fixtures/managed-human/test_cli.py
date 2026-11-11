import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_human_cli as cli


class CliTest(unittest.TestCase):
    def test_invalid_arguments_fail_before_resource_actions(self):
        with patch.object(cli.origin21_managed_init, 'initialize') as initialize:
            with self.assertRaises(ValueError): cli.main([])
            initialize.assert_not_called()

    def test_fixed_bootstrap_orders_enrollment_before_human_start(self):
        from pathlib import Path
        events=[]; evidence=(b'a'*32,b'b'*32); handle=object()
        def step(name, value=None):
            def call(*args, **kwargs):
                events.append(name)
                self.assertIs(kwargs.get('selected'),cli.origin21_profile.HUMAN)
                return value
            return call
        def services(expected, given):
            events.append('human')
            self.assertEqual(expected,evidence)
            self.assertIs(given,handle)
            return {'ui_verified':False}
        with patch.object(cli.os, 'getuid', return_value=123), \
             patch.object(cli.origin21_managed_init, 'initialize', side_effect=step('db',(Path('/fixed/receipt'),'d'*64))), \
             patch.object(cli.origin21_setup, 'prepare_identities', side_effect=step('identities')), \
             patch.object(cli.origin21_products, 'start_products', side_effect=step('products',evidence)), \
             patch.object(cli.origin21_transport, 'managed_transport', side_effect=step('transport',handle)), \
             patch.object(cli.origin21_setup, 'prepare', side_effect=step('enrollment')), \
             patch.object(cli.origin21_products, 'start_companions', side_effect=step('companions')), \
             patch.object(cli.origin21_managed_human_services, 'start', side_effect=services):
            result=cli.main(['sha256:'+'a'*64,'b'*40,'/fixed/build-receipt','c'*64])
        self.assertEqual(events,['db','identities','products','transport','enrollment','companions','human'])
        self.assertEqual(result,{'ui_verified':False})

    def test_invalid_build_inputs_cannot_trigger_initializer(self):
        valid=['sha256:'+'a'*64,'b'*40,'/fixed/receipt','c'*64]
        invalid=[['remote',*valid[1:]], [valid[0],'z'*40,*valid[2:]],
                 [*valid[:2],'relative',valid[3]], [*valid[:3],'d'*63], valid+['extra']]
        with patch.object(cli.os, 'getuid', return_value=123), patch.object(cli.origin21_managed_init, 'initialize') as initialize:
            for argv in invalid:
                with self.subTest(argv=argv), self.assertRaises(ValueError): cli.main(argv)
            initialize.assert_not_called()
