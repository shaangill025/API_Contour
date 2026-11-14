import unittest
from unittest.mock import MagicMock, patch
from deploy.local import origin21_profile as profiles, origin21_products as products, origin21_transport as transport


class TransportGateTest(unittest.TestCase):
    def test_unproved_transition_blocks_before_database_target(self):
        runner=MagicMock(); deployment={'name':'fixed'}
        value=transport.ManagedTransport(transport._MANAGED_SEAL,runner,deployment,'image','head','receipt','digest',selected=profiles.HUMAN)
        record={'deployment':deployment,'app_image_id':'image','build_head':'head','build_receipt_sha256':'digest'}
        with patch.object(products, '_build_receipt', return_value=deployment), patch.object(products, '_read_record', return_value=record), \
             patch.object(transport.os.path, 'lexists', side_effect=lambda path:path.name in ('companions.json','human.intent')):
            with self.assertRaises(ValueError): value.verify()
            runner.verify_target.assert_not_called()

    def test_completed_profile_checks_whole_topology_before_database_target(self):
        from deploy.local import origin21_managed_controller as controller
        runner=MagicMock(); deployment={'name':'fixed'}
        value=transport.ManagedTransport(transport._MANAGED_SEAL,runner,deployment,'image','head','receipt','digest',selected=profiles.HUMAN)
        record={'deployment':deployment,'app_image_id':'image','build_head':'head','build_receipt_sha256':'digest'}
        with patch.object(products, '_build_receipt', return_value=deployment), patch.object(products, '_read_record', return_value=record), \
             patch.object(transport.os.path, 'lexists', side_effect=lambda path:path.name in ('companions.json','human.intent','human.json')), \
             patch.object(controller, 'verify_recorded_topology', side_effect=ValueError('drift')) as verify:
            with self.assertRaises(ValueError): value.verify()
            verify.assert_called_once_with(selected=profiles.HUMAN)
            runner.verify_target.assert_not_called()

    def test_missing_companion_record_does_not_bypass_completed_topology(self):
        runner=MagicMock(); deployment={'name':'fixed'}
        value=transport.ManagedTransport(transport._MANAGED_SEAL,runner,deployment,'image','head','receipt','digest',selected=profiles.HUMAN)
        record={'deployment':deployment,'app_image_id':'image','build_head':'head','build_receipt_sha256':'digest'}
        with patch.object(products, '_build_receipt', return_value=deployment), patch.object(products, '_read_record', return_value=record), \
             patch.object(transport.os.path, 'lexists', side_effect=lambda path:path.name in ('human.intent','human.json')):
            with self.assertRaises(ValueError): value.verify()
            runner.verify_target.assert_not_called()
