import unittest
from unittest.mock import patch
from deploy.local import origin21_managed_human_cleanup as cleanup


class CleanupTest(unittest.TestCase):
    def test_unavailable_owner_refuses_cleanup_before_docker(self):
        with patch.object(cleanup.products, '_command') as command, patch.object(cleanup.controller, 'open_edge', side_effect=ValueError('unavailable')) as edge:
            with self.assertRaises(ValueError): cleanup.teardown()
            command.assert_not_called()
            edge.assert_called_once()

    def test_sealed_cleanup_rechecks_snapshot_and_rejects_drift(self):
        from types import SimpleNamespace
        owner=SimpleNamespace(peer=object(),publisher=object())
        with patch.object(cleanup.controller, '_topology_snapshot', side_effect=[('base','envoy'),('base','envoy')]) as snapshot:
            cleanup._check(owner, ('base','envoy'))
            self.assertEqual(snapshot.call_count, 2)
            self.assertIs(snapshot.call_args.kwargs['_cleanup'], cleanup.controller._HUMAN_CLEANUP)
        with patch.object(cleanup.controller, '_topology_snapshot', side_effect=[('base','envoy'),('changed','envoy')]):
            with self.assertRaises(ValueError): cleanup._check(owner, ('base','envoy'))

    def test_cleanup_guard_refuses_a_remaining_container(self):
        import hashlib
        import json
        from deploy.local import origin21_managed_cleanup as managed, origin21_profile as profiles
        selected=profiles.HUMAN; token='a'*64; net='b'*64; app='c'*64; idp='d'*64
        human={'token':token,'network_ids':{'human':net},'services':{'app':{'id':app},'mvp-keycloak':{'id':idp}}}
        raw=json.dumps(human,sort_keys=True,separators=(',',':')).encode()
        records={'human.json':human,'human.cleanup.intent':{'version':1,'token':token,'human_sha256':hashlib.sha256(raw).hexdigest()},
                 'human.cleanup-network.intent':{'version':1,'id':net},'human.cleanup-network.done':{'version':1,'id':net},
                 'human.cleanup-app.intent':{'version':1,'id':app},'human.cleanup-app.done':{'version':1,'id':app},
                 'human.cleanup-identity.intent':{'version':1,'id':idp},'human.cleanup-identity.done':{'version':1,'id':idp}}
        def command(args, *unused):
            return b'container-remains' if 'id='+app in args else b''
        with patch.object(managed.origin_credentials, '_file', return_value=raw), patch.object(managed, '_record', side_effect=lambda path:records[path.name]), patch.object(managed.products, '_command', side_effect=command), patch.object(managed.products, '_objects') as objects:
            with self.assertRaises(ValueError): managed._human_cleanup_guard(selected, {'token':token})
            objects.assert_not_called()
