"""Offline tests of the exclusive qualification proof; no Docker or SQL."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from deploy.local import origin21_managed_qualification as q

class QualificationProofTests(unittest.TestCase):
    def test_worktree_must_match_exclusive_owner_intent_and_registration(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            owner=Path(directory).resolve(); owner.chmod(0o700); root=owner/'worktree'; root.mkdir(mode=0o700)
            head='b'*40; token='a'*32; receipt=owner/'build-receipt.json'
            value={'version':1,'head':head,'tag':'apicontour-origin21-build:'+token,'token':token,'worktree':str(root)}
            intent=owner/'intent.json'; intent.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode()); intent.chmod(0o600)
            data='worktree '+str(root)+'\0HEAD '+head+'\0\0'
            with mock.patch.object(q.profiles,'ROOT',root),mock.patch.object(q.init.origin21_transport,'_run',return_value=data):
                q._owned_worktree(head,str(receipt))
                with self.assertRaises(ValueError): q._owned_worktree(head,str(owner/'other-receipt'))
            value['worktree']=str(owner/'foreign'); intent.write_bytes(json.dumps(value,sort_keys=True,separators=(',',':')).encode())
            with mock.patch.object(q.profiles,'ROOT',root),mock.patch.object(q.init.origin21_transport,'_run') as run:
                with self.assertRaises(ValueError): q._owned_worktree(head,str(receipt))
                run.assert_not_called()

    def test_qualification_owner_cannot_use_unbound_managed_transport(self):
        from deploy.local import origin21_transport,origin21_products
        with mock.patch.object(origin21_transport.os.path,'lexists',return_value=True),mock.patch.object(origin21_products,'_build_receipt') as build:
            with self.assertRaises(ValueError): origin21_transport.managed_transport(image_id='image',head='head',receipt='/receipt',digest='digest')
            build.assert_not_called()

    def test_unbound_entrypoints_reject_qualification_before_work(self):
        from deploy.local import origin21_managed_cli as cli,origin21_setup,origin21_products
        with tempfile.TemporaryDirectory() as d:
            base=Path(d); (base/'qualification').mkdir()
            with mock.patch.object(q.init,'BASE',base),mock.patch.object(cli.origin21_products,'_build_receipt') as build,mock.patch.object(origin21_setup.origin21_schema,'require_reference') as refs,mock.patch.object(origin21_products,'_identity_ready') as identity:
                with self.assertRaises(ValueError): cli.main(['up','bad','bad','bad','bad'])
                with self.assertRaises(ValueError): origin21_setup.prepare_identities(selected=q.profiles.MANAGED)
                with self.assertRaises(ValueError): origin21_products.start_products(app_image_id='bad',build_head='bad',build_receipt='bad',build_receipt_sha256='bad',selected=q.profiles.MANAGED)
                build.assert_not_called(); refs.assert_not_called(); identity.assert_not_called()

    def test_orphaned_qualification_volume_intent_requires_live_proof(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); path=root/'volume.intent'; path.write_bytes(json.dumps({'name':'contour-managed-origin21-qual-'+'a'*32+'-data'},sort_keys=True,separators=(',',':')).encode()); path.chmod(0o600)
            with mock.patch.object(q.init,'BASE',root):
                with self.assertRaises(ValueError): q.require_matching(None)

    def test_publication_ack_is_bound_to_exact_publisher_document_and_nonce(self):
        import hashlib
        from deploy.gateway.managed_edge import NativeDirectoryPublisher
        proof=object.__new__(q.OwnedManagedQualification); object.__setattr__(proof,'_publish_ack',None)
        publisher=object.__new__(NativeDirectoryPublisher); publisher.qualification=proof
        with mock.patch.object(q.OwnedManagedQualification,'verify',return_value=proof),mock.patch.object(NativeDirectoryPublisher,'identity',return_value={'publisher':'exact'}):
            proof._record_publication_ack(publisher,b'first','a'*32); first=proof.publication_ack()
            proof._record_publication_ack(publisher,b'second','b'*32); second=proof.publication_ack()
            self.assertEqual(first,{'sequence':1,'publisher':{'publisher':'exact'},'document_sha256':hashlib.sha256(b'first').hexdigest(),'nonce':'a'*32})
            self.assertEqual(second['sequence'],2); self.assertEqual(second['nonce'],'b'*32)
            publisher.qualification=object()
            with self.assertRaises(ValueError): proof._record_publication_ack(publisher,b'third','c'*32)
            self.assertEqual(proof.publication_ack(),second)

    def test_close_failure_preserves_primary_failure(self):
        proof=object.__new__(q.OwnedManagedQualification); primary=ValueError('primary')
        with mock.patch.object(q.OwnedManagedQualification,'close',side_effect=OSError('close')):
            with self.assertRaises(BaseExceptionGroup) as raised: proof.__exit__(ValueError,primary,None)
        self.assertIs(raised.exception.exceptions[0],primary)
        self.assertIsInstance(raised.exception.exceptions[1],OSError)

    def test_raw_constructor_and_unpinned_source_are_refused(self):
        with self.assertRaises(ValueError): q.OwnedManagedQualification(object(),0,(0,0),b'', '', '', '', '')
        with mock.patch.object(q.init.origin21_products,'_objects') as inspect:
            with self.assertRaises(ValueError): q.init._volume('a'*32,qualification=object())
            inspect.assert_not_called()
        with mock.patch.object(q.origin21_state,'MANAGED_SOURCE_FILES',()),mock.patch.object(q.init,'_build') as build:
            with self.assertRaises(RuntimeError): q.begin(image_id='image',head='head',build_receipt='/unused',build_receipt_sha256='digest')
            build.assert_not_called()

    def test_exclusive_proof_binds_root_context_and_fixed_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); (root/'.git').write_text('gitdir: owned')
            fixture=root/q.DESTINATION; fixture.parent.mkdir(parents=True); fixture.write_bytes(b'fixed source')
            base=root/'.local-mvp-managed'; context=q.profiles.MANAGED._replace(profile=q.profiles.MANAGED.profile._replace(state=base/'origin21-pilot'))
            with mock.patch.object(q.profiles,'ROOT',root),mock.patch.object(q.profiles,'MANAGED',context),mock.patch.object(q.init,'BASE',base),mock.patch.object(q,'_owned_worktree'),mock.patch.object(q.init,'_source',return_value='source'),mock.patch.object(q.init,'_build',return_value={}),mock.patch.object(q.origin21_state,'MANAGED_SOURCE_FILES',(q.SOURCE,q.DESTINATION)):
                proof=q.begin(image_id='sha256:'+'a'*64,head='b'*40,build_receipt='/private/receipt',build_receipt_sha256='c'*64)
                try:
                    self.assertIs(proof.verify(),proof); self.assertEqual(len(proof.token),32)
                    self.assertEqual(q.init._selected_volume(proof),proof.volume)
                    self.assertEqual(q.init._selected_volume(None),q.init.VOLUME)
                    with self.assertRaises(ValueError): proof.require_build('sha256:'+'f'*64,'b'*40,'c'*64)
                    self.assertIs(proof.require_build('sha256:'+'a'*64,'b'*40,'c'*64),proof)
                    model={'services':{'destination':{'volumes':[{'type':'bind','source':str(root/'deploy/pilot/destination.js'),'target':'/pilot/destination.js','read_only':True}]}}}
                    revised=proof.destination_model(model)
                    self.assertEqual(revised['services']['destination']['volumes'][0]['source'],str(fixture))
                    self.assertNotEqual(model,revised)
                    model['services']['destination']['volumes'][0]['read_only']=False
                    with self.assertRaises(ValueError): proof.destination_model(model)
                    self.assertEqual(proof.volume,'contour-managed-origin21-qual-'+proof.token+'-data')
                    self.assertEqual((proof.folder/'qualification.intent').stat().st_mode & 0o777,0o600)
                    with self.assertRaises(FileExistsError): q.begin(image_id='sha256:'+'a'*64,head='b'*40,build_receipt='/private/receipt',build_receipt_sha256='c'*64)
                    with self.assertRaises(AttributeError): proof._token='d'*32
                    fixture.write_bytes(b'changed')
                    with self.assertRaises(ValueError): proof.verify()
                finally: proof.close()

    def test_replaced_root_cannot_be_adopted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(); (root/'.git').write_text('gitdir: owned'); fixture=root/q.DESTINATION; fixture.parent.mkdir(parents=True); fixture.write_bytes(b'fixed')
            base=root/'.local-mvp-managed'; context=q.profiles.MANAGED._replace(profile=q.profiles.MANAGED.profile._replace(state=base/'origin21-pilot'))
            with mock.patch.object(q.profiles,'ROOT',root),mock.patch.object(q.profiles,'MANAGED',context),mock.patch.object(q.init,'BASE',base),mock.patch.object(q,'_owned_worktree'),mock.patch.object(q.init,'_source',return_value='source'),mock.patch.object(q.init,'_build',return_value={}),mock.patch.object(q.origin21_state,'MANAGED_SOURCE_FILES',(q.SOURCE,q.DESTINATION)):
                proof=q.begin(image_id='sha256:'+'a'*64,head='b'*40,build_receipt='/private/receipt',build_receipt_sha256='c'*64)
                try:
                    base.rename(root/'old-root'); base.mkdir(mode=0o700); sentinel=base/'foreign'; sentinel.write_text('keep')
                    with self.assertRaises(ValueError): proof.verify()
                    self.assertEqual(sentinel.read_text(),'keep')
                finally: proof.close()

if __name__=='__main__': unittest.main()
