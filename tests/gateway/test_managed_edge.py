"""Offline filesystem and synthetic socket controls; no real credentials/listeners."""
import hashlib
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from deploy.gateway import managed_edge as edge
from deploy.gateway import certificates

class FakeCertificates:
    def __init__(self,directory,ca,ca_key,hostname): self.directory=directory; self.hostname=hostname
    def _read(self,path,limit=65536): return b'public-fixture'
    def stage_native_edge(self,version,days=1):
        p=self.directory/version; p.mkdir(mode=0o700)
        for name in ('cert.pem','key.pem'): (p/name).write_bytes(b'fixture'); (p/name).chmod(0o600)
    def native_edge_commitment(self,version,*,allow_expired=False):
        cert,key=self.validate_native_edge(version,allow_expired=allow_expired)
        return {'cert_sha256':hashlib.sha256(cert.read_bytes()).hexdigest(),'key_spki_sha256':hashlib.sha256(key.read_bytes()).hexdigest()}
    def sync_native_edge(self,version): self.validate_native_edge(version)
    def validate_native_edge(self,version,*,allow_expired=False):
        p=self.directory/version
        if not (p/'cert.pem').is_file() or not (p/'key.pem').is_file(): raise ValueError('invalid candidate')
        return p/'cert.pem',p/'key.pem'

class ManagedEdgeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.root=Path(self.tmp.name).resolve()
        for n in ('state','published','watched'): (self.root/n).mkdir(mode=0o700)
        for n in ('ca','client'): (self.root/n).write_bytes(b'public-fixture')
        self.patch=mock.patch.object(edge,'Certificates',FakeCertificates); self.patch.start()
    def tearDown(self): self.patch.stop(); self.tmp.cleanup()
    def owner(self,port=9443):
        r=self.root
        return edge.ManagedEdge(r/'state',r/'published',r/'watched',r/'ca',r/'ca-key',edge.LoopbackPeer(r/'ca',r/'client',r/'client-key',port))
    def native_peer(self):
        mounts={'/pilot/ca.crt':'/owned/ca','/pilot/tls/client.crt':'/owned/client','/pilot/tls/client.key':'/owned/key','/pilot/native_edge_probe.js':str(edge._PROBE)}
        mounts.update({dst:'/owned/profile' for dst in edge._PROFILE_MOUNTS})
        envoy={'/certs':str(self.root/'published'),'/run/watch':str(self.root/'watched'),'/run/forwarder':'/owned/forwarder'}
        return edge.NativeReplicaPeer('a'*64,'sha256:'+'b'*64,'c'*64,mounts,'e'*64,'sha256:'+'f'*64,envoy)
    def native_owner(self,peer):
        r=self.root
        return edge.ManagedEdge(r/'state',r/'published',r/'watched',r/'ca',r/'ca-key',peer)
    def test_native_bootstrap_binds_observed_start_before_confirmation(self):
        peer=self.native_peer(); binding={'replica_started':'2026-11-07T01:02:03Z','envoy_started':'2026-11-07T01:02:04Z'}
        with self.native_owner(peer) as owner, mock.patch.object(peer,'verify_created') as created, mock.patch.object(owner,'_confirm') as confirm:
            owner.prepare_initial(); self.assertEqual(created.call_count,2)
            self.assertIsNone(owner._load()['binding']); self.assertIsNone(owner._load()['current'])
            owner.reconcile(); confirm.assert_not_called()
            with mock.patch.object(peer,'observe_live',return_value=binding): owner.bind_initial_peer()
            self.assertEqual(owner._load()['binding'],binding); self.assertTrue((self.root/'state/binding.intent').is_file()); self.assertTrue((self.root/'state/binding.result').is_file())
            owner.reconcile(); self.assertEqual(confirm.call_args.args[2],binding); self.assertIsNotNone(owner._load()['current'])
        with self.assertRaisesRegex(ValueError,'journal'): self.owner()
    def test_binding_recovery_requires_same_starts_after_result_fsync(self):
        peer=self.native_peer(); binding={'replica_started':'2026-11-07T01:02:03Z','envoy_started':'2026-11-07T01:02:04Z'}
        with self.native_owner(peer) as owner, mock.patch.object(peer,'verify_created'):
            owner.prepare_initial(); real=owner._binding_file
            def crash(name,data):
                real(name,data)
                if name=='binding.result': raise OSError('after durable result')
            with mock.patch.object(owner,'_binding_file',side_effect=crash), mock.patch.object(peer,'observe_live',return_value=binding):
                with self.assertRaises(OSError): owner.bind_initial_peer()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'observe_live',return_value=dict(binding,replica_started='2026-11-07T01:03:00Z')):
            with self.assertRaisesRegex(ValueError,'binding changed'): owner.bind_initial_peer()
            self.assertIsNone(owner._load()['binding'])
        with self.native_owner(peer) as owner, mock.patch.object(peer,'observe_live',return_value=binding):
            owner.bind_initial_peer(); self.assertEqual(owner._load()['binding'],binding)
    def test_binding_result_sync_failure_reopens_only_same_observed_start(self):
        peer=self.native_peer(); binding={'replica_started':'2026-11-07T01:02:03Z','envoy_started':'2026-11-07T01:02:04Z'}
        with self.native_owner(peer) as owner, mock.patch.object(peer,'verify_created'):
            owner.prepare_initial(); real=owner._binding_file
            def fault(name,data):
                if name=='binding.result':
                    with mock.patch.object(edge.os,'fsync',side_effect=OSError('result fsync')): return real(name,data)
                return real(name,data)
            with mock.patch.object(owner,'_binding_file',side_effect=fault), mock.patch.object(peer,'observe_live',return_value=binding):
                with self.assertRaises(OSError): owner.bind_initial_peer()
                with self.assertRaisesRegex(RuntimeError,'reopen'): owner.bind_initial_peer()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'observe_live',return_value=binding):
            owner.bind_initial_peer(); self.assertEqual(owner._load()['binding'],binding)
    def test_binding_intent_sync_failure_is_terminal_without_result(self):
        peer=self.native_peer()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'verify_created'):
            owner.prepare_initial(); real=owner._binding_file
            def fault(name,data):
                with mock.patch.object(edge.os,'fsync',side_effect=OSError('intent fsync')): return real(name,data)
            with mock.patch.object(owner,'_binding_file',side_effect=fault), mock.patch.object(peer,'observe_live') as observe:
                with self.assertRaises(OSError): owner.bind_initial_peer()
                observe.assert_not_called()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'observe_live') as observe:
            with self.assertRaisesRegex(RuntimeError,'incomplete binding'): owner.bind_initial_peer()
            observe.assert_not_called()

    def test_incomplete_binding_intent_never_reobserves_or_confirms(self):
        peer=self.native_peer()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'verify_created'):
            owner.prepare_initial()
            with mock.patch.object(peer,'observe_live',side_effect=OSError('crash')):
                with self.assertRaises(OSError): owner.bind_initial_peer()
        with self.native_owner(peer) as owner, mock.patch.object(peer,'observe_live') as observe, mock.patch.object(owner,'_confirm') as confirm:
            with self.assertRaisesRegex(RuntimeError,'incomplete binding'): owner.bind_initial_peer()
            observe.assert_not_called(); confirm.assert_not_called(); self.assertIsNone(owner._load()['binding'])
    def test_private_parent_cannot_be_exposed_by_envoy_mount(self):
        peer=self.native_peer(); peer.envoy_mounts['/run/forwarder']=str(self.root)
        with self.assertRaisesRegex(ValueError,'private material'): self.native_owner(peer)

    def test_bootstrap_publishes_pending_without_claiming_served(self):
        with self.owner() as owner, mock.patch.object(owner,'_confirm') as confirm:
            owner.prepare_initial(); data=owner._load()
            self.assertIsNone(data['current']); self.assertEqual(data['pending']['phase'],'staged')
            self.assertTrue((self.root/'watched/sds.json').is_file()); confirm.assert_not_called()
            with self.assertRaisesRegex(RuntimeError,'reconciliation'): owner.renew()
        with self.owner() as owner, mock.patch.object(owner,'_confirm') as confirm:
            owner.reconcile(); self.assertIsNotNone(owner._load()['current']); confirm.assert_called_once()

    def test_pending_confirmation_blocks_rotation_then_reconciles_and_rollback(self):
        with self.owner() as owner, mock.patch.object(owner,'_confirm',side_effect=ValueError('transport')):
            with self.assertRaises(ValueError): owner.renew()
            pending=owner._load()['pending']; self.assertEqual(pending['phase'],'staged')
            with self.assertRaisesRegex(RuntimeError,'reconciliation'): owner.renew()
            with self.assertRaisesRegex(RuntimeError,'reconciliation'): owner.rollback()
            with self.assertRaisesRegex(RuntimeError,'reconciliation'): owner.renew_due(10)
        with self.owner() as owner, mock.patch.object(owner,'_confirm') as confirm:
            owner.reconcile(); first=owner._load()['current']; self.assertEqual(first,pending['candidate'])
            owner.renew(); second=owner._load()['current']; self.assertNotEqual(first,second)
            owner.rollback(); self.assertEqual(owner._load()['current'],first)
            self.assertEqual(owner._load()['previous'],second)
            self.assertEqual([x.args[0] for x in confirm.call_args_list],[first,second,first])
            self.assertEqual(len(list((self.root/'published').iterdir())),2)
    def test_failed_publish_requires_reopen_and_preserves_candidate(self):
        real=edge._replace
        def fail_watch(directory,name,data):
            if directory==self.root/'watched': raise OSError('controlled')
            return real(directory,name,data)
        with self.owner() as owner, mock.patch.object(edge,'_replace',side_effect=fail_watch):
            with self.assertRaises(OSError): owner.renew()
            with self.assertRaisesRegex(RuntimeError,'reopen'): owner.reconcile()
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            self.assertEqual(owner._load()['pending']['phase'],'staged'); owner.reconcile()
            self.assertIsNone(owner._load()['pending'])
    def test_watched_directory_sync_failure_keeps_pending_on_reopen(self):
        real=edge._sync_dir
        def fail(path):
            if path==self.root/'watched': raise OSError('injected after replacement')
            return real(path)
        with self.owner() as owner, mock.patch.object(edge,'_sync_dir',side_effect=fail):
            with self.assertRaises(OSError): owner.renew()
            self.assertTrue((self.root/'watched/sds.json').is_file())
            with self.assertRaisesRegex(RuntimeError,'reopen'): owner.reconcile()
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            self.assertEqual(owner._load()['pending']['phase'],'staged'); owner.reconcile()
            self.assertIsNone(owner._load()['pending'])
    def test_journal_sync_failure_does_not_discard_reserved_intent(self):
        real=edge._sync_dir
        def fail(path):
            if path==self.root/'state' and (path/'journal.json').exists(): raise OSError('injected')
            return real(path)
        with self.owner() as owner, mock.patch.object(edge,'_sync_dir',side_effect=fail):
            with self.assertRaises(OSError): owner.renew()
            with self.assertRaisesRegex(RuntimeError,'reopen'): owner.renew()
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            self.assertEqual(owner._load()['pending']['phase'],'reserved'); owner.reconcile()
            self.assertIsNotNone(owner._load()['current'])
    def test_missing_journal_cannot_reinitialize_existing_publication(self):
        with self.owner() as owner, mock.patch.object(owner,'_confirm'): owner.renew()
        (self.root/'state/journal.json').unlink()
        with self.assertRaisesRegex(ValueError,'missing publication journal'): self.owner()

    def test_recorded_candidate_and_previous_commitments_refuse_replacement(self):
        with self.owner() as owner, mock.patch.object(owner,'_confirm',side_effect=ValueError('transport')):
            with self.assertRaises(ValueError): owner.renew()
            candidate=owner._load()['pending']['candidate']
        (self.root/'published'/candidate/'key.pem').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'commitment changed'): self.owner()
        (self.root/'published'/candidate/'key.pem').write_bytes(b'fixture')
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            owner.reconcile(); first=owner._load()['current']; owner.renew()
        (self.root/'published'/first/'cert.pem').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'commitment changed'): self.owner()

    def test_peer_configuration_drift_fails_closed(self):
        with self.owner() as owner:
            owner.peer.port=9555
            with self.assertRaisesRegex(ValueError,'identity'): owner.renew()
            self.assertFalse(list((self.root/'published').iterdir()))

    def test_reserved_crash_resumes_only_absent_candidate(self):
        with self.owner() as owner, mock.patch.object(owner.certs,'stage_native_edge',side_effect=OSError('controlled')):
            with self.assertRaises(OSError): owner.renew()
            self.assertEqual(owner._load()['pending']['phase'],'reserved')
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            owner.reconcile(); self.assertIsNotNone(owner._load()['current'])
    def test_existing_reserved_candidate_must_sync_before_stage_or_publish(self):
        def interrupted(version,days):
            FakeCertificates.stage_native_edge(FakeCertificates(self.root/'published',None,None,None),version,days)
            raise OSError('after candidate write')
        with self.owner() as owner, mock.patch.object(owner.certs,'stage_native_edge',side_effect=interrupted):
            with self.assertRaises(OSError): owner.renew()
        with self.owner() as owner, mock.patch.object(owner.certs,'sync_native_edge',side_effect=OSError('sync failed')), mock.patch.object(owner,'_confirm') as confirm:
            with self.assertRaises(OSError): owner.reconcile()
            self.assertEqual(owner._load()['pending']['phase'],'reserved'); self.assertFalse((self.root/'watched/sds.json').exists()); confirm.assert_not_called()
        with self.owner() as owner, mock.patch.object(owner,'_confirm'):
            owner.reconcile(); self.assertIsNotNone(owner._load()['current'])
    def test_sync_candidate_retries_each_durability_boundary(self):
        certs=object.__new__(certificates.Certificates); certs.directory=self.root
        version='v-'+'a'*32; path=self.root/version; path.mkdir(mode=0o700)
        for name in ('cert.pem','key.pem'): (path/name).write_bytes(b'x'); (path/name).chmod(0o600)
        with mock.patch.object(certs,'validate_native_edge',return_value=(path/'cert.pem',path/'key.pem')):
            for fail in range(1,5):
                seen=[]
                def sync(fd):
                    seen.append(fd)
                    if len(seen)==fail: raise OSError('sync')
                with mock.patch.object(certificates.os,'fsync',side_effect=sync):
                    with self.assertRaises(OSError): certs.sync_native_edge(version)
                    self.assertEqual(len(seen),fail)
            with mock.patch.object(certificates.os,'fsync') as sync:
                certs.sync_native_edge(version); self.assertEqual(sync.call_count,4)

    def test_partial_candidate_is_never_reissued(self):
        def partial(version,days): (self.root/'published'/version).mkdir(mode=0o700); raise OSError('controlled')
        with self.owner() as owner, mock.patch.object(owner.certs,'stage_native_edge',side_effect=partial):
            with self.assertRaises(OSError): owner.renew()
        with self.owner() as owner, mock.patch.object(owner,'_confirm') as confirm:
            with self.assertRaises(ValueError): owner.reconcile()
            confirm.assert_not_called(); self.assertEqual(owner._load()['pending']['phase'],'reserved')
    def test_single_owner_and_changed_config_rejected(self):
        with self.owner():
            with self.assertRaises((BlockingIOError,OSError)): self.owner()
        with self.owner() as owner, mock.patch.object(owner,'_confirm'): owner.renew()
        with self.assertRaisesRegex(ValueError,'journal'): self.owner(9444)
    def test_expiry_error_never_becomes_renewal(self):
        with self.owner() as owner, mock.patch.object(owner,'_confirm'): owner.renew()
        with self.owner() as owner, mock.patch.object(edge.subprocess,'run',return_value=mock.Mock(returncode=2)), mock.patch.object(owner,'renew') as renew:
            with self.assertRaisesRegex(ValueError,'expiry'): owner.renew_due(10)
            renew.assert_not_called()
    def test_exact_sans_and_eku_are_required(self):
        certs=object.__new__(certificates.Certificates); certs.directory=self.root; v='v-'+'a'*32; (self.root/v).mkdir(mode=0o700)
        for n in ('cert.pem','key.pem'): (self.root/v/n).write_bytes(b'x'); (self.root/v/n).chmod(0o600)
        outputs={'subjectAltName':b'X509v3 Subject Alternative Name:\n    DNS:pilot-gateway, DNS:pilot-destination\n','extendedKeyUsage':b'X509v3 Extended Key Usage:\n    TLS Web Server Authentication\n'}
        def run(*args): return outputs[args[-1]]
        with mock.patch.object(certs,'_read',return_value=b'x'), mock.patch.object(certs,'_validate'), mock.patch.object(certificates,'_run',side_effect=run):
            certs.validate_native_edge(v)
            for value in (b'X509v3 Subject Alternative Name:\n    DNS:pilot-destination\n',b'X509v3 Subject Alternative Name:\n    DNS:pilot-gateway, DNS:pilot-destination, DNS:other\n'):
                old=outputs['subjectAltName']; outputs['subjectAltName']=value
                with self.assertRaisesRegex(ValueError,'SAN'): certs.validate_native_edge(v)
                outputs['subjectAltName']=old
            outputs['extendedKeyUsage']=b'X509v3 Extended Key Usage:\n    TLS Web Client Authentication\n'
            with self.assertRaisesRegex(ValueError,'purpose'): certs.validate_native_edge(v)
    def test_native_commitment_contains_only_leaf_and_public_spki_digests(self):
        certs=object.__new__(certificates.Certificates); certs.directory=self.root
        version='v-'+'a'*32; cert=self.root/'cert'; key=self.root/'key'
        with mock.patch.object(certs,'validate_native_edge',return_value=(cert,key)), mock.patch.object(certs,'_read',return_value=b'public-pem'), mock.patch.object(certificates.ssl,'PEM_cert_to_DER_cert',return_value=b'leaf-der'), mock.patch.object(certificates,'_run',return_value=b'public-spki') as run:
            result=certs.native_edge_commitment(version)
        self.assertEqual(result,{'cert_sha256':hashlib.sha256(b'leaf-der').hexdigest(),'key_spki_sha256':hashlib.sha256(b'public-spki').hexdigest()})
        self.assertEqual(run.call_args.args,('pkey','-in',key,'-pubout','-outform','DER'))

    def test_candidate_rejects_hardlink_and_unsafe_permissions(self):
        certs=object.__new__(certificates.Certificates); certs.directory=self.root
        version='v-'+'a'*32; path=self.root/version; path.mkdir(mode=0o700)
        for name in ('cert.pem','key.pem'): (path/name).write_bytes(b'x'); (path/name).chmod(0o600)
        with mock.patch.object(certs,'_read',return_value=b'x'), mock.patch.object(certs,'_validate'), mock.patch.object(certificates,'_run',side_effect=[b'X509v3 Subject Alternative Name:\n    DNS:pilot-gateway, DNS:pilot-destination\n',b'X509v3 Extended Key Usage:\n    TLS Web Server Authentication\n']):
            certs.validate_native_edge(version)
        os.link(path/'key.pem',self.root/'linked')
        with self.assertRaisesRegex(ValueError,'unsafe'): certs.validate_native_edge(version)
        (self.root/'linked').unlink(); (path/'key.pem').chmod(0o644)
        with self.assertRaisesRegex(ValueError,'unsafe'): certs.validate_native_edge(version)

    def test_native_replica_rechecks_identity_mounts_and_fingerprint(self):
        import json
        cid='a'*64; image='sha256:'+'b'*64; net='c'*64; started='2026-11-07T00:00:00.000000000Z'
        sources={'/pilot/ca.crt':'/owned/ca','/pilot/tls/client.crt':'/owned/client','/pilot/tls/client.key':'/owned/key','/pilot/native_edge_probe.js':str(edge._PROBE)}
        sources.update({dst:'/owned/profile' for dst in edge._PROFILE_MOUNTS})
        peer=edge.NativeReplicaPeer(cid,image,net,sources,'e'*64,'sha256:'+'f'*64,{'/certs':'/owned/certs','/run/watch':'/owned/watch','/run/forwarder':'/owned/forwarder'})
        values=[cid,image,edge._NODE_IMAGE,['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'],True,started,{'default':{'NetworkID':net}},[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in sources.items()],True,{}, {'/data':'rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp':'rw,nosuid,nodev,noexec,size=16m,mode=1777'},'running','owned-network']
        def inspect(): return ('\n'.join(json.dumps(x) for x in values)+'\n').encode()
        fingerprint=bytes.fromhex('dd'*32); commands=[]
        def command(args,timeout=10):
            commands.append(args)
            if args[1]=='image': return json.dumps(image).encode()
            if args[1]=='network': return json.dumps(net).encode()
            return inspect() if args[1]=='inspect' else fingerprint.hex().encode()+b'\n'
        with mock.patch.object(edge,'_command',side_effect=command), mock.patch.object(peer,'_envoy_and_topology',return_value=('topology',)): peer.confirm(fingerprint,{'replica_started':started,'envoy_started':started})
        self.assertEqual([x[1] for x in commands],['image','inspect','network','exec','image','inspect','network'])
        self.assertIn('/usr/local/bin/node',commands[3]); self.assertIn('NODE_OPTIONS=',commands[3]); self.assertIn('NODE_PATH=',commands[3]); self.assertIn('-i',commands[3])
        for index,bad in [(1,'sha256:'+'d'*64),(5,'2026-11-08T00:00:00Z'),(6,{'default':{'NetworkID':'d'*64}}),(8,False)]:
            old=values[index]; values[index]=bad
            with mock.patch.object(edge,'_command',side_effect=command), mock.patch.object(peer,'_envoy_and_topology',return_value=('topology',)):
                with self.assertRaises(ValueError): peer.confirm(fingerprint,{'replica_started':started,'envoy_started':started})
            values[index]=old
        values[7].append({'Type':'bind','Source':'/owned/shadow','Destination':'/usr/local/bin/node','RW':False})
        with mock.patch.object(edge,'_command',side_effect=command), mock.patch.object(peer,'_envoy_and_topology',return_value=('topology',)):
            with self.assertRaises(ValueError): peer.confirm(fingerprint,{'replica_started':started,'envoy_started':started})
        values[7].pop()
        values[7][2]['RW']=True
        with mock.patch.object(edge,'_command',side_effect=command), mock.patch.object(peer,'_envoy_and_topology',return_value=('topology',)):
            with self.assertRaises(ValueError): peer.confirm(fingerprint,{'replica_started':started,'envoy_started':started})
        values[7][2]['RW']=False
        with mock.patch.object(edge,'_command',side_effect=lambda args,timeout=10: json.dumps(image).encode() if args[1]=='image' else json.dumps(net).encode() if args[1]=='network' else inspect() if args[1]=='inspect' else b'00'*32+b'\n'), mock.patch.object(peer,'_envoy_and_topology',return_value=('topology',)):
            with self.assertRaises(ValueError): peer.confirm(fingerprint,{'replica_started':started,'envoy_started':started})
    def test_native_peer_detects_restart_after_handshake(self):
        import json
        cid='a'*64; image='sha256:'+'b'*64; net='c'*64; started='2026-11-07T00:00:00Z'
        mounts={'/pilot/ca.crt':'/owned/ca','/pilot/tls/client.crt':'/owned/client','/pilot/tls/client.key':'/owned/key','/pilot/native_edge_probe.js':str(edge._PROBE)}
        mounts.update({dst:'/owned/profile' for dst in edge._PROFILE_MOUNTS})
        peer=edge.NativeReplicaPeer(cid,image,net,mounts,'e'*64,'sha256:'+'f'*64,{'/certs':'/owned/certs','/run/watch':'/owned/watch','/run/forwarder':'/owned/forwarder'}); values=[cid,image,edge._NODE_IMAGE,['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'],True,started,{'net':{'NetworkID':net}},[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in mounts.items()],True,{}, {'/data':'rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp':'rw,nosuid,nodev,noexec,size=16m,mode=1777'},'running','owned-network']
        called=[]
        def command(args,timeout=10):
            if args[1]=='exec': return b'aa'*32+b'\n'
            if args[1]=='image': return json.dumps(image).encode()
            if args[1]=='network': return json.dumps(net).encode()
            called.append(True)
            current=values.copy()
            if len(called)>1: current[5]='2026-11-07T00:00:01Z'
            return ('\n'.join(json.dumps(x) for x in current)+'\n').encode()
        with mock.patch.object(edge,'_command',side_effect=command):
            with self.assertRaises(ValueError): peer.confirm(bytes.fromhex('aa'*32),{'replica_started':started,'envoy_started':started})

    def test_created_peer_checks_network_mode_mounts_and_alias_without_membership(self):
        import json
        peer=self.native_peer(); net=peer.network_id; created='0001-01-01T00:00:00Z'
        replica=[peer.cid,peer.image_id,edge._NODE_IMAGE,['node','/usr/src/node-red/node_modules/node-red/red.js','--userDir','/data','--settings','/pilot/settings.js'],False,created,{'default':{'NetworkID':'','Aliases':['replica']}},[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in peer.mounts.items()],True,{}, {'/data':'rw,nosuid,nodev,noexec,size=16m,mode=1777','/tmp':'rw,nosuid,nodev,noexec,size=16m,mode=1777'},'created','owned-network']
        envoy=[peer.envoy_cid,peer.envoy_image_id,edge._ENVOY_IMAGE,False,created,{'default':{'NetworkID':'','Aliases':['pilot-gateway']}},{},'created','owned-network',[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in peer.envoy_mounts.items()],True]
        calls=[]
        def command(args,timeout=10):
            calls.append(args)
            if args[1]=='image': return json.dumps(peer.image_id if args[-1]==edge._NODE_IMAGE else peer.envoy_image_id).encode()
            if args[1]=='network':
                if '{{json .Containers}}' in args: raise AssertionError('created membership must not be required')
                return json.dumps(net if args[-1]=='owned-network' else 'd'*64).encode()
            return ('\n'.join(json.dumps(x) for x in (replica if args[-1]==peer.cid else envoy))+'\n').encode()
        with mock.patch.object(edge,'_command',side_effect=command): peer.verify_created()
        self.assertFalse(any('{{json .Containers}}' in c for c in calls))
        for field,bad in [(4,True),(11,'running'),(12,'other-network')]:
            old=replica[field]; replica[field]=bad
            with mock.patch.object(edge,'_command',side_effect=command):
                with self.assertRaises(ValueError): peer.verify_created()
            replica[field]=old
        envoy[5]['default']['Aliases']=[]
        with mock.patch.object(edge,'_command',side_effect=command):
            with self.assertRaisesRegex(ValueError,'network'): peer.verify_created()
        envoy[5]['default']['Aliases']=['pilot-gateway']
        envoy[9].append({'Type':'bind','Source':str(self.root),'Destination':'/leak','RW':False})
        with mock.patch.object(edge,'_command',side_effect=command):
            with self.assertRaisesRegex(ValueError,'mounts'): peer.verify_created()

    def test_envoy_alias_is_unique_and_bound_to_owned_instance(self):
        import json
        cid='a'*64; envoy='e'*64; image='sha256:'+'b'*64; envoy_image='sha256:'+'f'*64; net='c'*64; started='2026-11-07T00:00:00Z'
        mounts={'/pilot/ca.crt':'/owned/ca','/pilot/tls/client.crt':'/owned/client','/pilot/tls/client.key':'/owned/key','/pilot/native_edge_probe.js':str(edge._PROBE)}
        mounts.update({dst:'/owned/profile' for dst in edge._PROFILE_MOUNTS})
        peer=edge.NativeReplicaPeer(cid,image,net,mounts,envoy,envoy_image,{'/certs':'/owned/certs','/run/watch':'/owned/watch','/run/forwarder':'/owned/forwarder'})
        mappings={cid:{'default':{'NetworkID':net,'Aliases':['replica']}},envoy:{'default':{'NetworkID':net,'Aliases':['pilot-gateway']}}}
        def enc(items): return ('\n'.join(json.dumps(x) for x in items)+'\n').encode()
        def command(args,timeout=10):
            if args[1]=='image': return json.dumps(envoy_image).encode()
            if args[1]=='network': return json.dumps(net if '{{json .Id}}' in args else {cid:{},envoy:{}}).encode()
            if len(args)==5 and args[-1]==envoy and '.Config.Image' in args[3]: return enc([envoy,envoy_image,edge._ENVOY_IMAGE,True,started,mappings[envoy],{},'running','owned-network',[{'Type':'bind','Source':src,'Destination':dst,'RW':False} for dst,src in peer.envoy_mounts.items()],True])
            return enc([args[-1],mappings[args[-1]]])
        with mock.patch.object(edge,'_command',side_effect=command): peer._envoy_and_topology(edge.time.monotonic()+30)
        mappings[cid]['default']['Aliases'].append('pilot-gateway')
        with mock.patch.object(edge,'_command',side_effect=command):
            with self.assertRaisesRegex(ValueError,'alias'): peer._envoy_and_topology(edge.time.monotonic()+30)

    def test_confirmation_checks_peer_and_exact_exchange_without_listener(self):
        body=b'{"result":"owned-pilot-ok"}'; reply=b'HTTP/1.1 200 OK\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body
        class Stream:
            def __init__(self,peer,content): self.peer=peer; self.content=content; self.sent=b''
            def __enter__(self): return self
            def __exit__(self,*_): pass
            def getpeercert(self,**_): return self.peer
            def sendall(self,data): self.sent=data
            def settimeout(self,_): pass
            def recv(self,n): result=self.content[:n]; self.content=self.content[n:]; return result
        class Context:
            def __init__(self,stream): self.stream=stream
            def load_cert_chain(self,*_): pass
            def wrap_socket(self,raw,server_hostname):
                if server_hostname!='pilot-destination': raise AssertionError('wrong name')
                return self.stream
        class Raw:
            def __enter__(self): return self
            def __exit__(self,*_): pass
        with self.owner() as owner:
            owner.certs.stage_native_edge('v-'+'a'*32)
            commitment={'cert_sha256':hashlib.sha256(b'der').hexdigest(),'key_spki_sha256':'a'*64}
            for peer,content,ok in [(b'der',reply,True),(b'wrong',reply,False),(b'der',reply.replace(b'200 OK',b'500 NO'),False),(b'der',reply[:-1],False)]:
                stream=Stream(peer,content)
                with mock.patch.object(owner.certs,'native_edge_commitment',return_value=commitment), mock.patch.object(edge.ssl,'create_default_context',return_value=Context(stream)), mock.patch.object(edge.socket,'create_connection',return_value=Raw()):
                    if ok: owner._confirm('v-'+'a'*32,commitment,None); self.assertIn(b'POST /pilot',stream.sent)
                    else:
                        with self.assertRaises(ValueError): owner._confirm('v-'+'a'*32,commitment,None)

if __name__=='__main__': unittest.main()
