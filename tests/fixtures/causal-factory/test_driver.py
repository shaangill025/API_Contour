import json
import copy
import hashlib
import os
from pathlib import Path
import re
import runpy
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[3]
DRIVER = runpy.run_path(str(ROOT / 'scripts/test-postgres-causal-factory.py'))


class DriverTests(unittest.TestCase):
    def test_collector_build_uses_separate_private_config(self):
        with tempfile.TemporaryDirectory() as temp:
            work = Path(temp)
            config = work / 'docker-config'; config.mkdir(mode=0o700)
            iid = 'sha256:' + 'a' * 64
            token = 'b' * 64
            calls = []
            def build(args, **kwargs):
                calls.append(args)
                build_config = Path(args[args.index('--config') + 1])
                self.assertNotEqual(build_config, config)
                self.assertEqual(build_config.stat().st_mode & 0o777, 0o700)
                (build_config / 'buildx').mkdir()
                Path(args[args.index('--iidfile') + 1]).write_text(iid)
            def inspect(kind, ident):
                self.assertEqual((kind, ident), ('image', iid))
                return {'Id': iid, 'Config': {'Labels': {DRIVER['LABEL']: token}}}
            owned, uncertain, diagnostic = [], [], {}
            result = DRIVER['build_collector_image'](work, Path('/docker'), Path('/socket'),
                'fixture', token, {'bounded_process_output': build}, inspect, owned, uncertain, diagnostic)
            self.assertEqual(result, iid)
            self.assertEqual(list(config.iterdir()), [])
            self.assertTrue((work / 'docker-build-config' / 'buildx').is_dir())
            self.assertEqual(calls[0][:3], ['/docker', '--host', 'unix:///socket'])
            self.assertEqual(owned, [('image', iid, token)])
            self.assertEqual(uncertain, [])
            self.assertEqual(diagnostic['collector_image'], iid)

    def test_stale_fault_requires_checked_newer_session_and_unchanged_original(self):
        check=DRIVER['validate_advanced_session']
        original='1 1000 2000'; advanced='ADVANCED 2 1100 2100'
        self.assertEqual(check('original','fault',original,advanced,original,'2 1100 2100'),2)
        cases=[('original','original',original,advanced,original,'2 1100 2100'),
               ('original','fault',original,'ADVANCED 1 1100 2100',original,'1 1100 2100'),
               ('original','fault',original,'ADVANCED 0 1100 2100',original,'0 1100 2100'),
               ('original','fault',original,'ADVANCED 2 2100 2100',original,'2 2100 2100'),
               ('original','fault',original,advanced,'1 1000 2001','2 1100 2100'),
               ('original','fault',original,advanced,original,'2 1100 2101'),
               ('original','fault',original,advanced+' extra',original,'2 1100 2100')]
        for args in cases:
            with self.subTest(args=args), self.assertRaises(RuntimeError): check(*args)

    def test_committed_producer_evidence_is_exact(self):
        root, activity, parent, attempt = ('a'*32, 'b'*32, 'c'*32, 'd'*32)
        marker = 'e'*64
        events = [
            {'kind':'root','event_id':'1'*32,'seq':1,'root':root},
            {'kind':'delivery','event_id':'2'*32,'seq':2,'root':root,'activity':activity,'parent':parent},
            {'kind':'attempt','event_id':'3'*32,'seq':3,'root':root,'activity':activity,'attempt':attempt,'marker_digest':marker},
        ]
        batch = {'wire_version':1,'batch_id':'00000000-0000-4000-8000-000000000001',
                 'tenant_id':'tenant','runtime_id':'runtime','session_epoch':1,'first_seq':1,'last_seq':3,'events':events}
        def encoded(value): return json.dumps(value,sort_keys=True,separators=(',', ':')).encode()
        def stored(value):
            raw=encoded(value)
            return {'canonical':raw.hex(),'digest':hashlib.sha256(b'apicontour/causal-events/1\n'+raw).hexdigest(),
                    'events':[{'event':e,'digest':hashlib.sha256(b'apicontour/causal-event/1\n'+encoded(e)).hexdigest()} for e in value['events']]}
        check=DRIVER['validate_producer_batches']
        self.assertEqual(check([stored(batch)],'tenant','runtime',1,[marker]), {batch['batch_id']})
        for change in ('epoch','tenant','digest','event_digest','marker','count','kind','duplicate'):
            rows=[stored(batch)]
            if change=='epoch': rows=[stored(dict(batch,session_epoch=2))]
            elif change=='tenant': rows=[stored(dict(batch,tenant_id='other'))]
            elif change=='digest': rows[0]['digest']='0'*64
            elif change=='event_digest': rows[0]['events'][0]['digest']='0'*64
            elif change=='marker':
                bad=copy.deepcopy(batch); bad['events'][2]['marker_digest']='f'*64; rows=[stored(bad)]
            elif change=='count': rows[0]['events'].pop()
            elif change=='kind':
                bad=copy.deepcopy(batch); bad['events'][2]={'kind':'loss','event_id':'3'*32,'seq':3}; rows=[stored(bad)]
            else: rows.append(copy.deepcopy(rows[0]))
            with self.subTest(change=change), self.assertRaises(AssertionError): check(rows,'tenant','runtime',1,[marker])

    def test_probe_stage_is_exact_closed_allowlist(self):
        classify = DRIVER['probe_stage']
        source = DRIVER['EXAMPLE'].read_text()
        emitted = set(re.findall(r'(?:map_err\(\|_\|\s*|Err\()"([A-Za-z ]+)"', source))
        bind_emitted = set(re.findall(r'=> "(bind_[a-z_]+)"', source))
        self.assertEqual(bind_emitted, {stage for stage in DRIVER['PROBE_STAGES']
                                        if stage.startswith('bind_') and stage not in DRIVER['PROBE_OBSERVATIONS']})
        emitted.update(bind_emitted)
        self.assertTrue(emitted)
        self.assertLessEqual(emitted, DRIVER['PROBE_STAGES'])
        for stage in DRIVER['PROBE_STAGES']:
            self.assertEqual(classify(b'factory probe: ' + stage.encode('ascii') + b'\n'), stage)
        for unknown in (b'factory probe: private-secret\n', b'factory probe: bind_invalid\nprivate-secret',
                        b'factory probe: bind_database_deadline: secret\n',
                        b'factory probe: bind_invalid_target_image\nprivate-secret',
                        b'factory probe: bind_invalid_target_unknown\n',
                        b'factory probe: bind_invalid_target_image unsafe deadline_reached extra\n',
                        b'factory probe: bind_invalid_metadata unsafe deadline_reached\n',
                        b'factory probe: bind_invalid_target_image secret deadline_reached\n',
                        b'factory probe: bind', b'private-secret', b'x' * 10000,
                        b'factory probe: \xff\n', 'factory probe: bind\n'):
            self.assertIsNone(classify(unknown))

    def test_final_drain_clears_previous_stage_on_read_failure(self):
        stderr = b'factory probe: bind\n'
        diagnostic = {'probe_stage': DRIVER['probe_stage'](stderr)}
        self.assertEqual(diagnostic['probe_stage'], 'bind')
        for overflow, read_failed in ((True, False), (False, True), (True, True)):
            diagnostic['probe_stage'] = DRIVER['final_probe_stage'](stderr, overflow, read_failed)
            self.assertIsNone(diagnostic['probe_stage'])
            diagnostic['probe_stage'] = 'bind'
        self.assertEqual(DRIVER['final_probe_stage'](stderr, False, False), 'bind')

    def test_primary_and_stop_failure_do_not_remove_known_proxy(self):
        primary, stop = ValueError('primary'), RuntimeError('stop')
        uncertain, remote = [], []
        def fail_stop():
            raise stop
        with self.assertRaises(BaseExceptionGroup) as caught:
            DRIVER['cleanup_with_evidence'](primary, uncertain, True, ('cid', 'owner'), True, True,
                                            fail_stop, lambda: remote.append('removed'))
        self.assertEqual(caught.exception.exceptions, (primary, stop))
        self.assertTrue(any(item[0] == 'local' for item in uncertain))
        self.assertEqual(remote, [])

    def test_primary_and_stop_failure_retained_with_unknown_create(self):
        primary = ValueError('primary')
        stop = RuntimeError('stop')
        uncertain, remote = [], []
        def fail_stop():
            raise stop
        with self.assertRaises(BaseExceptionGroup) as caught:
            DRIVER['cleanup_with_evidence'](primary, uncertain, True, None, True, False,
                                            fail_stop, lambda: remote.append('removed'))
        self.assertEqual(caught.exception.exceptions, (primary, stop))
        self.assertTrue(any(item[0] == 'container' for item in uncertain))
        self.assertTrue(any(item[0] == 'local' for item in uncertain))
        self.assertEqual(remote, [])

    def test_source_snapshot_detects_loaded_helper_and_node_test_changes(self):
        changed = set()
        bridge = {'source_paths': lambda: [],
                  'digest_file': lambda p: 'changed' if str(p) in changed else 'original'}
        before = DRIVER['source_snapshot'](bridge)
        for relative in ('scripts/test-postgres-causal-https.py', 'tests/fixtures/causal-factory/test_tls_peer.js'):
            path = str(ROOT / relative)
            self.assertIn(path, before)
            changed.add(path)
            self.assertNotEqual(before, DRIVER['source_snapshot'](bridge))
            changed.clear()

    def test_same_cid_restart_is_not_same_generation(self):
        cid, owner = 'a' * 64, 'b' * 64
        info = {'Id':cid, 'Config':{'Labels':{'org.apicontour.causal.owner':owner}},
                'RestartCount':0, 'State':{'Status':'running', 'Running':True,
                                           'Pid':123, 'StartedAt':'2026-01-01T00:00:00Z'}}
        initial = DRIVER['proxy_generation'](info, cid, owner)
        info['State']['Pid'] = 124
        self.assertNotEqual(initial, DRIVER['proxy_generation'](info, cid, owner))
        info['State']['Pid'] = 123
        info['State']['StartedAt'] = '2026-01-01T00:00:01Z'
        self.assertNotEqual(initial, DRIVER['proxy_generation'](info, cid, owner))
        info['RestartCount'] = 1
        with self.assertRaises(RuntimeError):
            DRIVER['proxy_generation'](info, cid, owner)

    def test_collector_requires_exact_owned_image_and_generation(self):
        cid, owner, image = 'a'*64, 'b'*64, 'sha256:'+'c'*64
        info = {'Id':cid,'Image':image,'Config':{'Labels':{DRIVER['LABEL']:owner}},'RestartCount':0,
                'State':{'Status':'running','Running':True,'Pid':123,'StartedAt':'2026-01-01T00:00:00Z'}}
        initial=DRIVER['fixture_generation'](info,cid,owner,image)
        changed=copy.deepcopy(info); changed['State']['StartedAt']='2026-01-01T00:00:01Z'
        self.assertNotEqual(initial,DRIVER['fixture_generation'](changed,cid,owner,image))
        for change in ('image','owner','pid','restart'):
            bad=copy.deepcopy(info)
            if change=='image': bad['Image']='sha256:'+'d'*64
            elif change=='owner': bad['Config']['Labels'][DRIVER['LABEL']]='d'*64
            elif change=='pid': bad['State']['Pid']=0
            else: bad['RestartCount']=1
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                DRIVER['fixture_generation'](bad,cid,owner,image)

    def test_native_linux_uid_preflight(self):
        with self.assertRaises(RuntimeError): DRIVER['check_native_uid']('linux', 501)
        DRIVER['check_native_uid']('linux', 1000)
        DRIVER['check_native_uid']('darwin', 501)

    def test_cargo_artifact_is_unique_and_contained(self):
        with tempfile.TemporaryDirectory(prefix='contour-factory-artifact-') as temp:
            target = Path(temp).resolve()
            binary = target / 'probe'
            binary.write_bytes(b'fixture')
            os.chmod(binary, 0o700)
            entry = {'reason':'compiler-artifact', 'target':{'name':'causal_factory_probe',
                'kind':['example'], 'src_path':str(DRIVER['EXAMPLE'])},
                'profile':{'test':False, 'opt_level':'3', 'debug_assertions':False}, 'executable':str(binary)}
            line = json.dumps(entry)
            self.assertEqual(DRIVER['artifact']([line], target), binary)
            for profile in ({'test':False},
                            {'test':False, 'opt_level':'0', 'debug_assertions':True},
                            {'test':False, 'opt_level':'3', 'debug_assertions':True}):
                with self.assertRaises(RuntimeError):
                    DRIVER['artifact']([json.dumps(dict(entry, profile=profile))], target)
            with self.assertRaises(RuntimeError):
                DRIVER['artifact']([line, line], target)
            entry['executable'] = '/bin/sh'
            with self.assertRaises((RuntimeError, ValueError)):
                DRIVER['artifact']([json.dumps(entry)], target)

    def test_cleanup_absence_requires_specific_daemon_response(self):
        class Result:
            returncode, stdout, stderr = 1, b'[]\n', b'Error: No such object: abc\n'
        bridge = {'run_process': lambda *args, **kwargs: Result()}
        DRIVER['require_absent'](bridge, ['docker'], 'container', 'abc')
        Result.stderr = b'permission denied\n'
        with self.assertRaises(RuntimeError):
            DRIVER['require_absent'](bridge, ['docker'], 'container', 'abc')


if __name__ == '__main__':
    unittest.main()
