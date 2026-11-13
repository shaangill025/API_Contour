"""Offline controls for the dormant SQL24 database-TLS qualification source."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('live_profile', ROOT / 'scripts/test-postgres-causal-live-profile.py')
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

class Driver(unittest.TestCase):
    def test_success_requires_every_case_and_clean_finalization(self):
        complete=list(d.REQUIRED_STAGES)
        self.assertTrue(d.qualification_pass(None,[],complete,'a'*64))
        self.assertFalse(d.qualification_pass(RuntimeError('protocol'),[],complete,'a'*64))
        self.assertFalse(d.qualification_pass(None,[RuntimeError('cleanup')],complete,'a'*64))
        self.assertFalse(d.qualification_pass(None,[RuntimeError('source changed')],complete,'a'*64))
        self.assertFalse(d.qualification_pass(None,[],complete[:-1],'a'*64))
        self.assertFalse(d.qualification_pass(None,[],complete[:4]+complete[5:],'a'*64))
        self.assertFalse(d.qualification_pass(None,[],complete,None))
        self.assertFalse(d.qualification_pass(None,[],complete+['unexpected'],'a'*64))

    def test_complete_candidate_argument_vector(self):
        work=Path('/private/synthetic')
        ids=['00000000-0000-4000-8000-%012d' % n for n in range(1,11)]
        original_ids=['10000000-0000-4000-8000-%012d' % n for n in range(1,11)]
        nonce='aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
        base=['/private/probe','localhost','5432','contour_fixture','/private/ca.crt',
              'causal_issuer_login','causal_provisioner_login','/private/grant.pub',
              '/private/policy.pub','/private/grant.json','/private/policy.json',
              '/private/batch.json','33'*32,*original_ids,nonce]
        expected=['/private/probe','localhost','5432','contour_fixture','/private/ca.crt',
                  'causal_issuer_login','causal_provisioner_login','/private/grant.pub',
                  '/private/policy.pub','/private/synthetic/candidate_grant.json',
                  '/private/synthetic/candidate_policy.json','/private/batch.json',
                  '55'*32,*ids,nonce]
        self.assertEqual(d.candidate_arguments(base,work,ids),expected)
        self.assertEqual(d.candidate_arguments(base,work,ids)+['positive'],expected+['positive'])
        self.assertEqual(base[9:13],['/private/grant.json','/private/policy.json','/private/batch.json','33'*32])
        for bad_base,bad_ids in ((base[:-1],ids),(base,ids[:-1])):
            with self.assertRaises(ValueError): d.candidate_arguments(bad_base,work,bad_ids)

    def test_profile_transition_is_exact_and_scoped(self):
        ids = ['00000000-0000-4000-8000-%012d' % n for n in range(1, 11)]
        before = []
        d.profile_checks(lambda sql: before.append(sql), ids, False)
        self.assertEqual(len(before), 3)
        self.assertIn('000000000503', before[1])
        self.assertIn('EXCEPTION WHEN check_violation', before[1])
        after = []
        def execute(sql):
            after.append(sql)
            return '1' if sql.startswith('SELECT count(*)') else ''
        d.profile_checks(execute, ids, True)
        self.assertEqual(len(after), 16)
        for sql in before+after:
            if 'contour.register_causal_profile(' in sql or 'contour.enroll_causal_runtime(' in sql:
                self.assertTrue(sql.startswith("BEGIN; SELECT set_config("))
                self.assertTrue(sql.endswith(' COMMIT;'))
                self.assertEqual(sql.count('contour.register_causal_profile(')+sql.count('contour.enroll_causal_runtime('),1)
        positive=[sql for sql in after if 'SELECT contour.register_causal_profile(' in sql or 'SELECT contour.enroll_causal_runtime(' in sql]
        self.assertEqual(positive[1],positive[2])
        self.assertEqual(positive[3],positive[4])
        self.assertTrue(any('000000000502' in sql for sql in after))
        self.assertTrue(any('insufficient_privilege' in sql for sql in after))
        self.assertTrue(any('000000000501' in sql and 'a4d698a75a' in sql for sql in after))
        self.assertTrue(any('000000000503' in sql and 'b0bcc91455' in sql for sql in after))
        with self.assertRaisesRegex(AssertionError, 'registry row mismatch'):
            d.profile_checks(lambda _: '', ids, True)

    def test_artifact_identity_is_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve(); exe = root / 'probe'; exe.write_text('x'); exe.chmod(0o700)
            entry = {'reason':'compiler-artifact','target':{'name':'causal_live_profile_probe','kind':['example'],'src_path':str(d.EXAMPLE)},'profile':{'test':False},'executable':str(exe)}
            bridge = {'digest_file':lambda _: 'hash'}
            self.assertEqual(d.artifact([json.dumps(entry)],root,bridge),exe)
            with self.assertRaises(RuntimeError): d.artifact([json.dumps(entry)] * 2,root,bridge)
            entry['target']['name']='other'
            with self.assertRaises(RuntimeError): d.artifact([json.dumps(entry)],root,bridge)

    def test_extra_migration_and_symlink_are_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp).resolve(); folder=root/'db/opt-in-migrations'; folder.mkdir(parents=True)
            for name in d.OPT+d.SOURCE_ONLY_MIGRATIONS: (folder/(name+'.sql')).write_text('x')
            (folder/'0025_other.sql').write_text('x')
            with mock.patch.object(d,'ROOT',root), self.assertRaises(ValueError):
                d.snapshot({'source_paths':lambda:[],'digest_file':lambda _: 'hash'})
            target=root/'target'; target.write_text('x'); link=root/'link'; link.symlink_to(target)
            with self.assertRaises(ValueError): d.safe(link)

    def test_postcommit_context_requires_exact_committed_nonce_and_resets_role(self):
        from types import SimpleNamespace
        for mode in ('pass','not_committed','unexpected_success','probe_failure'):
            with self.subTest(mode=mode):
                calls=[]; counts=iter(['0','0' if mode=='not_committed' else '1'])
                def execute(sql):
                    calls.append(sql)
                    if sql.startswith('SELECT count(*) FROM contour.causal_sessions'): return next(counts)
                    return ''
                def run(args,**kwargs):
                    self.assertEqual(args[-1],'issue_context_unknown')
                    if mode=='probe_failure': raise RuntimeError('failure')
                    return SimpleNamespace(returncode=0,stderr=b'',stdout=b'CONTEXT_UNEXPECTED_SUCCESS\n' if mode=='unexpected_success' else b'CONTEXT_OUTCOME_UNKNOWN\n')
                bridge={'IDS':['tenant','runtime'],'run_process':run}
                import contextlib,io
                sink=io.StringIO()
                with contextlib.redirect_stdout(sink):
                    if mode=='pass': d.issue_context_unknown(['probe']*24,{},execute,bridge)
                    else:
                        with self.assertRaises((AssertionError,RuntimeError)): d.issue_context_unknown(['probe']*24,{},execute,bridge)
                wanted={'pass':'unknown','unexpected_success':'unexpected-success','probe_failure':'wrong'}
                self.assertEqual(sink.getvalue(),'' if mode=='not_committed' else 'issue-context committed=1 outcome='+wanted[mode]+'\n')
                self.assertNotIn('tenant',sink.getvalue()); self.assertNotIn('runtime',sink.getvalue())
                self.assertEqual(calls[-1],'ALTER ROLE causal_issuer_login RESET apicontour.tenant_id;')
                self.assertTrue(any('ALTER ROLE causal_issuer_login SET apicontour.tenant_id' in sql for sql in calls))
                if mode in ('pass','not_committed','unexpected_success','probe_failure'):
                    queries=[sql for sql in calls if sql.startswith('SELECT count(*)')]
                    self.assertEqual(len(queries),2); self.assertEqual(queries[0],queries[1])

    def test_deferred_sequence_privilege_checked_before_either_probe(self):
        for function,login,sequence in ((d.issue_unknown,'causal_issuer_login','fixture_issue_entered'),
                                        (d.marker_unknown,'causal_provisioner_login','fixture_marker_commit_entered')):
            with self.subTest(login=login):
                calls=[]
                def execute(sql):
                    calls.append(sql)
                    if 'has_sequence_privilege' in sql: return 'false'
                    return ''
                runner=mock.Mock()
                with self.assertRaisesRegex(AssertionError,'sequence privilege'):
                    function(['probe']*24,{},execute,{'IDS':['tenant','runtime'],'run_process':runner})
                runner.assert_not_called()
                self.assertEqual(len(calls),2)
                self.assertIn('GRANT USAGE ON SEQUENCE contour.'+sequence+' TO '+login,calls[0])
                self.assertIn("has_sequence_privilege('"+login+"','contour."+sequence+"','USAGE')",calls[1])

    def test_unknown_issue_requires_entered_commit_and_same_request_retry(self):
        from types import SimpleNamespace
        calls=[]
        def execute(sql):
            calls.append(sql)
            if 'has_sequence_privilege' in sql: return 't'
            if 'is_called::text' in sql: return 'true|1'
            if 'pg_stat_activity' in sql: return '0'
            if 'SELECT count(*) FROM contour.causal_sessions' in sql: return '1'
            return ''
        runner=mock.Mock(side_effect=[SimpleNamespace(returncode=0,stderr=b'',stdout=b'OUTCOME_UNKNOWN\n'), SimpleNamespace(returncode=0,stderr=b'',stdout=b'RETRIED\n')])
        bridge={'run_process':runner,'IDS':['tenant','runtime']}
        d.issue_unknown(['probe']*23,{},execute,bridge)
        first,second=(c.args[0] for c in runner.call_args_list)
        self.assertEqual(first[:-1],second[:-1])
        self.assertEqual((first[-1],second[-1]),('issue_unknown','issue_retry'))
        runner.reset_mock(side_effect=True)
        runner.return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'OUTCOME_UNKNOWN\n')
        with self.assertRaisesRegex(AssertionError,'never entered'):
            d.issue_unknown(['probe']*23,{},lambda sql:'t' if 'has_sequence_privilege' in sql else ('false|1' if 'is_called' in sql else ''),bridge)
        self.assertEqual(runner.call_count,1)

    def test_clock_and_quota_guards_fail_closed(self):
        from types import SimpleNamespace
        ids=['tenant','runtime','collector']
        with self.assertRaisesRegex(AssertionError,'clock guard'):
            d.clock_guard(lambda _: 'true|true|false',ids)
        d.clock_guard(lambda _: 'tenant\ntrue|false|false',ids)
        calls=[]
        def execute(sql):
            calls.append(sql)
            return '0|1073741824' if 'SELECT (SELECT count(*)' in sql else ''
        bridge={'IDS':ids,'run_process':mock.Mock(return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'QUOTA\n'))}
        d.quota_guard(['probe']*23,{},execute,bridge)
        self.assertEqual(len(calls),3)
        self.assertIn('1073741824',calls[0])
        self.assertIn("VALUES ('tenant',0)",calls[-1])
        bridge['run_process'].return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'QUOTA\nextra')
        with self.assertRaisesRegex(AssertionError,'quota protocol'):
            d.quota_guard(['probe']*23,{},execute,bridge)

    def test_negative_grants_use_correct_files_and_key_position(self):
        from types import SimpleNamespace
        runner=mock.Mock(return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'REFUSED\n'))
        bridge={'IDS':['tenant','runtime'],'run_process':runner}
        base=['arg'+str(i) for i in range(24)]
        d.negative_grants(base,Path('/private/synthetic'),{},lambda _: '0',bridge)
        vectors=[call.args[0] for call in runner.call_args_list]
        self.assertEqual([x[-1] for x in vectors],['negative_identity','negative_scope','negative_expired','negative_signature'])
        self.assertEqual([x[9] for x in vectors[:3]],['/private/synthetic/negative_scope.json','/private/synthetic/negative_hash.json','/private/synthetic/negative_time.json'])
        self.assertEqual(vectors[3][7],base[8]); self.assertEqual(vectors[3][9],base[9])
        with self.assertRaisesRegex(AssertionError,'created session'):
            d.negative_grants(base,Path('/private/synthetic'),{},lambda _: '1',bridge)

    def test_unknown_marker_has_barrier_and_no_retry(self):
        from types import SimpleNamespace
        calls=[]
        def execute(sql):
            calls.append(sql)
            if 'has_sequence_privilege' in sql: return 't'
            if 'is_called::text' in sql: return 'true|1'
            if 'pg_stat_activity' in sql: return '0'
            if 'SELECT count(*) FROM contour.causal_marker_bindings' in sql: return '1'
            return ''
        runner=mock.Mock(return_value=SimpleNamespace(returncode=0,stderr=b'',stdout=b'MARKER_OUTCOME_UNKNOWN\n'))
        bridge={'IDS':['tenant','runtime'],'run_process':runner}
        self.assertEqual(d.marker_unknown(['probe']*24,{},execute,bridge),1)
        self.assertEqual(runner.call_count,1)
        self.assertEqual(runner.call_args.args[0][-1],'marker_unknown')
        with self.assertRaisesRegex(AssertionError,'never entered'):
            d.marker_unknown(['probe']*24,{},lambda sql:'t' if 'has_sequence_privilege' in sql else ('false|1' if 'is_called' in sql else ''),bridge)
        self.assertEqual(runner.call_count,2)

    def test_probe_uses_borrowed_view_and_candidate_scope(self):
        src=d.EXAMPLE.read_text()
        for item in ('wire_profile_503()', 'candidate view mismatch', 'invalidated view', '000000000003', 'CONFLICT_INVALIDATED'):
            self.assertIn(item,src)

if __name__=='__main__': unittest.main()
