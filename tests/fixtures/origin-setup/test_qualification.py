"""Offline checks for fixture pinning, failures and owned cleanup selection."""
import importlib.util
from pathlib import Path
import subprocess
import unittest
import sys
from unittest import mock

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT))
from deploy.local import capture_profiles
spec=importlib.util.spec_from_file_location('origin_setup_qualification',ROOT/'scripts/test-origin-pilot-setup.py')
qualification=importlib.util.module_from_spec(spec); spec.loader.exec_module(qualification)


class Qualification(unittest.TestCase):
    def test_missing_image_pulls_exact_pinned_digest_only(self):
        missing=subprocess.CompletedProcess([],1,stdout=b'',stderr=b'No such image')
        present=subprocess.CompletedProcess([],0,stdout=b'',stderr=b'')
        with mock.patch.object(qualification.subprocess,'run',side_effect=[missing,present,present]) as run:
            qualification.ensure_image()
        self.assertEqual(run.call_args_list[1].args[0],['docker','pull',qualification.IMAGE])
        self.assertEqual(run.call_args_list[2].args[0],['docker','image','inspect',qualification.IMAGE])

    def test_docker_daemon_failure_does_not_trigger_pull(self):
        failure=subprocess.CompletedProcess([],1,stdout=b'',stderr=b'Cannot connect to daemon')
        with mock.patch.object(qualification.subprocess,'run',return_value=failure) as run:
            with self.assertRaises(RuntimeError): qualification.ensure_image()
            self.assertEqual(run.call_count,1)

    def test_command_failure_does_not_expose_process_output(self):
        result=subprocess.CompletedProcess([],1,stdout='sensitive fixture',stderr='sensitive fixture')
        with mock.patch.object(qualification.subprocess,'run',return_value=result):
            with self.assertRaises(RuntimeError) as error: qualification.command(['fixture'])
        self.assertNotIn('sensitive fixture',str(error.exception))

    def test_cleanup_discovery_requires_exact_owner_label_and_id(self):
        container='a'*64
        good=subprocess.CompletedProcess([],0,stdout=container+' owner\n',stderr='')
        foreign=subprocess.CompletedProcess([],0,stdout=container+' stranger\n',stderr='')
        invalid=subprocess.CompletedProcess([],0,stdout='invalid owner\n',stderr='')
        missing=subprocess.CompletedProcess([],1,stdout='',stderr='')
        with mock.patch.object(qualification.subprocess,'run',side_effect=[good,foreign,invalid,missing]):
            self.assertEqual(qualification.find_owned('name','owner'),container)
            self.assertIsNone(qualification.find_owned('name','owner'))
            self.assertIsNone(qualification.find_owned('name','owner'))
            self.assertIsNone(qualification.find_owned('name','owner'))

    def test_synthetic_profile_rebases_every_owned_path(self):
        root=Path('/tmp/fixed-fixture-state')
        original=capture_profiles.ORIGIN_PILOT
        result=qualification.synthetic_profile(root,original)
        self.assertEqual(result.state,root)
        self.assertEqual(result.capture.capture,root/'capture')
        self.assertEqual([slot.leaf_der for slot in result.origins],
                         [root/'replica1/client.crt.der',root/'replica2/client.crt.der'])
        self.assertEqual(result.capture.collector,original.capture.collector)
        self.assertEqual([slot.lifecycle for slot in result.origins],[slot.lifecycle for slot in original.origins])
        self.assertNotEqual(original.state,root)

    def test_arguments_never_select_a_partial_run(self):
        with mock.patch.object(qualification.sys,'argv',['test-origin-pilot-setup.py','--setup']), \
             mock.patch.object(qualification,'ensure_image') as image:
            with self.assertRaises(ValueError): qualification.main()
            image.assert_not_called()

    def test_failure_diagnostic_uses_only_fixed_types_phases_and_owned_frames(self):
        known=str(ROOT/'deploy/pilot/origin_credentials.py')
        try:
            exec(compile('raise ValueError("private-secret /private/user/key SQL payload")',known,'exec'),{})
        except ValueError as error:
            line=qualification.failure_line(error,'credentials','primary')
        self.assertEqual(line,'origin-setup-failure phase=credentials role=primary type=ValueError '
                              'location=deploy/pilot/origin_credentials.py:1')
        self.assertNotIn('private',line)
        try:
            exec(compile('raise RuntimeError("secret")','/outside/deploy/pilot/origin_credentials.py','exec'),{})
        except RuntimeError as error:
            self.assertTrue(qualification.failure_line(error,'setup','primary').endswith('location=unavailable'))
            self.assertIsNone(qualification.failure_line(error,'secret-phase','primary'))
            self.assertIsNone(qualification.failure_line(error,'setup','private-role'))
        class SecretType(Exception): pass
        self.assertIn('type=OtherError',qualification.failure_line(SecretType('secret'),'setup','cleanup'))
        oversized='x'*2100+'.py'
        try:
            exec(compile('raise ValueError("secret")',str(ROOT/oversized),'exec'),{})
        except ValueError as error:
            with mock.patch.object(qualification,'_FRAMES',{oversized}):
                self.assertIsNone(qualification.failure_line(error,'setup','primary'))

    def test_failure_diagnostic_limits_frames_and_keeps_primary_and_cleanup(self):
        path=str(ROOT/'deploy/pilot/origin_credentials.py')
        code=compile('def f(n):\n if n: return f(n-1)\n raise ValueError("secret")\nf(20)',path,'exec')
        try: exec(code,{})
        except ValueError as primary:
            line=qualification.failure_line(primary,'credentials','primary')
            self.assertEqual(line.count('deploy/pilot/origin_credentials.py:'),6)
            self.assertLessEqual(len(line.encode()),2048)
            cleanup=RuntimeError('cleanup secret')
            with mock.patch.object(qualification,'_FAILURES',[(primary,'credentials','primary')]), \
                 mock.patch.object(qualification,'_PHASE','cleanup'):
                lines=qualification.failure_lines(cleanup)
            self.assertEqual(len(lines),2)
            self.assertIn('role=primary',lines[0]); self.assertIn('role=cleanup',lines[1])
            self.assertNotIn('secret',' '.join(lines))

    def test_invalid_arguments_still_fail_without_secret_output(self):
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/test-origin-pilot-setup.py'),'secret-argument'],
                              capture_output=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'origin-setup-failure phase=arguments role=primary type=ValueError',result.stderr)
        self.assertNotIn(b'secret-argument',result.stderr)
        self.assertIn(b'Synthetic internal origin setup qualification failed',result.stderr)


if __name__=='__main__': unittest.main()
