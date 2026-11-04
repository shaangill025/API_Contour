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


if __name__=='__main__': unittest.main()
