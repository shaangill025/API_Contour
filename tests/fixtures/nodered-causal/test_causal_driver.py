"""Offline failure-path tests for the owned qualification driver."""
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

PATH = Path(__file__).resolve().parents[3] / 'scripts/test-nodered-causal.py'
spec = importlib.util.spec_from_file_location('causal_driver', PATH)
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)


class DriverTests(unittest.TestCase):
    def test_timeout_still_removes_exact_owned_container(self):
        ok = subprocess.CompletedProcess([], 0, stdout=b'')
        owned = subprocess.CompletedProcess([], 0, stdout=(('a'*64)+' abc123\n').encode())
        with mock.patch.object(driver.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('docker', 1), owned, ok, ok, ok]) as run:
            with self.assertRaises(subprocess.TimeoutExpired):
                driver.container('offline', 'abc123', [], [], timeout=1)
        name = 'contour-causal-abc123-offline'
        self.assertEqual(run.call_args_list[2].args[0], ['docker','rm','-f','a'*64])
        self.assertEqual(run.call_args_list[1].args[0][-1], name)

    def test_cleanup_failure_is_failure(self):
        ok = subprocess.CompletedProcess([], 0, stdout=b'')
        bad = subprocess.CompletedProcess([], 1, stdout=b'error')
        owned = subprocess.CompletedProcess([], 0, stdout=(('a'*64)+' abc123\n').encode())
        with mock.patch.object(driver.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('docker', 1), owned, bad, ok, ok]):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                driver.container('offline', 'abc123', [], [], timeout=1)

    def test_foreign_container_never_removed(self):
        foreign = subprocess.CompletedProcess([], 0, stdout=(('b'*64)+' other-owner\n').encode())
        present = subprocess.CompletedProcess([], 0, stdout=b'foreign-id\n')
        with mock.patch.object(driver.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('docker', 1), foreign, present]) as run:
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                driver.container('offline', 'abc123', [], [], timeout=1)
        self.assertFalse(any(call.args[0][:2] == ['docker','rm'] for call in run.call_args_list))

    def test_unremoved_owned_id_prevents_pass(self):
        owned_id = 'a' * 64
        owned = subprocess.CompletedProcess([], 0, stdout=(owned_id+' abc123\n').encode())
        ok = subprocess.CompletedProcess([], 0, stdout=b'')
        still_present = subprocess.CompletedProcess([], 0, stdout=(owned_id+'\n').encode())
        with mock.patch.object(driver.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('docker',1), owned, ok, still_present, ok]):
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                driver.container('offline','abc123',[],[],timeout=1)

    def test_failed_case_removes_private_temporary_files(self):
        with tempfile.TemporaryDirectory() as outer:
            directory = Path(outer)/'owned'; directory.mkdir()
            (directory/'secret').write_text('synthetic')
            ok = subprocess.CompletedProcess([], 0, stdout=b'')
            with mock.patch.object(driver, 'snapshot', return_value={'source':'same'}), \
                 mock.patch.object(driver.tempfile, 'mkdtemp', return_value=str(directory)), \
                 mock.patch.object(driver.subprocess, 'run', return_value=ok), \
                 mock.patch.object(driver, 'container', side_effect=RuntimeError('case failed')):
                with self.assertRaisesRegex(RuntimeError, 'case failed'):
                    driver.qualify()
            self.assertFalse(directory.exists())

    def test_missing_image_pulls_exact_pin_and_runs_every_case(self):
        with tempfile.TemporaryDirectory() as outer:
            directory = Path(outer)/'owned'; directory.mkdir()
            missing = subprocess.CompletedProcess([], 1, stdout=b'Error: No such image: fixture')
            def make_certs(folder):
                for name in ('ca','unrelated-ca','server','server-key','wrong-name','wrong-name-key'):
                    (folder/name).write_text('synthetic')
            with mock.patch.object(driver, 'snapshot', return_value={'x':'same'}), \
                 mock.patch.object(driver.tempfile, 'mkdtemp', return_value=str(directory)), \
                 mock.patch.object(driver.subprocess, 'run', return_value=missing), \
                 mock.patch.object(driver, 'command') as command, \
                 mock.patch.object(driver, 'certificates', side_effect=make_certs), \
                 mock.patch.object(driver, 'container') as container:
                with contextlib.redirect_stdout(io.StringIO()):
                    driver.qualify()
            self.assertEqual(command.call_args_list[0].args[0], ['docker','pull',driver.IMAGE])
            self.assertEqual([call.args[0] for call in container.call_args_list],
                             ['offline','http-regression','https','wrong-ca','wrong-name'])
            self.assertFalse(directory.exists())

    def test_daemon_failure_never_pulls(self):
        with tempfile.TemporaryDirectory() as outer:
            directory = Path(outer)/'owned'; directory.mkdir()
            denied = subprocess.CompletedProcess([], 1, stdout=b'permission denied connecting to docker daemon')
            with mock.patch.object(driver, 'snapshot', return_value={'x':'same'}), \
                 mock.patch.object(driver.tempfile, 'mkdtemp', return_value=str(directory)), \
                 mock.patch.object(driver.subprocess, 'run', return_value=denied), \
                 mock.patch.object(driver, 'command') as command:
                with self.assertRaisesRegex(RuntimeError, 'image inspection failed'):
                    driver.qualify()
            command.assert_not_called()
            self.assertFalse(directory.exists())

    def test_replaced_name_never_removes_foreign_container(self):
        owned_id = 'a' * 64
        own = subprocess.CompletedProcess([], 0, stdout=(owned_id+' abc123\n').encode())
        ok = subprocess.CompletedProcess([], 0, stdout=b'')
        foreign = subprocess.CompletedProcess([], 0, stdout=b'b'*64+b'\n')
        with mock.patch.object(driver.subprocess, 'run', side_effect=[subprocess.TimeoutExpired('docker',1), own, ok, ok, foreign]) as run:
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                driver.container('offline','abc123',[],[],timeout=1)
        self.assertEqual(run.call_args_list[2].args[0], ['docker','rm','-f',owned_id])
        self.assertFalse(any(call.args[0] == ['docker','rm','-f','b'*64] for call in run.call_args_list))

    def test_missing_normative_fixture_fails_before_any_process(self):
        with tempfile.TemporaryDirectory() as outer, \
             mock.patch.object(driver, 'ROOT', Path(outer)), \
             mock.patch.object(driver.subprocess, 'run') as run:
            with self.assertRaisesRegex(RuntimeError, 'normative causal fixture missing'):
                driver.qualify()
            run.assert_not_called()

    def test_symlinked_normative_parent_fails_before_process(self):
        parts = ('docs','specification','fixtures')
        for index in range(len(parts)):
            with self.subTest(ancestor=parts[index]), tempfile.TemporaryDirectory() as outer, tempfile.TemporaryDirectory() as external:
                root = Path(outer)
                link = root.joinpath(*parts[:index+1]); link.parent.mkdir(parents=True, exist_ok=True)
                fixture = Path(external).joinpath(*parts[index+1:])/'causal-events.json'
                fixture.parent.mkdir(parents=True, exist_ok=True); fixture.write_text('synthetic')
                link.symlink_to(external, target_is_directory=True)
                with mock.patch.object(driver, 'ROOT', root), \
                     mock.patch.object(driver.subprocess, 'run', side_effect=AssertionError('process ran')) as run:
                    with self.assertRaisesRegex(RuntimeError, 'symlink'):
                        driver.qualify()
                    run.assert_not_called()

    def test_normative_fixture_mutation_fails_complete_run(self):
        with tempfile.TemporaryDirectory() as outer:
            root = Path(outer)
            fixture = root/'docs/specification/fixtures/causal-events.json'
            fixture.parent.mkdir(parents=True); fixture.write_text('before')
            ok = subprocess.CompletedProcess([], 0, stdout=b'')
            def make_certs(folder):
                for name in ('ca','unrelated-ca','server','server-key','wrong-name','wrong-name-key'):
                    (folder/name).write_text('synthetic')
            def case(name, _run_id, mounts, _args, **_kwargs):
                if name == 'offline':
                    self.assertIn(str(fixture)+':/work/docs/specification/fixtures/causal-events.json:ro', mounts)
                    fixture.write_text('changed')
            with mock.patch.object(driver, 'ROOT', root), \
                 mock.patch.object(driver.subprocess, 'run', return_value=ok), \
                 mock.patch.object(driver, 'certificates', side_effect=make_certs), \
                 mock.patch.object(driver, 'container', side_effect=case):
                with contextlib.redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, 'source changed'):
                        driver.qualify()

    def test_changed_source_prevents_pass(self):
        with tempfile.TemporaryDirectory() as outer:
            directory = Path(outer)/'owned'; directory.mkdir()
            ok = subprocess.CompletedProcess([], 0, stdout=b'')
            with mock.patch.object(driver, 'snapshot', side_effect=[{'x':'before'},{'x':'after'}]), \
                 mock.patch.object(driver.tempfile, 'mkdtemp', return_value=str(directory)), \
                 mock.patch.object(driver.subprocess, 'run', return_value=ok), \
                 mock.patch.object(driver, 'container', side_effect=RuntimeError('case failed')):
                with self.assertRaisesRegex(RuntimeError, 'source changed'):
                    driver.qualify()
            self.assertFalse(directory.exists())


if __name__ == '__main__': unittest.main()
