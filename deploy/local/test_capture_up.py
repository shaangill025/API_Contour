"""Readiness regressions use fakes and never open a listener or invoke Docker."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest import mock

PATH=Path(__file__).with_name('capture_up.py')
spec=importlib.util.spec_from_file_location('capture_up',PATH)
up=importlib.util.module_from_spec(spec); spec.loader.exec_module(up)

class StartupReadiness(unittest.TestCase):
    def test_expiry_during_build_never_starts_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory); (state/'business.json').touch(); (state/'capture').mkdir()
            commands=[]
            with mock.patch.object(up,'STATE',state), mock.patch.object(up,'CAPTURE',state/'capture'), \
                 mock.patch.object(up.os,'getuid',return_value=1000), mock.patch.object(up.os,'getgid',return_value=1000), \
                 mock.patch.object(up,'run',side_effect=lambda command,timeout: commands.append(command)), \
                 mock.patch.object(up,'lease',side_effect=[{},RuntimeError('expired during build')]), \
                 mock.patch.object(up,'authority_ready') as ready:
                with self.assertRaisesRegex(RuntimeError,'expired during build'): up.main()
                ready.assert_not_called()
            self.assertTrue(any('build' in c for c in commands))
            self.assertFalse(any('up' in c for c in commands))

    def test_fresh_profile_build_precedes_credential_creation(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory); (state/'business.json').touch()
            commands=[]
            def run(command,timeout):
                commands.append(command)
                if 'capture_init.py' in command[-1]:
                    (state/'capture').mkdir()
            with mock.patch.object(up,'STATE',state), mock.patch.object(up,'CAPTURE',state/'capture'), \
                 mock.patch.object(up.os,'getuid',return_value=1000), mock.patch.object(up.os,'getgid',return_value=1000), \
                 mock.patch.object(up,'run',side_effect=run), mock.patch.object(up,'lease',return_value={}), \
                 mock.patch.object(up,'authority_ready'), mock.patch.object(up,'running',return_value=True), \
                 mock.patch('builtins.print'):
                up.main()
            build=next(i for i,c in enumerate(commands) if 'build' in c)
            init=next(i for i,c in enumerate(commands) if c[-1].endswith('capture_init.py'))
            provision=next(i for i,c in enumerate(commands) if c[-1].endswith('capture_provision.py'))
            self.assertLess(build,init)
            self.assertLess(init,provision)

    def test_existing_expired_profile_is_not_replaced_or_built(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory); (state/'business.json').touch(); (state/'capture').mkdir()
            with mock.patch.object(up,'STATE',state), mock.patch.object(up,'CAPTURE',state/'capture'), \
                 mock.patch.object(up.os,'getuid',return_value=1000), mock.patch.object(up.os,'getgid',return_value=1000), \
                 mock.patch.object(up,'run') as run, mock.patch.object(up,'lease',side_effect=RuntimeError('expired')):
                with self.assertRaisesRegex(RuntimeError,'expired'): up.main()
                run.assert_not_called()

    def test_running_container_with_refused_authority_never_ready(self):
        with tempfile.TemporaryDirectory() as directory:
            state=Path(directory); (state/'business.json').touch(); (state/'capture').mkdir()
            with mock.patch.object(up,'STATE',state), mock.patch.object(up,'CAPTURE',state/'capture'), \
                 mock.patch.object(up.os,'getuid',return_value=1000), mock.patch.object(up.os,'getgid',return_value=1000), \
                 mock.patch.object(up,'run'), mock.patch.object(up,'lease',return_value={}), \
                 mock.patch.object(up,'running',return_value=True), \
                 mock.patch.object(up,'authority_ready',side_effect=RuntimeError('not listening')), \
                 mock.patch('builtins.print') as printed:
                with self.assertRaisesRegex(RuntimeError,'not listening'): up.main()
                printed.assert_not_called()

    def test_trickled_headers_interrupt_whole_exchange_and_restore_timer(self):
        fake=mock.Mock()
        def stalled_headers():
            # Simulate the installed deadline signal while getresponse is parsing headers.
            up.signal.getsignal(up.signal.SIGALRM)(up.signal.SIGALRM, None)
        fake.getresponse.side_effect=stalled_headers
        original=up.signal.getsignal(up.signal.SIGALRM)
        with mock.patch.object(up.ssl,'create_default_context',return_value=mock.Mock()), \
             mock.patch.object(up.http.client,'HTTPSConnection',return_value=fake):
            with self.assertRaisesRegex(RuntimeError,'authority not ready'):
                up.authority_ready({},up.time.monotonic()+1)
        fake.close.assert_called_once()
        self.assertEqual(up.signal.getsignal(up.signal.SIGALRM),original)
        self.assertEqual(up.signal.getitimer(up.signal.ITIMER_REAL),(0.0,0.0))

    def test_connection_refusal_times_out_without_network(self):
        fake=mock.Mock(); fake.request.side_effect=ConnectionRefusedError()
        context=mock.Mock()
        with mock.patch.object(up.ssl,'create_default_context',return_value=context), \
             mock.patch.object(up.http.client,'HTTPSConnection',return_value=fake), \
             mock.patch.object(up.time,'monotonic',side_effect=[0,0,0,2,2]), \
             mock.patch.object(up.time,'sleep'):
            with self.assertRaisesRegex(RuntimeError,'authority not ready'): up.authority_ready({},1)
        fake.close.assert_called_once()

if __name__=='__main__': unittest.main()
