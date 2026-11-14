import socket
import unittest
from unittest.mock import patch

from deploy.local import origin21_managed_human_preflight as preflight


class PreflightTest(unittest.TestCase):
    def test_only_fixed_names_and_loopback_answers(self):
        calls = []
        def resolver(host, port, **kwargs):
            calls.append((host, port))
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', port)),
                    (socket.AF_INET6, socket.SOCK_STREAM, 6, '', ('::1', port, 0, 0))]
        with patch.object(preflight.socket, 'getaddrinfo', side_effect=resolver), patch.object(preflight, '_check_port') as check:
            preflight.check()
        self.assertEqual(calls, [('mvp.localhost', 19443), ('idp.mvp.localhost', 18444)])
        self.assertEqual([c.args for c in check.call_args_list], [(19443,), (18444,)])

    def test_nonloopback_or_no_answers_rejected(self):
        for answers in ([], [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('192.0.2.1', 19443))]):
            with self.subTest(answers=answers), patch.object(preflight.socket, 'getaddrinfo', return_value=answers), patch.object(preflight, '_check_port'):
                with self.assertRaises(ValueError):
                    preflight.check()

    def test_check_port_binds_only_ipv4_loopback_and_closes(self):
        with patch.object(preflight.socket, 'socket') as factory:
            preflight._check_port(19443)
        factory.assert_called_once_with(socket.AF_INET, socket.SOCK_STREAM)
        probe = factory.return_value.__enter__.return_value
        probe.bind.assert_called_once_with(('127.0.0.1', 19443))
        factory.return_value.__exit__.assert_called_once()

    def test_port_error_is_not_ignored(self):
        answer = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('127.0.0.1', 19443))]
        with patch.object(preflight.socket, 'getaddrinfo', return_value=answer), patch.object(preflight, '_check_port', side_effect=OSError('busy')):
            with self.assertRaises(OSError):
                preflight.check()
