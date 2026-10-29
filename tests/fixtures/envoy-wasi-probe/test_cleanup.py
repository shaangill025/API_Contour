"""Exercise cleanup failure after a successful synthetic probe without Docker."""
import sys
sys.dont_write_bytecode = True
import contextlib
import importlib.util
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("probe", ROOT / "scripts/test-envoy-wasi-probe.py")
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)

class Stream:
    def __enter__(self): return self
    def __exit__(self, *args): pass
    def sendall(self, data): pass

class Response:
    status = 200
    def __init__(self, sock): pass
    def begin(self): pass
    def read(self, limit): return b"wasi-probe-ok"

class Context:
    verify_flags = 0
    def wrap_socket(self, *args, **kwargs): return Stream()

class CleanupTest(unittest.TestCase):
    def test_failed_remove_cannot_report_pass(self):
        def docker_shim(*args, **kwargs):
            argv = args[0]
            self.assertEqual(argv[:3], ["docker", "rm", "-f"])
            return subprocess.CompletedProcess(argv, 1)
        def command(*args, **kwargs):
            output = b"true" if "{{.State.Running}}" in args else b"none"
            if "port" in args: output = b"127.0.0.1:12345"
            return subprocess.CompletedProcess(args, 0, stdout=output)
        output = io.StringIO()
        with patch.object(probe.os, "getuid", return_value=1234), \
             patch.object(probe.os, "getgid", return_value=1234), \
             patch.object(probe, "cmd", side_effect=command), \
             patch.object(probe.fixture, "certs"), \
             patch.object(probe.fixture, "network_profile", return_value=("127.0.0.1", "127.0.0.1", 12345, [])), \
             patch.object(probe.socket, "create_connection", return_value=Stream()), \
             patch.object(probe.ssl, "create_default_context", return_value=Context()), \
             patch.object(probe.fixture.http.client, "HTTPResponse", Response), \
             patch.object(probe.subprocess, "run", side_effect=docker_shim), \
             contextlib.redirect_stdout(output):
            with self.assertRaises(RuntimeError):
                probe.main()
        self.assertNotIn("PASS", output.getvalue())

if __name__ == "__main__": unittest.main()
