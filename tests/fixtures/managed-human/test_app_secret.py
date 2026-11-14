import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from deploy.local import origin21_managed_human_secret as secret


class AppSecretTest(unittest.TestCase):
    def test_secret_persisted_and_committed_before_sql_can_be_built(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            with patch.object(secret, '_base', return_value=base), patch.object(secret.secrets, 'token_hex', return_value='a'*64):
                value = secret.create_fresh()
                self.assertEqual(value, 'a'*64)
                self.assertEqual((base/'database-password').read_text(), value)
                self.assertEqual(json.loads((base/'app-credential.intent').read_text()),
                                 {'version': 1, 'sha256': hashlib.sha256(value.encode()).hexdigest()})
                self.assertEqual(os.stat(base/'database-password').st_mode & 0o777, 0o600)
                self.assertEqual(secret.read_committed(), value)
                (base/'database-password').write_text('b'*64)
                with self.assertRaises(ValueError):
                    secret.read_committed()
                with self.assertRaises(FileExistsError):
                    secret.create_fresh()

    def test_unknown_partial_state_is_never_replaced(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            (base/'database-password').write_text('existing')
            with patch.object(secret, '_base', return_value=base):
                with self.assertRaises(FileExistsError):
                    secret.create_fresh()
            self.assertEqual((base/'database-password').read_text(), 'existing')
            self.assertFalse((base/'app-credential.intent').exists())
