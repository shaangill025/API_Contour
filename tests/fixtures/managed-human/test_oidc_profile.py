import unittest
from pathlib import Path
import tempfile
from deploy.local import check_oidc, origin21_profile


class OidcProfileTest(unittest.TestCase):
    def test_only_exact_human_context_selects_new_provider(self):
        state, origin, issuer, client, callback = check_oidc._settings(origin21_profile.HUMAN)
        self.assertEqual(state, origin21_profile.HUMAN.profile.state.parent)
        self.assertEqual(origin, 'https://idp.mvp.localhost:18444')
        self.assertEqual(issuer, origin + '/realms/apicontour-mvp')
        self.assertEqual(client, 'apicontour-mvp')
        self.assertEqual(callback, 'https://mvp.localhost:19443/auth/callback')
        self.assertEqual(check_oidc._settings(None), (check_oidc.STATE, check_oidc.ORIGIN, check_oidc.ISSUER, check_oidc.CLIENT, check_oidc.CALLBACK))
        with self.assertRaises(ValueError):
            check_oidc._settings(origin21_profile.HUMAN._replace())

    def test_private_approval_is_exclusive_and_detects_drift(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'approved.json'
            check_oidc._private_approved(path, {'issuer': 'fixed'})
            check_oidc._private_approved(path, {'issuer': 'fixed'})
            with self.assertRaises(ValueError):
                check_oidc._private_approved(path, {'issuer': 'other'})
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_optimized_python_refuses_before_any_build_network_or_secret_io(self):
        import subprocess, sys
        code = '''from unittest.mock import patch
from deploy.local import check_oidc, origin21_profile
with patch.object(check_oidc.subprocess, "run", side_effect=AssertionError("build called")), patch.object(check_oidc.tempfile, "TemporaryDirectory", side_effect=AssertionError("state touched")), patch.object(check_oidc.ssl, "create_default_context", side_effect=AssertionError("TLS touched")):
    try: check_oidc.main(selected=origin21_profile.HUMAN)
    except RuntimeError: pass
    else: raise AssertionError("optimized HUMAN was accepted")
'''
        result=subprocess.run([sys.executable,'-O','-c',code],cwd=check_oidc.ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_human_artifact_requires_exact_package_source_and_fresh_target(self):
        import json, os, subprocess
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder).resolve(); exe=target/'debug'/'examples'/'verify_local'; exe.parent.mkdir(parents=True); exe.write_bytes(b'test-artifact'); exe.chmod(0o700)
            source=check_oidc.ROOT/'crates/contour-auth/examples/verify_local.rs'
            package={'name':'contour-auth','id':'fixed-package','manifest_path':str(check_oidc.ROOT/'crates/contour-auth/Cargo.toml'),
                     'targets':[{'name':'verify_local','kind':['example'],'src_path':str(source)}]}
            metadata=json.dumps({'packages':[package]})
            artifact={'reason':'compiler-artifact','package_id':'fixed-package','target':{'name':'verify_local','kind':['example'],'src_path':str(source)},'executable':str(exe),'fresh':False}
            def run_artifact(record):
                results=[subprocess.CompletedProcess([],0,stdout=metadata),subprocess.CompletedProcess([],0,stdout=json.dumps(record)+'\n')]
                with patch.object(check_oidc.subprocess,'run',side_effect=results):
                    return check_oidc._build_human_verifier(target)
            record=run_artifact(artifact)
            self.assertEqual(check_oidc._check_human_verifier(record),exe)
            for change in ({'package_id':'wrong'}, {'fresh':True}, {'executable':'/tmp/unowned'},
                           {'target':{'name':'verify_local','kind':['example'],'src_path':'/tmp/wrong.rs'}}):
                with self.subTest(change=change), self.assertRaises(ValueError): run_artifact(dict(artifact,**change))
            exe.write_bytes(b'changed-artifact')
            with self.assertRaises(ValueError): check_oidc._check_human_verifier(record)

    def test_verifier_rejects_noncanonical_target_before_build(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder).resolve()
            link = target / 'alias'
            link.symlink_to(target, target_is_directory=True)
            with patch.object(check_oidc.subprocess, 'run') as build:
                for candidate in (link, target / '..' / target.name):
                    with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                        check_oidc._build_human_verifier(candidate)
                build.assert_not_called()

    def test_main_passes_resolved_private_target_to_runner(self):
        from unittest.mock import MagicMock, patch
        from deploy.pilot import origin_credentials
        folder = '/private/example/alias'
        resolved = Path('/private/example/canonical')
        path = MagicMock()
        path.resolve.return_value = resolved
        with patch.object(origin_credentials, '_dir') as directory, \
             patch.object(check_oidc.tempfile, 'TemporaryDirectory') as temporary, \
             patch.object(check_oidc, 'Path', return_value=path) as path_factory, \
             patch.object(check_oidc, '_run', return_value='result') as run:
            temporary.return_value.__enter__.return_value = folder
            self.assertEqual(check_oidc.main(selected=origin21_profile.HUMAN), 'result')
        state = origin21_profile.HUMAN.profile.state.parent
        directory.assert_called_once_with(state)
        temporary.assert_called_once_with(prefix='oidc-target-', dir=state)
        path_factory.assert_called_once_with(folder)
        path.resolve.assert_called_once_with()
        run.assert_called_once_with(origin21_profile.HUMAN, resolved)
