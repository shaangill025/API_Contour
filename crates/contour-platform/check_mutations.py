"""Focused regression sensitivity; restores every production file even on failure."""
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "crates/contour-platform"
CASES = [
    ("browser binding", "src/state.rs", "if login.binding != binding {", "if false && login.binding != binding {", "browser_binding_consumption_and_replay"),
    ("exact expiry", "src/state.rs", "login.expires > now", "login.expires >= now", "exact_expiry_boundary_and_session_logout"),
    ("origin", "src/wire.rs", '!= Some(ORIGIN)', '== Some("impossible-origin")', "exact_origin_json_and_host_required_before_mutations"),
    ("duplicate token", "src/wire.rs", "!keys.insert(key.clone())", "!keys.insert(key.clone()) && false", "token_response_does_not_accept_duplicate_selected_fields_or_oversized_token"),
    ("retained token clock", "src/state.rs", ".verify(&session.token, &session.nonce, unix_now)", ".verify(&session.token, &session.nonce, unix_now.min(1_800_000_000))", "retained_session_rechecks_real_signature_nonce_and_current_expiry"),
]


def main():
    env = dict(os.environ, AWS_LC_SYS_USE_SYSTEM="0")
    for name, relative, old, new, test in CASES:
        path = CRATE / relative
        source = path.read_bytes()
        assert source.count(old.encode()) == 1, name
        try:
            path.write_bytes(source.replace(old.encode(), new.encode()))
            result = subprocess.run(["cargo", "test", "-p", "contour-platform", "--locked", "--offline", test], cwd=ROOT, env=env, capture_output=True, timeout=120)
            output = result.stdout + result.stderr
            assert result.returncode != 0 and b"test result: FAILED" in output and test.encode() in output, name + " mutation did not produce intended test failure"
            print(name + ": intended RED")
        finally:
            path.write_bytes(source)
            assert path.read_bytes() == source
    subprocess.run(["cargo", "test", "-p", "contour-platform", "--locked", "--offline"], cwd=ROOT, env=env, check=True, timeout=120)
    print("Restored source: GREEN")


if __name__ == "__main__":
    main()
