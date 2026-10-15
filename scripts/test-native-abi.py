"""Compile a real C caller; verify structural corpus and bounded ABI failures."""
import hashlib
import json
from pathlib import Path
import platform
import re
import runpy
import shutil
import subprocess
import tempfile
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]


def command(argv, data=None, timeout=30):
    result = subprocess.run(argv, cwd=ROOT, input=data, capture_output=True, timeout=timeout)
    if result.returncode:
        if re.fullmatch(rb"ABI boundary assertion failed at line [0-9]+\n", result.stderr):
            raise AssertionError(result.stderr.decode().strip())
        raise AssertionError("native ABI fixture command failed: " + argv[0])
    return result.stdout


def main():
    runpy.run_path(str(ROOT / "scripts/test-declared-model.py"))["main"]()
    started = datetime.now(timezone.utc).isoformat()
    if not shutil.which("cc") or not shutil.which("cargo"):
        raise RuntimeError("native ABI fixture requires cc and cargo")
    command(["cargo", "build", "-p", "contour-abi", "--locked", "--offline"], timeout=180)
    metadata = json.loads(command(["cargo", "metadata", "--format-version", "1", "--no-deps", "--offline"]))
    library = Path(metadata["target_directory"]) / "debug"
    with tempfile.TemporaryDirectory(prefix="contour-native-abi-") as folder:
        probe = str(Path(folder) / "probe")
        command(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror",
                 "-I", str(ROOT / "crates/contour-abi/include"),
                 str(ROOT / "crates/contour-abi/tests/probe.c"),
                 "-L", str(library), "-lcontour_abi", "-Wl,-rpath," + str(library), "-o", probe])
        assert command([probe, "--boundaries"]) == b"C ABI pointer, capacity and guard checks passed\n"
        vectors = json.loads((ROOT / "docs/specification/fixtures/canonical.json").read_text())

        def check(raw, expected=None):
            output = command([probe], raw, timeout=5)
            if expected is None:
                assert output == b"2\n", "invalid structure accepted through C ABI"
                return
            canonical = expected.encode()
            digest = hashlib.sha256(b"apicontour/structure/1\n" + canonical).hexdigest().encode()
            assert output == b"0\n" + digest + b"\n" + canonical, "C ABI canonical or fingerprint mismatch"

        for vector in vectors:
            check(json.dumps(vector["node"], ensure_ascii=False).encode(), vector["canonical"])
        check(b'{"kind":"object","fields":{"\\u0000":{"kind":"string"}},"additional":null}',
              '["object",[["\\u0000",["string"]]],null]')
        valid = b'{"kind":"string"}'
        check(valid + b" " * (65536 - len(valid)), '["string"]')
        invalid = [b"", b"{", b"null", b"\xff", valid + b"x",
                   b'{"kind":"string","value":"SYNTHETIC_SECRET"}',
                   b'{"kind":"string","kind":"string"}',
                   b'{"kind":"object","fields":{"a":{"kind":"string"},"a":{"kind":"integer"}},"additional":null}',
                   valid + b" " * (65537 - len(valid))]
        for raw in invalid:
            check(raw)
        for count in [64, 65]:
            name = "n" * count
            raw = json.dumps({"kind": "object", "fields": {name: {"kind": "string"}}, "additional": None}).encode()
            expected = '["object",[["' + name + '",["string"]]],null]' if count == 64 else None
            check(raw, expected)
        for depth in [32, 33]:
            node = {"kind": "string"}
            canonical = '["string"]'
            for _ in range(depth - 1):
                node = {"kind": "array", "items": node}
                canonical = '["array",' + canonical + ']'
            check(json.dumps(node).encode(), canonical if depth == 32 else None)
        for count in [256, 257]:
            fields = {"f%03d" % i: {"kind": "string"} for i in range(count)}
            node = {"kind": "object", "fields": fields, "additional": None}
            expected = json.dumps(["object", [[key, ["string"]] for key in sorted(fields)], None], separators=(',', ':'))
            check(json.dumps(node).encode(), expected if count == 256 else None)
        executable_hash = hashlib.sha256(Path(probe).read_bytes()).hexdigest()
    dynamic = library / ("libcontour_abi.dylib" if platform.system() == "Darwin" else "libcontour_abi.so")
    print("Actual C ABI: %d shared vectors, independent SHA256, native buffer guards and structural boundaries passed" % len(vectors))
    print("WASM execution and collector authorization are not verified by this fixture")
    print(json.dumps({
        "case": "AT-P01-01/native-only", "result": "PASS", "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": command(["git", "rev-parse", "HEAD"]).decode().strip(),
        "working_tree_clean": not bool(command(["git", "status", "--porcelain", "--untracked-files=normal"])),
        "platform": platform.platform(), "rust": command(["rustc", "--version"]).decode().strip(),
        "cc": command(["cc", "--version"]).decode().splitlines()[0],
        "policy_hash": None, "authority": "not exercised by structural ABI",
        "corpus_sha256": hashlib.sha256((ROOT / "docs/specification/fixtures/canonical.json").read_bytes()).hexdigest(),
        "library_sha256": hashlib.sha256(dynamic.read_bytes()).hexdigest(),
        "c_executable_sha256": executable_hash,
    }, sort_keys=True))


if __name__ == "__main__":
    main()
