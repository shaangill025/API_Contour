"""Actual C/WASM parity using only Node built-ins and the pinned Rust target."""
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import platform
import runpy
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
command = runpy.run_path(str(ROOT / "scripts/test-native-abi.py"))["command"]


def main():
    started = datetime.now(timezone.utc).isoformat()
    command(["cargo", "+1.88.0", "clippy", "-p", "contour-wasm", "--target", "wasm32-unknown-unknown", "--locked", "--offline", "--", "-D", "warnings"], timeout=180)
    command(["cargo", "+1.88.0", "build", "-p", "contour-wasm", "--target", "wasm32-unknown-unknown", "--locked", "--offline"], timeout=180)
    command(["cargo", "+1.88.0", "build", "-p", "contour-abi", "--locked", "--offline"], timeout=180)
    metadata = json.loads(command(["cargo", "+1.88.0", "metadata", "--format-version", "1", "--no-deps", "--offline"]))
    target = Path(metadata["target_directory"])
    library = target / "debug"
    wasm = target / "wasm32-unknown-unknown/debug/contour_wasm.wasm"
    cases = []

    def case(raw, canonical=None):
        cases.append({"input": base64.b64encode(raw).decode(), "canonical": canonical})

    vectors = ROOT / "docs/specification/fixtures/canonical.json"
    for vector in json.loads(vectors.read_text()):
        case(json.dumps(vector["node"], ensure_ascii=False).encode(), vector["canonical"])
    valid = b'{"kind":"string"}'
    case(valid + b" " * (65536 - len(valid)), '["string"]')
    for raw in [b"", b"{", b"null", b"\xff", valid + b"x",
                b'{"kind":"string","value":"SYNTHETIC_SECRET"}',
                b'{"kind":"string","kind":"string"}',
                b'{"kind":"object","fields":{"a":{"kind":"string"},"a":{"kind":"integer"}},"additional":null}',
                valid + b" " * (65537 - len(valid))]:
        case(raw)
    for name in ["\0", "n" * 64, "n" * 65, "é" * 64, "é" * 65]:
        node = {"kind": "object", "fields": {name: {"kind": "string"}}, "additional": None}
        expected = json.dumps(["object", [[name, ["string"]]], None], ensure_ascii=False, separators=(',', ':'))
        case(json.dumps(node, ensure_ascii=False).encode(), expected if len(name) <= 64 else None)
    for depth in [32, 33]:
        node = {"kind": "string"}
        canonical = '["string"]'
        for _ in range(depth - 1):
            node = {"kind": "array", "items": node}
            canonical = '["array",' + canonical + ']'
        case(json.dumps(node).encode(), canonical if depth == 32 else None)
    for count in [256, 257]:
        fields = {"f%03d" % i: {"kind": "string"} for i in range(count)}
        node = {"kind": "object", "fields": fields, "additional": None}
        expected = json.dumps(["object", [[key, ["string"]] for key in sorted(fields)], None], separators=(',', ':'))
        case(json.dumps(node).encode(), expected if count == 256 else None)
    # Bounded deterministic malformed corpus; never report inputs on failure.
    for byte in range(256):
        case(b'{"kind":' + bytes([byte]) + b'}')
    case(valid, '["string"]')  # Valid recovery after all rejected inputs.
    with tempfile.TemporaryDirectory(prefix="contour-wasm-parity-") as folder:
        probe = str(Path(folder) / "native")
        command(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "crates/contour-abi/include"),
                 str(ROOT / "crates/contour-abi/tests/probe.c"), "-L", str(library), "-lcontour_abi", "-Wl,-rpath," + str(library), "-o", probe])
        path = Path(folder) / "cases.json"
        path.write_text(json.dumps(cases, ensure_ascii=False))
        host = subprocess.run(["node", str(ROOT / "scripts/wasm-parity.mjs"), str(wasm), str(path)], capture_output=True, timeout=30)
        if host.returncode:
            if b"stale canonical length" in host.stderr:
                raise AssertionError("WASM stale canonical length assertion failed")
            raise AssertionError("WASM host parity assertion failed")
        result = json.loads(host.stdout)
        assert len(result["results"]) == len(cases)
        for item, encoded in zip(cases, result["results"]):
            raw = base64.b64decode(item["input"])
            actual = command([probe], raw, timeout=5)
            assert actual == base64.b64decode(encoded), "native/WASM output mismatch"
        native_hash = hashlib.sha256(Path(probe).read_bytes()).hexdigest()
    print("Actual C/WASM parity, independent SHA256, repeated-state boundaries and memory ceiling passed")
    print(json.dumps({"case": "AT-P01-01/C-WASM", "result": "PASS", "cases": len(cases),
        "rounds": result["rounds"], "node": result["node"], "memory_bytes": result["memory_bytes"],
        "started_at": started, "finished_at": datetime.now(timezone.utc).isoformat(),
        "source_revision": command(["git", "rev-parse", "HEAD"]).decode().strip(),
        "working_tree_clean": not bool(command(["git", "status", "--porcelain", "--untracked-files=normal"])),
        "platform": platform.platform(), "rust": command(["rustc", "+1.88.0", "--version"]).decode().strip(),
        "target": "wasm32-unknown-unknown", "authority": "not exercised by structural ABI",
        "corpus_sha256": hashlib.sha256(vectors.read_bytes()).hexdigest(),
        "wasm_sha256": hashlib.sha256(wasm.read_bytes()).hexdigest(), "native_executable_sha256": native_hash}, sort_keys=True))


if __name__ == "__main__":
    main()
