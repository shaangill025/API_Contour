#!/usr/bin/env python3
"""Synthetic, local-only WASI availability probe in the pinned Envoy image."""
import sys
sys.dont_write_bytecode = True
import importlib.util
import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, ROOT / path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

gateway = load("gateway_config", "deploy/gateway/config.py")
fixture = load("gateway_fixture", "scripts/test-managed-gateway.py")
cmd = fixture.cmd
WASM = ROOT / "target/envoy-wasi-probe/wasm32-unknown-unknown/release/envoy_wasi_probe.wasm"

def main():
    if os.getuid() == 0:
        raise RuntimeError("run as a nonroot user")
    manifest = str(ROOT / "tests/fixtures/envoy-wasi-probe/Cargo.toml")
    cmd("cargo", "fmt", "--manifest-path", manifest, "--", "--check")
    cmd("cargo", "build", "--manifest-path", manifest, "--target", "wasm32-unknown-unknown", "--release", "--locked", "--offline", "--target-dir", str(ROOT / "target/envoy-wasi-probe"))
    cmd("docker", "image", "inspect", gateway.IMAGE)
    name = "contour-wasi-probe-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix="contour-wasi-probe-") as directory:
        p = Path(directory)
        fixture.certs(p)
        _, address, port, networking = fixture.network_profile(sys.platform)
        cfg = gateway.config("127.0.0.1", 12345, listen_address=address, listen_port=port)
        cfg["static_resources"]["clusters"] = []
        hcm = cfg["static_resources"]["listeners"][0]["filter_chains"][0]["filters"][0]["typed_config"]
        hcm["route_config"]["virtual_hosts"][0]["routes"] = [{"match": {"prefix": "/"}, "direct_response": {"status": 503}}]
        hcm["http_filters"].insert(0, {"name": "envoy.filters.http.wasm", "typed_config": {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.wasm.v3.Wasm",
            "config": {"name": "wasi_probe", "root_id": "probe", "vm_config": {"vm_id": "probe", "runtime": "envoy.wasm.runtime.v8", "code": {"local": {"filename": "/fixture/probe.wasm"}}}}}})
        config = p / "envoy.json"
        config.write_text(json.dumps(cfg))
        os.chmod(config, 0o600)
        mounts = []
        for source, dest in ((config, "envoy.json"), (p / "down.pem", "down.pem"), (p / "down.key", "down.key"), (WASM, "probe.wasm")):
            mounts += ["-v", str(source) + ":/fixture/" + dest + ":ro"]
        try:
            cmd("docker", "run", "--pull", "never", "-d", "--name", name, "--user", f"{os.getuid()}:{os.getgid()}", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "256m", "--cpus", "1", "--pids-limit", "128", "--log-driver", "none", *networking, *mounts, gateway.IMAGE, "envoy", "-c", "/fixture/envoy.json", "--log-level", "off", "--concurrency", "1")
            if sys.platform == "darwin":
                port = int(cmd("docker", "port", name, "8443/tcp").stdout.decode().strip().rsplit(":", 1)[1])
            context = ssl.create_default_context(cafile=str(p / "ca.pem"))
            context.verify_flags |= ssl.VERIFY_X509_STRICT
            deadline = time.monotonic() + 15
            while True:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                        with context.wrap_socket(raw, server_hostname="gateway.test") as tls:
                            tls.sendall(b"GET / HTTP/1.1\r\nHost: gateway.test\r\nConnection: close\r\n\r\n")
                            response = fixture.http.client.HTTPResponse(tls)
                            response.begin()
                            body = response.read(1024)
                            assert response.status == 200 and body == b"wasi-probe-ok", (response.status, body)
                    break
                except (ConnectionError, OSError):
                    if time.monotonic() >= deadline:
                        state = json.loads(cmd("docker", "inspect", "--format", "{{json .State}}", name).stdout)
                        raise RuntimeError(f"Envoy probe unavailable: running={state['Running']} exit={state['ExitCode']} oom={state['OOMKilled']}") from None
                    time.sleep(.1)
            assert cmd("docker", "inspect", "--format", "{{.State.Running}}", name).stdout.strip() == b"true"
            assert cmd("docker", "inspect", "--format", "{{.HostConfig.LogConfig.Type}}", name).stdout.strip() == b"none"
        finally:
            original = sys.exception()
            try:
                result = subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
                if result.returncode:
                    raise RuntimeError("Docker probe container cleanup failed")
            except (OSError, subprocess.TimeoutExpired, RuntimeError) as error:
                if original is None:
                    raise RuntimeError("Docker probe container cleanup failed") from error
                original.add_note("Docker probe container cleanup also failed; inspect container " + name)
        print("PASS pinned Envoy: realtime and advancing monotonic clocks, two distinct successful random calls")

if __name__ == "__main__":
    main()
