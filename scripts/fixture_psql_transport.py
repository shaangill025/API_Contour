"""Private fixture control transport: one fresh psql per request, per-thread shells."""
import base64
import json
import locale
import os
import re
import secrets
import selectors
import subprocess
import threading
import time

IMAGE = 'postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
LABEL = 'org.apicontour.fixture-owner'
LIMIT = 64 * 1024 * 1024
# SQL enters only as base64 data. psql's status is emitted separately from its
# base64-encoded stdout. timeout bounds the psql client, not the backend after
# parent SIGKILL. An outer owner must clean up the fixture on parent death.
SHELL = r'''while IFS=' ' read -r nonce seconds payload; do
  printf '%s' "$payload" | base64 -d | { timeout -k 1 "$seconds" psql -XAtq -v ON_ERROR_STOP=1 -U postgres -d contour_fixture; status=$?; printf '\n%s STATUS %s\n' "$nonce" "$status" >&2; } | base64
  printf '%s END\n' "$nonce"
done'''


class TransportError(RuntimeError):
    pass


class FreshPsqlTransport:
    def __init__(self, sql, environment, owner, *, popen=subprocess.Popen, run=subprocess.run):
        if (len(sql) != 12 or sql[:3] != ['docker', 'exec', '-i'] or
            not re.fullmatch('[0-9a-f]{64}', sql[3]) or
            sql[4:] != ['psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'contour_fixture']):
            raise ValueError('invalid fixture command')
        if not re.fullmatch('[0-9a-f]{32}', owner): raise ValueError('invalid fixture owner')
        self.container, self.owner, self.environment = sql[3], owner, environment
        self.popen, self.run = popen, run
        self.local = threading.local()
        self.lock = threading.Lock()
        self.workers = []
        self.owners = {}
        self.inflight = {}
        self.closed = False
        self.contained = False
        self.containment_error = False

    def _contain(self):
        with self.lock:
            if self.contained:
                if self.containment_error: raise TransportError('fixture containment previously failed')
                return
            self.contained = True
            try:
                result = self.run(['docker', 'inspect', self.container], capture_output=True, text=True, timeout=10, env=self.environment)
                infos = json.loads(result.stdout) if result.returncode == 0 else []
                if len(infos) != 1: raise TransportError('fixture containment ownership unavailable')
                obj = infos[0]; cfg = obj.get('Config') or {}; labels = cfg.get('Labels') or {}
                if (obj.get('Id') != self.container or cfg.get('Image') != IMAGE or
                    labels.get(LABEL) != self.owner or any(k.startswith('com.docker.compose.') for k in labels) or
                    'POSTGRES_DB=contour_fixture' not in (cfg.get('Env') or [])):
                    raise TransportError('fixture containment ownership mismatch')
                killed = self.run(['docker', 'kill', self.container], capture_output=True, timeout=10, env=self.environment)
                if killed.returncode: raise TransportError('fixture containment kill failed')
                state = self.run(['docker', 'inspect', '--format', '{{.State.Running}}', self.container], capture_output=True, text=True, timeout=10, env=self.environment)
                if state.returncode or state.stdout.strip() != 'false': raise TransportError('fixture containment verification failed')
            except TransportError:
                self.containment_error = True
                raise
            except Exception:
                self.containment_error = True
                raise TransportError('fixture containment unavailable') from None

    def _retire_idle(self, worker, deadline=None):
        # The caller holds the ownership lock and has established that the
        # request completed. A dead helper here is not an ambiguous query.
        try:
            worker.stdin.close()
            remaining = 5 if deadline is None else min(5, max(0, deadline-time.monotonic()))
            if remaining <= 0: raise TimeoutError('fixture query deadline')
            worker.wait(timeout=remaining)
        except Exception:
            if worker.poll() is None:
                worker.kill(); worker.wait(timeout=5)
            raise _IdleReapError('idle fixture helper could not be reaped') from None
        finally:
            worker.stdout.close(); worker.stderr.close()
        self.workers.remove(worker)
        del self.owners[worker]
        del self.inflight[worker]

    def _worker(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not self.lock.acquire(timeout=remaining):
            raise TimeoutError('fixture query deadline')
        held = True
        try:
            if self.closed or self.contained: raise TransportError('fixture transport closed')
            current = threading.current_thread()
            worker = getattr(self.local, 'worker', None)
            for candidate in list(self.workers):
                if not self.inflight[candidate].is_set() and (
                    not self.owners[candidate].is_alive() or
                    (candidate is worker and candidate.poll() is not None)):
                    self._retire_idle(candidate, deadline)
                    if candidate is worker: worker = None
            if time.monotonic() >= deadline: raise TimeoutError('fixture query deadline')
            if worker is None:
                if len(self.workers) >= 16: raise TransportError('fixture transport worker limit')
                worker = self.popen(['docker', 'exec', '-i', self.container, 'sh', '-c', SHELL], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=self.environment, bufsize=0)
                self.workers.append(worker)
                self.owners[worker] = current
                self.inflight[worker] = threading.Event()
                self.local.worker = worker
            if time.monotonic() >= deadline: raise TimeoutError('fixture query deadline')
            active = self.inflight[worker]
            active.set()
            return worker, active
        except _IdleReapError:
            # Containment may take longer than the query budget; release the
            # ownership lock before performing this separate safety cleanup.
            self.lock.release()
            held = False
            try: self._contain()
            except Exception as failure: raise TransportError('fixture cleanup containment failed') from failure
            raise
        finally:
            if held: self.lock.release()

    def execute(self, text, timeout=30):
        if not isinstance(text, str) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 300:
            raise ValueError('invalid fixture query')
        deadline = time.monotonic() + timeout
        payload = base64.b64encode(text.encode(locale.getpreferredencoding(False))).decode('ascii')
        if len(payload) > LIMIT: raise ValueError('fixture query exceeds bound')
        nonce = secrets.token_hex(16)
        worker, active = self._worker(deadline)
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0: raise _BeforeSendDeadline('fixture query deadline')
            # GNU timeout interprets a bare decimal as seconds.
            seconds = format(remaining, '.9f')
            request = (nonce + ' ' + seconds + ' ' + payload + '\n').encode('ascii')
            out, err = self._exchange(worker, request, nonce, deadline)
            if self.contained: raise TransportError('fixture transport closed')
            status_marker = re.compile(rb'\n' + nonce.encode() + rb' STATUS ([0-9]{1,3})\n')
            match = status_marker.search(err)
            if match is None: raise TransportError('fixture status frame invalid')
            status = int(match.group(1))
            if status in (124, 125, 126, 127, 137): raise TransportError('fixture query completion uncertain')
            if status != 0: raise _QueryFailed('authority fixture command failed')
            decoded = base64.b64decode(b''.join(out.split()), validate=True)
            return decoded.decode(locale.getpreferredencoding(False)).replace('\r\n', '\n').replace('\r', '\n').strip()
        except _BeforeSendDeadline:
            raise TimeoutError('fixture query deadline') from None
        except _QueryFailed:
            raise RuntimeError('authority fixture command failed') from None
        except BaseException as exc:
            try: self._contain()
            except Exception as failure: raise TransportError('fixture transport and containment failed') from failure
            if not isinstance(exc, Exception): raise
            raise TransportError('fixture transport failed; container contained') from None
        finally:
            active.clear()

    def _exchange(self, worker, request, nonce, deadline):
        selector = selectors.DefaultSelector(); out = bytearray(); err = bytearray(); offset = 0
        marker = nonce.encode() + b' END\n'
        try:
            for pipe, event in ((worker.stdin, selectors.EVENT_WRITE), (worker.stdout, selectors.EVENT_READ), (worker.stderr, selectors.EVENT_READ)):
                os.set_blocking(pipe.fileno(), False); selector.register(pipe, event)
            while True:
                if out.endswith(marker) and re.search(rb'\n' + nonce.encode() + rb' STATUS [0-9]{1,3}\n', err):
                    return bytes(out[:-len(marker)]), bytes(err)
                remaining = deadline - time.monotonic()
                if remaining <= 0: raise TransportError('fixture query deadline')
                events = selector.select(remaining)
                if not events: raise TransportError('fixture query deadline')
                for key, _ in events:
                    if key.fileobj is worker.stdin:
                        if time.monotonic() >= deadline:
                            if offset == 0: raise _BeforeSendDeadline('fixture query deadline')
                            raise TransportError('fixture query deadline')
                        wrote = os.write(worker.stdin.fileno(), request[offset:offset+65536]); offset += wrote
                        if offset == len(request): selector.unregister(worker.stdin)
                    else:
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk: raise TransportError('fixture helper EOF')
                        target = out if key.fileobj is worker.stdout else err
                        target.extend(chunk)
                        if len(target) > LIMIT: raise TransportError('fixture response exceeds bound')
        finally:
            selector.close()

    def close(self):
        errors = []
        with self.lock:
            self.closed = True
            if any(active.is_set() for active in self.inflight.values()):
                errors.append(TransportError('fixture helper still in flight'))
            for worker in list(self.workers):
                if self.inflight[worker].is_set(): continue
                try: self._retire_idle(worker)
                except Exception as exc: errors.append(exc)
        if errors:
            try: self._contain()
            except Exception as exc: raise TransportError('fixture cleanup containment failed') from exc
            with self.lock:
                for worker in list(self.workers):
                    try: self._retire_idle(worker)
                    except Exception as exc: errors.append(exc)
            raise TransportError('fixture helper cleanup failed') from errors[0]

    def __enter__(self): return self
    def __exit__(self, *unused): self.close()


class _BeforeSendDeadline(Exception):
    pass


class _IdleReapError(TransportError):
    pass


class _QueryFailed(Exception):
    pass
