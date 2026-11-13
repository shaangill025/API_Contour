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
    def __init__(self, sql, environment, owner, *, popen=subprocess.Popen, run=subprocess.run, diagnostic_context=None):
        if (len(sql) != 12 or sql[:3] != ['docker', 'exec', '-i'] or
            not re.fullmatch('[0-9a-f]{64}', sql[3]) or
            sql[4:] != ['psql', '-XAtq', '-v', 'ON_ERROR_STOP=1', '-U', 'postgres', '-d', 'contour_fixture']):
            raise ValueError('invalid fixture command')
        if not re.fullmatch('[0-9a-f]{32}', owner): raise ValueError('invalid fixture owner')
        if diagnostic_context not in (None,'observer-v1','receiver-v1','receiver-inbox-v1'): raise ValueError('invalid fixture diagnostic context')
        self.diagnostic_context = diagnostic_context
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
            if status != 0:
                if self.diagnostic_context == 'observer-v1':
                    phase, state, column, function, line = _observer_failure(text, out, err)
                    raise _ObserverQueryFailed(phase,state,column,function,line)
                if self.diagnostic_context == 'receiver-v1':
                    state, function, line, source_line, case = _receiver_failure(err,out)
                    raise _ReceiverQueryFailed(state,function,line,source_line,case)
                if self.diagnostic_context == 'receiver-inbox-v1':
                    raise _ReceiverInboxQueryFailed(*_receiver_inbox_failure(text,out,err))
                raise _QueryFailed()
            decoded = base64.b64decode(b''.join(out.split()), validate=True)
            return decoded.decode(locale.getpreferredencoding(False)).replace('\r\n', '\n').replace('\r', '\n').strip()
        except _BeforeSendDeadline:
            raise TimeoutError('fixture query deadline') from None
        except _ObserverQueryFailed as failure:
            raise ObserverQueryError(failure.phase,failure.sqlstate,failure.column,failure.function,failure.line) from None
        except _ReceiverInboxQueryFailed as failure:
            raise ReceiverInboxQueryError(*failure.values) from None
        except _ReceiverQueryFailed as failure:
            raise ReceiverQueryError(failure.sqlstate,failure.function,failure.line,failure.source_line,failure.case) from None
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


_OBSERVER_PREFIX = b'\\set VERBOSITY verbose\n\\echo observer-step=runtime-source\n'
_OBSERVER_STEPS = ('runtime-source','profile','runtime-enroll','session','generation','marker','gateway','proof','canonical','cases','parser','first-accept','replay','negativeclaims','quota','graph','chains')
_OBSERVER_COLUMNS = frozenset(('raw','proof','claim','epoch','generation','tenant_id','collector_id','source_id','project_id','service_id','environment_id','deployment_id','instance_id','lifecycle_id','credential_id','grant_id','leaf_sha256','runtime_id','batch_id','record_id','proof_id','gateway_id','gateway_generation','delivery_handle','session_epoch','attempt','retry_of','marker_digest','marker_root','marker_activity','marker_public','canonical_fact','fact_digest','receipt','receipt_id','accepted_at','expires_at','charged_bytes','used_bytes','metadata','root','activity','kind','name','seq','n','version','status','issued_at','policy_revision','policy_envelope','signed_envelope','count','value','k','v','p','r','x','j','b','col','leaf','gen','handle','prev','rec','bid','ep','md','c','e','g','q','w','z','origin','initial_at','final_at','floor_at','receipt_cutoff','stored_receipt','extra','charge','gateway','gateway2','binding','marker','reservation','old','ancestor_count','descendant_count','closes_cycle','at_time'))
_OBSERVER_FUNCTIONS = frozenset(('inline_code_block','contour.accept_causal_observer','contour.observer_wire','contour.human_observation_origin','contour.catalog_origin_mapping','contour.causal_json_canonical','contour.causal_session_locked','contour.causal_marker_product_current','contour.gateway_claim_current','contour.begin_origin_operation','contour.lock_origin_collector','contour.lock_origin_credential','contour.ensure_origin_tenant_state','contour.collector_lock_key','contour.immutable_row'))

class ObserverQueryError(RuntimeError):
    """Definite failure metadata; no database output is retained."""
    def __init__(self, phase, sqlstate, column, function, line):
        self.phase = phase if phase in _OBSERVER_STEPS else 'unavailable'
        self.sqlstate = sqlstate if re.fullmatch('[0-9A-Z]{5}',sqlstate) else 'unavailable'
        self.column = column if column in _OBSERVER_COLUMNS else 'unavailable'
        self.function = function if function in _OBSERVER_FUNCTIONS else 'unavailable'
        self.line = line if type(line) is int and 1 <= line <= 9999 and self.function != 'unavailable' else None
        super().__init__('authority fixture command failed (observer-step='+self.phase+', sqlstate='+self.sqlstate+', column='+self.column+', function='+self.function+', line='+(str(self.line) if self.line is not None else 'unavailable')+')')

class _ObserverQueryFailed(Exception):
    def __init__(self,phase,sqlstate,column,function,line): self.phase,self.sqlstate,self.column,self.function,self.line=phase,sqlstate,column,function,line

def _observer_failure(text, out, err):
    """Return only allowlisted context from a definite observer SQL failure."""
    unavailable=('unavailable','unavailable','unavailable','unavailable',None)
    if not text.encode('utf-8').startswith(_OBSERVER_PREFIX): return unavailable
    try:
        stdout=base64.b64decode(b''.join(out.split()),validate=True)
        steps=re.findall(rb'(?m)^observer-step=([^\r\n]*)\r?$',stdout)
        decoded=[step.decode('ascii') for step in steps]
        if not decoded or decoded!=list(_OBSERVER_STEPS[:len(decoded)]): return unavailable
        errors=re.findall(rb'(?m)^(?:psql:<stdin>:[0-9]+: )?ERROR:[ \t]+([0-9A-Z]{5}): ([^\r\n]*)\r?$',err)
        if len(errors)!=1: return decoded[-1],*unavailable[1:]
        code,message=errors[0]; state=code.decode('ascii'); column='unavailable'
        match=re.fullmatch(rb'column reference "([a-z_][a-z_0-9]*)" is ambiguous',message)
        if state=='42702' and match and match[1].decode('ascii') in _OBSERVER_COLUMNS: column=match[1].decode('ascii')
        contexts=re.findall(rb'(?m)^CONTEXT:[ \t]+PL/pgSQL function ([a-z_][a-z_0-9.]*)(?:\([^\r\n]*\))? line ([1-9][0-9]{0,3}) at [^\r\n]*\r?$',err)
        function='unavailable'; line=None
        if contexts:
            candidate=contexts[0][0].decode('ascii')
            if candidate in _OBSERVER_FUNCTIONS: function=candidate; line=int(contexts[0][1])
        return decoded[-1],state,column,function,line
    except (ValueError,UnicodeError): return unavailable


_RECEIVER_STATES=frozenset(('23502','23503','23505','23514','40001','42501','42601','42702','42703','42804','42883','42P01','42P07','42710','55000','54000','P0001','XX000'))
_RECEIVER_FUNCTIONS=frozenset(('inline_code_block','contour.register_causal_profile','contour.enroll_causal_runtime','contour.issue_causal_session','contour.enroll_origin_credential','contour.enroll_causal_receiver','contour.current_causal_receiver','contour.close_causal_receiver','contour.receiver_claim_current','contour.receiver_enrollment_metadata','contour.receiver_enrollment_commitment','contour.receiver_terminal_body','contour.enroll_causal_gateway','contour.gateway_claim_current','contour.causal_session_locked','contour.causal_runtime_authority_locked','contour.causal_marker_product_current','contour.causal_json_canonical','contour.begin_origin_operation','contour.lock_origin_credential','contour.lock_origin_collector','contour.ensure_origin_tenant_state','contour.immutable_row'))

_RECEIVER29_STATES=_RECEIVER_STATES | frozenset(('22P02',))
_RECEIVER29_STEPS=('migration28','migration29','observer-regression','seed','cases')
_RECEIVER29_CASES=('parser','observer-first','receiver-first','receiver-first-mismatch','quota','revoked-product')
_RECEIVER29_FUNCTIONS=_RECEIVER_FUNCTIONS | _OBSERVER_FUNCTIONS | frozenset(('contour.receiver_inbox_wire','contour.receiver_enrollment_current','contour.receiver_assignment_current','contour.receiver_assignment_metadata','contour.receiver_tombstone_metadata','contour.receiver_observer_current','contour.accept_causal_receiver'))

class ReceiverInboxQueryError(RuntimeError):
    def __init__(self,step,case,state,function,line,source_line):
        self.step=step if step in _RECEIVER29_STEPS or step in ('seed-authority','seed-session','seed-enrollment','seed-pairs') else 'unavailable'
        self.case=case if case in _RECEIVER29_CASES else 'unavailable'
        self.sqlstate=state if state in _RECEIVER29_STATES else 'unavailable'
        self.function=function if function in _RECEIVER29_FUNCTIONS else 'unavailable'
        self.line=line if type(line) is int and 1<=line<=9999 and self.function!='unavailable' else None
        self.source_line=source_line if type(source_line) is int and 1<=source_line<=999999 else None
        super().__init__('receiver inbox SQL failure')

class _ReceiverInboxQueryFailed(Exception):
    def __init__(self,*values): self.values=values

def _receiver_inbox_failure(text,out,err):
    """Extract closed labels only from the fixed SQL29 qualification stream."""
    unavailable=('unavailable','unavailable','unavailable','unavailable',None,None)
    if type(text) is not str or not (text.encode('utf-8').startswith(_OBSERVER_PREFIX) or text.startswith('\\set VERBOSITY verbose\n\\echo receiver-case=revoked-product\n')): return unavailable
    try:
        stdout=base64.b64decode(b''.join(out.split()),validate=True)
        steps=[x.decode('ascii') for x in re.findall(rb'(?m)^receiver29-step=([^\r\n]*)\r?$',stdout)]
        step=steps[-1] if steps and steps==list(_RECEIVER29_STEPS[:len(steps)]) else 'unavailable'
        cases=[x.decode('ascii') for x in re.findall(rb'(?m)^receiver-case=([^\r\n]*)\r?$',stdout)]
        seeds=[x.decode('ascii') for x in re.findall(rb'(?m)^receiver29-seed=([^\r\n]*)\r?$',stdout)]
        if step=='seed' and seeds and seeds==['authority','session','enrollment','pairs'][:len(seeds)]: step='seed-'+seeds[-1]
        case=cases[-1] if cases and cases==list(_RECEIVER29_CASES[:len(cases)]) else ('revoked-product' if cases==['revoked-product'] and text.startswith('\\set VERBOSITY verbose\n\\echo receiver-case=revoked-product\n') else 'unavailable')
        errors=re.findall(rb'(?m)^(?:psql:<stdin>:([1-9][0-9]{0,5}): )?ERROR:[ \t]+([0-9A-Z]{5}):[^\r\n]*\r?$',err)
        if len(errors)!=1: return (step,case,'unavailable','unavailable',None,None)
        source,state=errors[0];state=state.decode('ascii');state=state if state in _RECEIVER29_STATES else 'unavailable'
        contexts=re.findall(rb'(?m)^(?:CONTEXT:[ \t]*)?[ \t]*PL/pgSQL function ([a-z_][a-z_0-9.]*)(?:\([^\r\n]*\))? line ([1-9][0-9]{0,3}) at [^\r\n]*\r?$',err)
        function='unavailable';line=None
        for name,number in contexts:
            candidate=name.decode('ascii')
            if candidate in _RECEIVER29_FUNCTIONS: function=candidate;line=int(number);break
        return (step,case,state,function,line,int(source) if source else None)
    except (ValueError,UnicodeError): return unavailable

_RECEIVER_ALIASES={name.split('.')[-1]:name for name in _RECEIVER_FUNCTIONS}
_RECEIVER_CASES=('vector','setup','profile','runtime','session','enroll','retry','changed-claim','quota','current','selectors','missing-reservation','clock','second-credential','profile-second','runtime-second','session-second','enroll-second','current-second','revoke','primary-current','close','close-retry','closed-retry','closure-wire','purpose','acl','immutable')

class ReceiverQueryError(RuntimeError):
    def __init__(self,sqlstate,function,line,source_line,case='unavailable'):
        state=sqlstate if sqlstate in _RECEIVER_STATES else 'unavailable'
        function=function if function in _RECEIVER_FUNCTIONS else 'unavailable'
        line=line if type(line) is int and 1<=line<=9999 and function!='unavailable' else None
        source_line=source_line if type(source_line) is int and 1<=source_line<=999999 else None
        case=case if case in _RECEIVER_CASES else 'unavailable'
        super().__init__('receiver-sql state='+state+' function='+function+' line='+(str(line) if line else 'unavailable')+' input_line='+(str(source_line) if source_line else 'unavailable')+' case='+case)

class _ReceiverQueryFailed(Exception):
    def __init__(self,sqlstate,function,line,source_line,case): self.sqlstate,self.function,self.line,self.source_line,self.case=sqlstate,function,line,source_line,case

def _receiver_failure(err,out=b''):
    unavailable=('unavailable','unavailable',None,None,'unavailable')
    if not isinstance(err,bytes) or not isinstance(out,bytes): return unavailable
    case='unavailable'
    try:
        stdout=base64.b64decode(b''.join(out.split()),validate=True)
        tags=[tag.decode('ascii') for tag in re.findall(rb'(?m)^receiver-case=([^\r\n]*)\r?$',stdout)]
        if tags and tags==list(_RECEIVER_CASES[:len(tags)]): case=tags[-1]
    except (ValueError,UnicodeError): pass
    errors=re.findall(rb'(?m)^(?:psql:<stdin>:([1-9][0-9]{0,5}): )?ERROR:[ \t]+([0-9A-Z]{5}):[^\r\n]*\r?$',err)
    if len(errors)!=1: return unavailable[:4]+(case,)
    source,state=errors[0]; state=state.decode('ascii')
    if state not in _RECEIVER_STATES: state='unavailable'
    contexts=re.findall(rb'(?m)^(?:CONTEXT:[ \t]*)?[ \t]*PL/pgSQL function ([a-z_][a-z_0-9.]*)(?:\([^\r\n]*\))? line ([1-9][0-9]{0,3}) at [^\r\n]*\r?$',err)
    function='unavailable'; line=None
    for name,number in contexts:
        candidate=name.decode('ascii')
        candidate=candidate if candidate in _RECEIVER_FUNCTIONS else _RECEIVER_ALIASES.get(candidate,'unavailable')
        if candidate!='unavailable': function=candidate; line=int(number); break
    return state,function,line,int(source) if source else None,case
