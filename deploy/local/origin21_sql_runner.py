"""Closed SQL supervisor protocol with durable pre-payload identity."""
import hashlib
import re

MAX_PAYLOAD = 8 * 1024 * 1024
MAX_OUTPUT = 8 * 1024 * 1024


class Handshake:
    """Validate a supervisor identity before allowing any private bytes."""
    def __init__(self, nonce, payload):
        if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
            raise ValueError('invalid supervisor nonce')
        if type(payload) is not bytes or not 0 < len(payload) <= MAX_PAYLOAD:
            raise ValueError('invalid private payload')
        self.nonce = nonce
        self._payload = payload
        self.payload_sha256 = hashlib.sha256(payload).hexdigest()
        self.identity = None
        self._persisted = False

    def ready(self, line):
        if self.identity is not None or not isinstance(line, bytes) or len(line) > 256:
            raise ValueError('invalid supervisor readiness')
        match = re.fullmatch(rb'READY ([0-9a-f]{32}) ([1-9][0-9]{0,9}) ([1-9][0-9]{0,9}) ([1-9][0-9]{0,19})\n', line)
        if not match or match[1].decode('ascii') != self.nonce:
            raise ValueError('invalid supervisor readiness')
        pid, pgid, started = map(int, match.groups()[1:])
        if pid != pgid or pid <= 1:
            raise ValueError('invalid supervisor group')
        self.identity = {'pid': pid, 'pgid': pgid, 'starttime': started}
        return dict(self.identity)

    def persisted(self, identity):
        if self.identity is None or identity != self.identity or self._persisted:
            raise ValueError('identity checkpoint mismatch')
        self._persisted = True

    def payload(self):
        if not self._persisted:
            raise RuntimeError('private payload before durable supervisor identity')
        return self._payload


def _validate_intent(value, target):
    if (type(value) is not dict or set(value) != {'version', 'nonce', 'target', 'payload_sha256', 'identity', 'mode', 'role'}
            or value['version'] != 1 or value['target'] != target
            or not isinstance(value['nonce'], str) or not re.fullmatch('[0-9a-f]{32}', value['nonce'])
            or not isinstance(value['payload_sha256'], str) or not re.fullmatch('[0-9a-f]{64}', value['payload_sha256'])):
        raise ValueError('invalid SQL supervisor intent')
    _validate_mode_role(value['mode'], value['role'])
    identity = value['identity']
    if identity is not None:
        if (type(identity) is not dict or set(identity) != {'pid', 'pgid', 'starttime'}
                or any(type(identity[key]) is not int or identity[key] <= 0 for key in identity)
                or identity['pid'] <= 1 or identity['pid'] != identity['pgid']):
            raise ValueError('invalid SQL supervisor identity')
    return value


def _validate_mode_role(mode, role):
    from deploy.local import origin21_profile
    if not ((mode == 'sql' and role == 'postgres') or
            (mode == 'auth' and role in (origin21_profile.PROFILE.ingress_login, origin21_profile.PROFILE.worker_login))):
        raise ValueError('invalid SQL supervisor mode or role')


class IntentStore:
    """One owner may reconcile or advance a single private pending intent."""
    def __init__(self, directory, target):
        from pathlib import Path
        from deploy.local import capture_renew
        self.directory = Path(directory)
        capture_renew.safe_dir(self.directory)
        if (type(target) is not dict or set(target) != {'container_id', 'image_id', 'network_id'}
                or not re.fullmatch('[0-9a-f]{64}', target.get('container_id', ''))
                or not re.fullmatch('sha256:[0-9a-f]{64}', target.get('image_id', ''))
                or not re.fullmatch('[0-9a-f]{64}', target.get('network_id', ''))):
            raise ValueError('invalid SQL target')
        self.target = dict(target)
        self.path = self.directory / 'pending.json'
        self._fd = None

    def __enter__(self):
        import fcntl
        import os
        import stat
        fd = os.open(self.directory / 'lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise ValueError('unsafe SQL transport lock')
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd
        return self

    def __exit__(self, *_):
        import os
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None

    def _owned(self):
        if self._fd is None:
            raise RuntimeError('SQL transport lock required')

    def read(self):
        import os
        from deploy.local import capture_renew
        self._owned()
        if not os.path.lexists(self.path):
            return None
        raw = capture_renew.read_file(self.path, 4096)
        value = capture_renew.exact_json(raw)
        return _validate_intent(value, self.target)

    def begin(self, handshake, mode, role):
        import json
        import os
        self._owned()
        if self.read() is not None:
            raise RuntimeError('unresolved SQL transport intent')
        _validate_mode_role(mode, role)
        value = {'version': 1, 'nonce': handshake.nonce, 'target': self.target, 'mode': mode, 'role': role,
                 'payload_sha256': handshake.payload_sha256, 'identity': None}
        raw = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(raw)
                out.flush()
                os.fsync(out.fileno())
        except BaseException:
            # An incomplete intent remains in place and blocks further calls.
            raise
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)

    def ready(self, handshake, line):
        import json
        from deploy.local import capture_renew
        self._owned()
        value = self.read()
        if value is None or value['nonce'] != handshake.nonce or value['identity'] is not None or value['payload_sha256'] != handshake.payload_sha256:
            raise ValueError('SQL supervisor intent drift')
        identity = handshake.ready(line)
        value['identity'] = identity
        capture_renew.replace_durable(self.path, json.dumps(value, sort_keys=True, separators=(',', ':')).encode())
        handshake.persisted(identity)

    def remove(self):
        from deploy.local import capture_renew
        self._owned()
        if self.read() is None:
            raise ValueError('missing SQL transport intent')
        capture_renew.remove_durable(self.path)

# The supervisor receives only the nonce, mode, role, and payload length in its
# argv. Private input remains on stdin until the caller has persisted READY.
SUPERVISOR = r'''set -eu
nonce=$1; mode=$2; role=$3; size=$4
case "$nonce" in *[!0-9a-f]*|'') exit 91;; esac
case "$size" in *[!0-9]*|'') exit 91;; esac
stat=$(cat "/proc/$$/stat")
rest=${stat#*) }
set -- $rest
pgid=$3
shift 19
started=$1
[ "$$" = "$pgid" ] || exit 92
printf 'READY %s %s %s %s\n' "$nonce" "$$" "$pgid" "$started"
export PGAPPNAME="origin21_$nonce"
if [ "$mode" = auth ]; then
    password=$(timeout --foreground 10 head -c "$size") || exit 93
    [ "${#password}" -eq "$size" ] || exit 93
    export PGPASSWORD="$password" PGSSLMODE=verify-full PGSSLROOTCERT=/run/local-ca.crt
    { if timeout --foreground 60 psql -X -qAt -w -h localhost -p 5432 -U "$role" -d contour_local -c 'SELECT current_user;' 2>/dev/null; then result=0; else result=$?; fi; printf 'STATUS %s %s\n' "$nonce" "$result" >&2; } | base64 -w0
    unset PGPASSWORD password
elif [ "$mode" = sql ]; then
    { if timeout --foreground 60 sh -c 'head -c "$1" | psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d contour_local 2>/dev/null' sh "$size"; then result=0; else result=$?; fi; printf 'STATUS %s %s\n' "$nonce" "$result" >&2; } | base64 -w0
else
    exit 94
fi
printf '\nEND %s\n' "$nonce"
ack=$(timeout --foreground 10 head -c 4) || exit 95
[ "$ack" = ACK! ] || exit 95
'''


def decode_result(nonce, stdout, stderr):
    """Decode a fully bounded, authenticated supervisor result."""
    import base64
    import binascii
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('invalid supervisor nonce')
    if type(stdout) is not bytes or type(stderr) is not bytes or len(stdout) > ((MAX_OUTPUT + 2) // 3) * 4 + 40 or len(stderr) > 64:
        raise RuntimeError('SQL supervisor output bound')
    marker = b'\nEND ' + nonce.encode('ascii') + b'\n'
    if not stdout.endswith(marker) or stdout.count(marker) != 1:
        raise RuntimeError('SQL supervisor output framing')
    if stderr != b'STATUS ' + nonce.encode('ascii') + b' 0\n':
        raise RuntimeError('SQL supervisor command failed')
    try:
        raw = base64.b64decode(stdout[:-len(marker)], validate=True)
        if len(raw) > MAX_OUTPUT:
            raise ValueError('output bound')
        return raw.decode('utf-8').strip()
    except (ValueError, UnicodeError, binascii.Error):
        raise RuntimeError('invalid SQL supervisor output') from None


class Runner:
    """One target, with trusted target verification and exact cleanup adapters.

    Adapters are operator-owned: verify_target must recheck the complete target
    and cleanup must return True only after the recorded remote group and all
    application-nonce backends are absent. No default adapters are provided.
    """
    def __init__(self, directory, target, verify_target, cleanup, launch):
        if not all(callable(value) for value in (verify_target, cleanup, launch)):
            raise ValueError('trusted SQL runner adapters required')
        self.directory, self.target = directory, dict(target)
        self.verify_target, self.cleanup, self.launch = verify_target, cleanup, launch

    def _reconcile(self, store):
        value = store.read()
        if value is None:
            return
        self.verify_target(self.target)
        if value['identity'] is None:
            raise RuntimeError('unresolved pre-READY SQL supervisor intent')
        if self.cleanup(value) is not True:
            raise RuntimeError('SQL supervisor cleanup unresolved')
        store.remove()

    def run(self, payload, mode, role, deadline=80):
        import os
        import secrets
        import select
        import signal
        import time
        _validate_mode_role(mode, role)
        if type(deadline) not in (int, float) or not 1 <= deadline <= 120:
            raise ValueError('invalid SQL supervisor deadline')
        gate = Handshake(secrets.token_hex(16), payload)
        with IntentStore(self.directory, self.target) as store:
            self._reconcile(store)
            self.verify_target(self.target)
            store.begin(gate, mode, role)
            process = None
            try:
                process = self.launch(gate.nonce, mode, role, len(payload))
                for stream in (process.stdin, process.stdout, process.stderr):
                    os.set_blocking(stream.fileno(), False)
                end = time.monotonic() + deadline
                stdout = bytearray(); stderr = bytearray(); sent = 0
                ready = False; result = None; ack_sent = 0
                while True:
                    left = end - time.monotonic()
                    if left <= 0:
                        raise TimeoutError('SQL supervisor deadline')
                    readers = [process.stdout, process.stderr]
                    writers = [process.stdin] if ready and (sent < len(payload) or result is not None and ack_sent < 4) else []
                    readable, writable, _ = select.select(readers, writers, [], left)
                    for stream in readable:
                        data = os.read(stream.fileno(), 65536)
                        if not data:
                            raise RuntimeError('SQL supervisor disconnected')
                        if result is not None:
                            raise RuntimeError('unexpected SQL supervisor trailing output')
                        if stream is process.stdout:
                            stdout.extend(data)
                            if len(stdout) > ((MAX_OUTPUT + 2) // 3) * 4 + 512:
                                raise RuntimeError('SQL supervisor output bound')
                        else:
                            stderr.extend(data)
                            if len(stderr) > 64:
                                raise RuntimeError('SQL supervisor control bound')
                    if not ready and b'\n' in stdout:
                        line, remaining = bytes(stdout).split(b'\n', 1)
                        if remaining or stderr:
                            raise RuntimeError('SQL supervisor sent unexpected early output')
                        store.ready(gate, line + b'\n')
                        stdout.clear()
                        ready = True
                    if ready and result is None and sent == len(payload) and bytes(stdout).endswith(b'\nEND ' + gate.nonce.encode() + b'\n') and b'\n' in stderr:
                        result = decode_result(gate.nonce, bytes(stdout), bytes(stderr))
                    for stream in writable:
                        if sent < len(payload):
                            sent += os.write(stream.fileno(), gate.payload()[sent:sent + 65536])
                        elif result is not None:
                            ack_sent += os.write(stream.fileno(), b'ACK!'[ack_sent:])
                    if result is not None and ack_sent == 4:
                        process.stdin.close()
                        _drain_after_ack(process, end)
                        if process.wait(timeout=max(.01, end-time.monotonic())) != 0:
                            raise RuntimeError('SQL supervisor exit failed')
                        store.remove()
                        return result
            except BaseException:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        process.wait(timeout=5)
                    except Exception:
                        pass
                value = store.read()
                if value is not None and value['identity'] is not None:
                    try:
                        self.verify_target(self.target)
                        if self.cleanup(value) is True:
                            store.remove()
                    except Exception:
                        pass
                raise RuntimeError('SQL transport failed; unresolved intent blocks retry') from None
            finally:
                if process is not None:
                    for stream in (process.stdin, process.stdout, process.stderr):
                        if not stream.closed:
                            stream.close()


def _drain_after_ack(process, deadline):
    import os
    import select
    import time
    streams=[process.stdout, process.stderr]
    while streams:
        remaining=deadline-time.monotonic()
        if remaining <= 0: raise TimeoutError('SQL supervisor final drain deadline')
        readable,_,_=select.select(streams,[],[],remaining)
        for stream in readable:
            if os.read(stream.fileno(),65536): raise RuntimeError('unexpected SQL supervisor trailing output')
            streams.remove(stream)


CLEANUP = r'''set -eu
nonce=$1; pid=$2; pgid=$3; started=$4; mode=$5; role=$6
case "$nonce" in *[!0-9a-f]*|'') exit 91;; esac
case "$pid:$pgid:$started" in *[!0-9:]*|'') exit 91;; esac
[ "$pid" = "$pgid" ] && [ "$pid" -gt 1 ] || exit 91
case "$mode:$role" in
    sql:postgres) address='client_addr IS NULL';;
    auth:contour_local_origin21_ingress|auth:contour_local_origin21_worker) address="client_addr IN ('127.0.0.1'::pg_catalog.inet,'::1'::pg_catalog.inet)";;
    *) exit 91;;
esac
group_absent() {
    for path in /proc/[0-9]*/stat; do
        if ! stat=$(cat "$path" 2>/dev/null); then
            [ ! -e "$path" ] && continue
            return 1
        fi
        rest=${stat##*) }; set -- $rest
        [ "$#" -ge 3 ] || return 1
        [ "$3" != "$pgid" ] || return 1
    done
    return 0
}
if [ -e "/proc/$pid/stat" ]; then
    stat=$(cat "/proc/$pid/stat") || exit 92
    rest=${stat##*) }; set -- $rest
    actual_group=$3; shift 19; actual_started=$1
    [ "$actual_group" = "$pgid" ] && [ "$actual_started" = "$started" ] || exit 92
    tr '\000' '\n' < "/proc/$pid/cmdline" | grep -Fx "$nonce" >/dev/null || exit 92
    kill -TERM "-$pgid" || exit 92
else
    group_absent || exit 92
fi
export PGAPPNAME="origin21_cleanup_$nonce"
export PGOPTIONS='-c statement_timeout=5000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=5000'
predicate="application_name='origin21_$nonce' AND datname='contour_local' AND usename='$role' AND backend_type='client backend' AND $address AND pid<>pg_catalog.pg_backend_pid()"
i=0
while [ "$i" -lt 30 ]; do
    timeout --foreground 5 psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d contour_local -c "SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE $predicate;" >/dev/null 2>&1 || exit 93
    count=$(timeout --foreground 5 psql -X -qAt -v ON_ERROR_STOP=1 -U postgres -d contour_local -c "SELECT count(*) FROM pg_catalog.pg_stat_activity WHERE $predicate;" 2>/dev/null) || exit 93
    if [ "$count" = 0 ] && group_absent; then printf 'CLEAN\n'; exit 0; fi
    sleep .2
    i=$((i+1))
done
exit 94
'''


def for_deployment(directory, deployment, *, selected=None,qualification=None):
    """Bind a private runner to an exact operator-owned deployment."""
    import os
    import subprocess
    from deploy.local import capture_renew, origin21_products, origin21_profile, origin21_transport
    if selected is None: selected=origin21_profile.STATIC
    origin21_profile.require_context(selected)
    if selected is origin21_profile.MANAGED:
        from deploy.local.origin21_managed_qualification import require_matching
        require_matching(qualification)
    elif qualification is not None: raise ValueError('unexpected qualification')
    fields={'name','id','owner_kind','owner_token','postgres_id','postgres_image_id','ca_sha256'}
    if type(deployment) is not dict or set(deployment)!=fields or not all(isinstance(x,str) for x in deployment.values()): raise ValueError('invalid SQL deployment')
    if not re.fullmatch('[0-9a-f]{64}',deployment['id']) or not re.fullmatch('[0-9a-f]{64}',deployment['postgres_id']) or not re.fullmatch('sha256:[0-9a-f]{64}',deployment['postgres_image_id']) or not re.fullmatch('[0-9a-f]{64}',deployment['ca_sha256']): raise ValueError('invalid SQL deployment identity')
    if deployment['owner_kind']=='local' and selected is origin21_profile.STATIC:
        if (deployment['name'],deployment['owner_token'])!=('apicontour-local_default','apicontour-local'): raise ValueError('invalid local network')
    elif deployment['owner_kind']=='managed-local' and selected is origin21_profile.MANAGED:
        if (deployment['name'],deployment['owner_token'])!=('apicontour-origin21-managed-db_default','apicontour-origin21-managed-db'): raise ValueError('invalid managed network')
    elif deployment['owner_kind']=='fixture':
        prefix='contour-origin21-qual-' if selected is origin21_profile.STATIC else 'contour-managed-origin21-qual-'
        if not re.fullmatch('[0-9a-f]{32}',deployment['owner_token']) or deployment['name']!=prefix+deployment['owner_token']: raise ValueError('invalid fixture network')
    else: raise ValueError('unsupported SQL deployment')
    deployment=dict(deployment)
    target = {'container_id': deployment['postgres_id'], 'image_id': deployment['postgres_image_id'], 'network_id': deployment['id']}
    def verify(value):
        if value != target: raise RuntimeError('SQL target changed')
        if selected is origin21_profile.STATIC: origin21_products._capture_network(deployment)
        else:
            origin21_products._capture_network(deployment,selected=selected)
            from deploy.local import origin21_managed_init
            origin21_managed_init.verify_runtime_target(deployment,qualification=qualification)
    verify(target)
    capture_renew.safe_dir(directory)
    timeout_options = '-c statement_timeout=60000 -c lock_timeout=10000 -c idle_in_transaction_session_timeout=60000'
    def launch(nonce, mode, role, size):
        options = timeout_options + (' ' + origin21_transport.OPTIONS if mode == 'sql' else '')
        args = ['docker', 'exec', '-i', '-u', 'postgres', '-e', 'PGOPTIONS='+options, target['container_id'],
                'setsid', '--wait', 'sh', '-c', SUPERVISOR, 'origin21-supervisor', nonce, mode, role, str(size)]
        return subprocess.Popen(args, cwd=origin21_profile.ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    def cleanup(value):
        identity=value['identity']
        args=['docker','exec','-i','-u','postgres',target['container_id'],'timeout','--foreground','25','sh','-c',CLEANUP,'origin21-cleanup',
              value['nonce'],str(identity['pid']),str(identity['pgid']),str(identity['starttime']),value['mode'],value['role']]
        try:
            return origin21_transport._run(args,'',deadline=30) == 'CLEAN'
        except Exception:
            return False
    return Runner(directory, target, verify, cleanup, launch)


def production(*,selected=None):
    """Bind only the static recorded local PostgreSQL container."""
    from deploy.local import origin21_profile
    if selected is None: selected=origin21_profile.STATIC
    if selected is not origin21_profile.STATIC: raise ValueError('managed transport requires a verified receipt')
    import os
    from deploy.local import capture_renew, origin21_products, origin21_profile
    deployment=origin21_products._read_record('intent.json')['deployment']
    parent=origin21_profile.STATE.parent; capture_renew.safe_dir(parent)
    directory=parent/'origin21-transport'
    try: os.mkdir(directory,0o700)
    except FileExistsError: pass
    else:
        fd=os.open(parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try: os.fsync(fd)
        finally: os.close(fd)
    runner=for_deployment(directory,deployment)
    verify=runner.verify_target
    def verify_record(value):
        if origin21_products._read_record('intent.json')['deployment']!=deployment: raise RuntimeError('SQL deployment changed')
        verify(value)
    runner.verify_target=verify_record
    return runner
