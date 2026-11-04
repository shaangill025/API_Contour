"""Owned socket SCRAM checks and secret-suppressed provisioning for a disposable PG."""
import re
import subprocess
import uuid

OPTIONS = ('-c log_statement=none -c log_min_duration_statement=-1 '
           '-c log_min_duration_sample=-1 -c log_min_error_statement=panic '
           '-c log_min_messages=panic -c log_duration=off '
           '-c log_statement_sample_rate=0 -c log_transaction_sample_rate=0')


def configure(name, execute):
    secrets = set()
    marker = 'origin_sensitive_session_' + uuid.uuid4().hex
    sentinel = 'origin_public_log_control_' + uuid.uuid4().hex
    counts = dict(authenticated=0, password_rejected=0, sensitive_sessions=0)

    def process(args, data=None):
        return subprocess.run(args, input=data, text=True, capture_output=True, timeout=45)

    def quiet(query, *, database='contour_local', sensitive=False):
        args = ['docker', 'exec', '-i']
        if sensitive:
            args += ['-e', 'PGOPTIONS=' + OPTIONS]
        args += [name, 'psql', '-X', '-qAt', '-v', 'ON_ERROR_STOP=1', '-h',
                 '/var/run/postgresql', '-U', 'postgres', '-d', database]
        output = process(args, query)
        if output.returncode:
            raise RuntimeError('owned private provisioning or database check failed')
        return output.stdout.strip()

    # Keep only the fixture administrator on trust; all product logins require
    # PostgreSQL's actual SCRAM password exchange over the isolated Unix socket.
    hba = process(['docker', 'exec', '-i', '-u', 'postgres', name, 'sh', '-c',
                   'umask 077; cat > /var/lib/postgresql/data/pg_hba.conf'],
                  'local all postgres trust\nlocal all all scram-sha-256\n')
    if hba.returncode:
        raise RuntimeError('owned authentication fixture configuration failed')
    execute('SELECT pg_catalog.pg_reload_conf();')
    execute("SELECT '" + sentinel + "';")

    def sensitive(query):
        found=set(re.findall(r'SCRAM-SHA-256\$[0-9]+:[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+:[A-Za-z0-9+/=]+', query))
        if len(found)!=2:
            raise RuntimeError('expected two private verifier values')
        secrets.update(found)
        guard = """DO $$ BEGIN IF current_setting('log_statement')<>'none'
          OR current_setting('log_min_duration_statement')<>'-1'
          OR current_setting('log_min_duration_sample')<>'-1'
          OR current_setting('log_min_error_statement')<>'panic'
          OR current_setting('log_min_messages')<>'panic'
          OR current_setting('log_duration')<>'off'
          OR current_setting('log_statement_sample_rate')::numeric<>0
          OR current_setting('log_transaction_sample_rate')::numeric<>0
          THEN RAISE EXCEPTION 'unsafe private session settings'; END IF; END $$;
        """
        counts['sensitive_sessions'] += 1
        return quiet('/*' + marker + '*/ ' + guard + query, sensitive=True)

    def authenticate(role, password):
        if role not in ('contour_local_origin_ingress', 'contour_local_origin_worker'):
            raise ValueError('unexpected fixture login')
        if not isinstance(password, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,4096}', password):
            raise ValueError('invalid fixture credential')
        secrets.add(password)
        # Credential bytes travel only over stdin into a private, transient
        # passfile; no password or verifier enters a process argument or log.
        script = ('set -eu; umask 077; passfile=$(mktemp /tmp/origin-auth.XXXXXX); '
                  'trap \'rm -f "$passfile"\' EXIT; cat > "$passfile"; '
                  'PGPASSFILE="$passfile" psql -X -qAt -w -h /var/run/postgresql '
                  '-U "$1" -d contour_local -c "SELECT current_user;"')
        output = process(['docker', 'exec', '-i', '-u', 'postgres', name, 'sh', '-c',
                          script, 'origin-auth', role], '*:*:contour_local:' + role + ':' + password + '\n')
        if output.returncode == 0 and output.stdout.strip() == role:
            counts['authenticated'] += 1
            return True
        if output.returncode != 0 and 'password authentication failed for user' in output.stderr:
            counts['password_rejected'] += 1
            return False
        raise RuntimeError('owned login connection failed outside password rejection')

    def audit():
        output = process(['docker', 'logs', name])
        if output.returncode:
            raise RuntimeError('owned fixture logging audit unavailable')
        raw = output.stdout + output.stderr
        record = dict(counts, logging_positive_control=sentinel in raw,
                      private_session_absent=marker not in raw,
                      sensitive_values_absent=all(value not in raw for value in secrets))
        if not all(record[key] for key in ('logging_positive_control', 'private_session_absent', 'sensitive_values_absent')):
            raise RuntimeError('owned private provisioning logging audit failed')
        if counts['authenticated'] < 2 or counts['password_rejected'] < 2 or counts['sensitive_sessions'] < 2:
            raise RuntimeError('owned login matrix did not execute')
        return record

    return sensitive, authenticate, lambda query: quiet(query, database='postgres'), audit
