"""Fixed SQL31 continuation for the existing disposable SQL29 fixture.

The supervisor must run the existing SQL29 fixture first, then run each value
returned by scenario_sql() in order in that same psql backend with autocommit and
ON_ERROR_STOP. This module never opens a connection or accepts arbitrary SQL.
Synthetic issuer assertions do not establish TLS or signature possession.
"""
from pathlib import Path
import os
import stat
import subprocess

ROOT = Path(__file__).resolve().parents[3]
ARRIVAL_FILE = 'tests/fixtures/causal-edge-reconciliation/arrival.sql'
FILES = (
    'db/opt-in-migrations/0030_causal_gateway_reader.sql',
    'db/opt-in-migrations/0031_causal_edge_reconciliation.sql',
    'tests/fixtures/causal-edge-reconciliation/seed.sql',
    'tests/fixtures/causal-edge-reconciliation/clock_boundaries.sql',
    'db/tests/causal_join_facts_integrity.sql',
    'db/tests/causal_edge_reconciliation.sql',
    ARRIVAL_FILE,
)


def _source(name, tracked=False):
    if name not in FILES:
        raise ValueError('unsupported fixture source')
    path = ROOT / name
    if any(p.is_symlink() for p in (path, *path.parents)):
        raise ValueError('fixture source symlink')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 2_000_000:
            raise ValueError('fixture source invalid')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            raw = stream.read(2_000_001)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise ValueError('fixture source changed')
        if tracked:
            result = subprocess.run(['git', 'show', 'HEAD:' + name], cwd=ROOT, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=True)
            if result.stderr or result.stdout != raw:
                raise ValueError('tracked fixture source changed')
        return raw.decode('utf-8', 'strict')
    finally:
        os.close(fd)


def scenario_sql():
    values = tuple(_source(name, tracked=(i == 0)) for i, name in enumerate(FILES[:6]))
    if any(not migration.rstrip().endswith('COMMIT;') for migration in values[:2]):
        raise ValueError('migration incomplete')
    return values


def arrival_sql():
    """All fixed 24 permutations; every admission and resolve is autocommitted."""
    import itertools
    seed = _source(ARRIVAL_FILE, tracked=True)
    actions = {
        'P': ('contour_causal_inbox_writer', "SELECT i.n,'P',NOT r.duplicate FROM arrival_inputs i CROSS JOIN LATERAL contour.accept_causal_batch(i.tenant,i.producer_runtime,i.producer_epoch,i.producer_peer,i.producer_grant,i.producer_body) r"),
        'R': ('contour_causal_inbox_writer', "SELECT i.n,'R',NOT r.duplicate FROM arrival_inputs i CROSS JOIN LATERAL contour.accept_causal_batch(i.tenant,i.receiver_runtime,i.receiver_epoch,i.receiver_peer,i.receiver_grant,i.receiver_body) r"),
        'O': ('contour_causal_observer_writer', "SELECT i.n,'O',contour.accept_causal_observer(i.observer_raw,i.observer_proof) IS NOT NULL FROM arrival_inputs i"),
        'A': ('contour_causal_receiver_writer', "SELECT i.n,'A',contour.accept_causal_receiver(i.receiver_raw,i.receiver_proof) IS NOT NULL FROM arrival_inputs i"),
    }
    sql = [seed]
    for n, order in enumerate(itertools.permutations('PROA'), 1):
        for step, kind in enumerate(order, 1):
            role, select = actions[kind]
            sql.append(f"SET ROLE {role}; INSERT INTO arrival_receipts {select} WHERE i.n={n}; RESET ROLE;")
            sql.append(_arrival_check(n, step))
        sql.append(_arrival_check(n, 5))
    sql.append("DO $$ BEGIN IF (SELECT count(*) FROM arrival_receipts)<>96 OR (SELECT count(DISTINCT (n,kind)) FROM arrival_receipts)<>96 OR EXISTS(SELECT 1 FROM arrival_receipts WHERE NOT ok) OR (SELECT count(*) FROM arrival_checks)<>120 THEN RAISE EXCEPTION 'arrival matrix incomplete'; END IF; END $$;")
    return '\n'.join(sql)


def _arrival_check(n, step):
    if type(n) is not int or not 1 <= n <= 24 or type(step) is not int or not 1 <= step <= 5:
        raise ValueError('invalid fixed arrival case')
    prefix = f"""INSERT INTO arrival_checks SELECT i.n,{step},u.used_bytes,NULL FROM arrival_inputs i JOIN contour.origin_logical_usage u ON u.tenant_id=i.tenant WHERE i.n={n};
SET ROLE contour_causal_reconciler;
UPDATE arrival_checks c SET edge=contour.resolve_causal_delivery(i.tenant,i.gateway,i.generation,i.handle) FROM arrival_inputs i WHERE c.n={n} AND c.step={step} AND i.n=c.n;
RESET ROLE;"""
    if step < 4:
        check = f"""DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM arrival_checks c JOIN arrival_inputs i USING(n) JOIN contour.origin_logical_usage u ON u.tenant_id=i.tenant WHERE c.n={n} AND c.step={step} AND c.edge IS NULL AND c.before_used=u.used_bytes) OR EXISTS(SELECT 1 FROM contour.causal_resolved_edges e JOIN arrival_inputs i ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(i.tenant,i.gateway,i.generation,i.handle) WHERE i.n={n}) THEN RAISE EXCEPTION 'premature arrival edge'; END IF; END $$;"""
    elif step == 4:
        check = f"""SET ROLE contour_owner;
DO $$ DECLARE proof uuid; wrong_proof uuid; root text; delta bigint; result bytea; BEGIN
 SELECT p.proof_id,convert_from(i.receiver_raw,'UTF8')::jsonb->>'local_root',u.used_bytes-c.before_used,c.edge
 INTO STRICT proof,root,delta,result
 FROM arrival_inputs i JOIN arrival_checks c ON c.n=i.n AND c.step=4
 JOIN contour.origin_logical_usage u ON u.tenant_id=i.tenant
 JOIN contour.origin_proofs p ON (p.tenant_id,p.collector_id,p.batch_id,p.record_id)=(i.tenant,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'collector_id')::uuid,(convert_from(i.observer_raw,'UTF8')::jsonb->>'batch_id')::uuid,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'record_id')::uuid)
 WHERE i.n={n};
 SELECT p.proof_id INTO STRICT wrong_proof FROM arrival_inputs i JOIN contour.origin_proofs p
 ON (p.tenant_id,p.collector_id,p.batch_id,p.record_id)=(i.tenant,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'collector_id')::uuid,(convert_from(i.observer_raw,'UTF8')::jsonb->>'batch_id')::uuid,(convert_from(i.observer_raw,'UTF8')::jsonb->'binding'->>'record_id')::uuid)
 WHERE i.n=CASE WHEN {n}=24 THEN 1 ELSE {n}+1 END;
 IF wrong_proof=proof THEN RAISE EXCEPTION 'arrival distinct proof missing'; END IF;
 IF result IS NULL OR pg_temp.arrival_edge_matches({n},proof,root,delta) IS NOT TRUE OR
    (SELECT count(*) FROM contour.causal_resolved_edges e JOIN arrival_inputs i ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(i.tenant,i.gateway,i.generation,i.handle) WHERE i.n={n} AND e.canonical_edge=result)<>1
 THEN RAISE EXCEPTION 'arrival edge missing or provenance mismatch'; END IF;
 IF pg_temp.arrival_edge_matches({n},wrong_proof,root,delta) IS NOT FALSE
 OR pg_temp.arrival_edge_matches({n},proof,repeat('f',32),delta) IS NOT FALSE
 OR pg_temp.arrival_edge_matches({n},proof,root,delta+1) IS NOT FALSE
 THEN RAISE EXCEPTION 'arrival mismatched expectation accepted'; END IF;
END $$;
RESET ROLE;"""
    else:
        check = f"""DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM arrival_checks c JOIN arrival_checks first ON first.n=c.n AND first.step=4 JOIN arrival_inputs i ON i.n=c.n JOIN contour.origin_logical_usage u ON u.tenant_id=i.tenant WHERE c.n={n} AND c.step=5 AND c.edge=first.edge AND c.before_used=u.used_bytes) THEN RAISE EXCEPTION 'arrival retry changed'; END IF; END $$;"""
    return prefix + '\n' + check
