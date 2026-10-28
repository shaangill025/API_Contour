"""Public comparison provenance, selection and transaction fault fixtures."""
import json
from pathlib import Path
import queue
import runpy
import socket
import subprocess
import threading

ITEM = '00000000-0000-0000-0000-000000000001'
OTHER = '00000000-0000-0000-0000-000000000002'
ROOT = Path(__file__).resolve().parents[1]

def ident(n): return '00000000-0000-0000-0000-%012x' % n

def run_cases(execute, port, directory, environment, normal, token, holder, wait_for, check, source, target, operation):
    comparison_probe = Path(target) / 'debug/examples/comparison_store_probe'
    review_probe = Path(target) / 'debug/examples/review_store_probe'
    def args(wanted, number, left=('declared', 500), right=('declared', 510), mode='public', via=None, control=0):
        return [str(comparison_probe), str(via or port), str(directory / 'ca.crt'), *([ITEM]*4),
                operation, ident(number), left[0], ident(left[1]), right[0], ident(right[1]),
                mode, wanted, '10000', str(control)]
    env = dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(normal))
    def compare(wanted, number, left=('declared',500), right=('declared',510), mode='public', via=None):
        result = subprocess.run(args(wanted, number, left, right, mode, via), input='\n', text=True,
                                capture_output=True, timeout=15, env=env)
        assert result.returncode == 0 and result.stdout.startswith('{') and not result.stderr, 'public comparison expected ' + wanted + ': ' + result.stdout.strip()
        return json.loads(result.stdout)
    # A real review approval must lead back to the precise public right-side import.
    version = execute("SELECT version_id FROM contour.public_declared_members WHERE contract_id='%s' AND operation_id='%s'" % (ident(510), operation))
    second, _ = token(subject='second-user')
    def review(mode, wanted, credential):
        comparison_or_event = ident(700) if mode == 'store' else ident(1800)
        result = subprocess.run([str(review_probe), str(port), str(directory / 'ca.crt'), *([ITEM]*4),
                                 operation, ident(800), comparison_or_event, version, '-', OTHER, '1',
                                 mode, wanted, '10000', '0'], input='\n', text=True, capture_output=True,
                                timeout=15, env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential)))
        assert result.returncode == 0 and result.stdout.startswith('{') and not result.stderr, 'public provenance review: ' + result.stdout.strip()
        return json.loads(result.stdout)['value']
    review('store', 'Stored', normal)
    decision = review('approve', 'Decided', second)
    assert decision['event'] == ident(1800)
    approved = compare('Stored', 701, left=('approved',1800))['value']
    assert approved['public_inputs'][0] == ['approved', ident(1800)]
    assert execute("SELECT declared_contract_id FROM contour.public_comparison_inputs WHERE comparison_id='%s' AND side='left'" % ident(701)) == ident(510)
    assert compare('Read', 701, mode='public-read')['value'] == approved
    assert compare('Duplicate', 701, left=('approved',1800))['value'] == approved
    # Event 1610 arose from the legacy projection-1 comparison and has no public provenance.
    compare('NotFound', 702, left=('approved',1610))
    # Distinct members for the same operation are deliberately ambiguous, regardless of selectors.
    schema = {'type': 'string'}
    def put_import(number, request_media=None, response_media='application/json'):
        operation_spec = {'responses': {'200': {'content': {response_media: {'schema': schema}}}}}
        if request_media:
            operation_spec['requestBody'] = {'content': {request_media: {'schema': schema}}}
        source.write_text(json.dumps({'openapi':'3.0.3', 'paths': {'/source': {'post': operation_spec}}}))
        check('Stored', number=number)
    source.write_text(json.dumps({'openapi':'3.0.3','paths':{'/source':{'post':{'responses':{
        '200':{'content':{'application/json':{'schema':schema}}},
        '201':{'content':{'application/json':{'schema':schema}}}}}}}}))
    check('Stored', number=540)
    put_import(541, response_media='text/plain')
    source.write_text(json.dumps({'openapi':'3.0.3','paths':{'/source':{'post':{'responses':{
        '201':{'content':{'application/json':{'schema':schema}}}}}}}}))
    check('Stored', number=542)
    assert execute("SELECT count(*) FROM contour.public_declared_members WHERE contract_id='%s' AND operation_id='%s'" % (ident(540), operation)) == '2'
    compare('Conflict', 703, right=('declared',540))
    compare('Conflict', 704, right=('declared',541))
    compare('Conflict', 705, right=('declared',542))
    for number in (703,704,705):
        assert execute("SELECT count(*) FROM contour.comparisons WHERE comparison_id='%s'" % ident(number)) == '0'
    # Commit reply loss and post-commit cleanup retain retry and read semantics.
    CommitProxy = runpy.run_path(str(ROOT / 'scripts/test-postgres-recovery.py'))['CommitProxy']
    for number, fault, wanted in [(706,'drop','OutcomeUnknown'), (707,'cleanup','Stored')]:
        proxy = CommitProxy(port, directory, fault)
        try:
            result = compare(wanted, number, via=proxy.port)
            proxy.finish()
            assert not result['reusable']
        finally: proxy.close()
        retry = compare('Duplicate', number)['value']
        assert compare('Read', number, mode='public-read')['value'] == retry
        if fault == 'cleanup': assert result['value'] == retry
    EofRelay = runpy.run_path(str(ROOT / 'scripts/test-declared-store.py'))['EofRelay']
    with holder('DO $$ BEGIN PERFORM 1 FROM contour.human_service_roles FOR UPDATE; END $$') as release:
        relay = EofRelay(port)
        control = socket.socket(); control.bind(('127.0.0.1',0)); control.listen(1); control.settimeout(3)
        process = None
        try:
            process = subprocess.Popen(args('Invalidated', 708, mode='cancel-public', via=relay.port, control=control.getsockname()[1]),
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
            output = queue.Queue()
            reader = threading.Thread(target=lambda: output.put(process.stdout.readline()), daemon=True); reader.start()
            peer, _ = control.accept()
            with peer:
                wait_for("SELECT count(*) FROM pg_stat_activity WHERE usename='contour_comparison_writer_tls' AND wait_event_type='Lock' AND query LIKE '%human_service_roles%'", '1')
                assert not relay.eof.is_set(); peer.sendall(b'C')
            line = output.get(timeout=15)
            assert line.startswith('{')
            receipt = json.loads(line)
            assert receipt['outcome'] == 'Invalidated' and not receipt['reusable']
            assert process.poll() is None
            relay.finish(); release()
            out, err = process.communicate('\n', timeout=3)
            assert process.returncode == 0 and not out and not err
            reader.join(2)
        finally:
            if process:
                if process.poll() is None: process.kill(); process.wait(timeout=3)
                for pipe in [process.stdin,process.stdout,process.stderr]: pipe.close()
            control.close(); relay.close()
    assert execute("SELECT count(*) FROM contour.comparisons WHERE comparison_id='%s'" % ident(708)) == '0'
    print('Public comparison provenance, ambiguity, selector/media, COMMIT faults and cancellation EOF passed.')
