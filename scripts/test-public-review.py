"""Public review provenance using the real human identity and PostgreSQL TLS fixture.

Call after the public comparison fixture has created comparison 701, with the
operation selected by that fixture. Existing review TLS logins must exist.
"""
import json
from pathlib import Path
import subprocess

ITEM = '00000000-0000-0000-0000-000000000001'
def uid(number): return '00000000-0000-0000-0000-%012x' % number

def run_cases(execute, port, directory, environment, normal, operation):
    for role in ['writer', 'reader']:
        execute('GRANT contour_comparison_reader TO contour_review_%s_tls' % role)
    target = json.loads(subprocess.check_output(['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'], text=True, timeout=15))['target_directory']
    probe = Path(target) / 'debug/examples/public_review_probe'
    def check(wanted='Stored', number=820, mode='store', comparison=701, candidate=510, credential=normal, scope=None, expected=uid(1800)):
        result = subprocess.run([str(probe), str(port), str(directory / 'ca.crt'), *(scope or [ITEM] * 4), operation, uid(number), uid(number + 1000) if mode == 'approve' else uid(comparison), uid(candidate), expected, ITEM, '1', mode, wanted, '10000', '0'], input='\n', text=True, capture_output=True, timeout=15, env=dict(environment, CONTOUR_FIXTURE_ID_TOKEN=str(credential)))
        assert result.returncode == 0 and not result.stderr, 'public review expected %s: %s' % (wanted, result.stdout.strip())
        return json.loads(result.stdout)['value']
    first = check()
    assert first['candidate'] == uid(510) and first['comparison'] == uid(701)
    assert first['creator'] == ITEM and first['status'] == 'Pending'
    assert check('Duplicate') == first
    assert check('Read', mode='read') == first
    check('Conflict', number=821, candidate=500)
    check('NotFound', number=822, comparison=600)
    for mode in ['store', 'read', 'approve']:
        check('Forbidden', mode=mode, scope=[uid(2), ITEM, ITEM, ITEM])
    execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=false')
    try:
        for mode in ['store', 'read', 'approve']: check('Forbidden', mode=mode)
    finally:
        execute('SET ROLE contour_human_provisioner; UPDATE contour.human_actors SET enabled=true')
    approved = check('Decided', mode='approve')
    assert approved['candidate'] == uid(510) and approved['actor'] == ITEM and approved['event'] == uid(1820)
    assert check('Duplicate', mode='approve') == approved
    assert check('Read', mode='read') == approved
    assert execute("SELECT count(*) FROM contour.review_decisions WHERE review_id='%s' AND approval_event_id='%s'" % (uid(820), uid(1820))) == '1'
    print('Public review exact right import, fresh authorization, and approval provenance passed.')
