"""Disposable PG fixture hook for committed origin renewal; no connections created."""
import datetime
from deploy.local import capture_renew
from deploy.pilot import origin_credentials, origin_enrollment, origin_renewal, origin_setup


def run_cases(profile,ca_cert,ca_key,execute,sensitive_execute,authenticate):
    """Caller provides a fully enrolled, owned synthetic profile and real PG."""
    initial=origin_enrollment.Observer(profile,execute).policy()[0]
    before=origin_renewal.history(profile,execute)
    if before is None or before.count!=1 or before.initial!=initial:
        raise AssertionError('renewal fixture initial head unavailable')
    def lost_ack(sql):
        result=execute(sql)
        if 'INSERT INTO contour.policy_revisions' in sql and 'GET DIAGNOSTICS affected=ROW_COUNT' in sql:
            raise RuntimeError('fixture renewal acknowledgment lost')
        return result
    try:
        origin_setup.renew_enrolled(profile,ca_cert,ca_key,psql=lost_ack,
            sensitive_execute=sensitive_execute,authenticate=authenticate)
    except RuntimeError as error:
        if str(error)!='fixture renewal acknowledgment lost': raise
    else: raise AssertionError('renewal lost ACK not exercised')
    if not (profile.state/origin_renewal.PENDING).exists(): raise AssertionError('renewal journal absent')
    result=origin_setup.renew_enrolled(profile,ca_cert,ca_key,psql=execute,
        sensitive_execute=sensitive_execute,authenticate=authenticate)
    if result!={'renewal_reconciled':True,'policy_current':True,'pilot_ready':False}: raise AssertionError('renewal status mismatch')
    after=origin_renewal.history(profile,execute)
    if after.count!=2 or after.initial!=initial or after.head_policy['revision']!=2:
        raise AssertionError('renewal history mismatch')
    if origin_enrollment.Observer(profile,execute).policy()[0]!=initial:
        raise AssertionError('initial policy changed')
    if (profile.state/origin_renewal.PENDING).exists(): raise AssertionError('renewal journal retained')
    # Another contender based on the old head must fail without changing it.
    key=origin_credentials._file(profile.state/'capture/private/policy.key',16384)
    proposed=capture_renew.signed_policy(before.head_policy,key,datetime.datetime.now(datetime.timezone.utc),profile.capture)
    proposed_data=origin_renewal._valid(profile,proposed)
    try: origin_renewal._locked_cas(profile,execute,initial,before.head_policy,proposed,proposed_data,False)
    except RuntimeError: pass
    else: raise AssertionError('old-head contender accepted')
    if origin_renewal.history(profile,execute)!=after: raise AssertionError('old-head contender changed history')
    # Even if a buggy implementation accepts an expired proposal, rollback the
    # disposable transaction and fail the fixture rather than retaining it.
    expired=capture_renew.signed_policy(after.head_policy,key,datetime.datetime.now(datetime.timezone.utc)-datetime.timedelta(hours=1),profile.capture)
    expired_data=origin_renewal._valid(profile,expired)
    def rollback(sql): return execute(sql.rsplit('COMMIT;',1)[0]+'ROLLBACK;')
    try: origin_renewal._locked_cas(profile,rollback,after.head,after.head_policy,expired,expired_data,False)
    except RuntimeError: pass
    else: raise AssertionError('database accepted expired renewal proposal')
    if origin_renewal.history(profile,execute)!=after: raise AssertionError('expired proposal changed history')
    # Privileged fixture-only revocation is introduced in the same transaction
    # as the attempted CAS and always rolled back.
    tenant=origin_enrollment.Q(origin_enrollment.TENANT)
    collector=origin_enrollment.Q(profile.capture.collector)
    def revoked(sql):
        mutation=("DO $$ BEGIN PERFORM set_config('apicontour.tenant_id',"+tenant+
                  ",true); PERFORM contour.lock_collector("+tenant+","+collector+"); END $$; "
                  "UPDATE contour.collector_authorization SET enabled=false WHERE tenant_id="+tenant+" AND collector_id="+collector+"; ")
        return execute(sql.replace('BEGIN;','BEGIN; '+mutation,1).rsplit('COMMIT;',1)[0]+'ROLLBACK;')
    live=capture_renew.signed_policy(after.head_policy,key,datetime.datetime.now(datetime.timezone.utc),profile.capture)
    live_data=origin_renewal._valid(profile,live)
    try: origin_renewal._locked_cas(profile,revoked,after.head,after.head_policy,live,live_data,False)
    except RuntimeError: pass
    else: raise AssertionError('revoked observer accepted renewal')
    if origin_renewal.history(profile,execute)!=after: raise AssertionError('revocation fixture changed history')
    # Positive control: a live proposal on the exact unchanged head must pass
    # the same C-locked CAS, then roll back, so failures above cannot be
    # attributed to a generally broken N+1 setup.
    origin_renewal._locked_cas(profile,rollback,after.head,after.head_policy,live,live_data,False)
    if origin_renewal.history(profile,execute)!=after: raise AssertionError('positive control changed history')
    # Caller owns each transaction. A permanent probe table must disappear on
    # rollback; an inner history COMMIT would incorrectly persist it.
    def caller_transaction(sql):
        return execute('BEGIN; CREATE TABLE contour.origin_history_rollback_probe (x integer); '+sql+' ROLLBACK;')
    if origin_renewal.history(profile,caller_transaction)!=after:
        raise AssertionError('caller transaction history mismatch')
    if execute("SELECT (to_regclass('contour.origin_history_rollback_probe') IS NULL)::text;")!='true':
        raise AssertionError('history committed caller transaction')
    return 'origin renewal fault fixture passed'
