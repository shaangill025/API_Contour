"""Root-owned synthetic enrollment fixture helpers; no connections created."""
import json
import os
import tempfile
from deploy.local import capture_renew
from deploy.pilot import origin_credentials, origin_enrollment


def check_signed_timestamp_negatives(profile):
    """Sign malformed local timestamps with the fixture key and require refusal.

    The caller owns a disposable, already prepared profile. No production state
    is accepted as an input. The original fixture policy is restored afterwards.
    """
    observer=origin_enrollment.Observer(profile,lambda _:None)
    original,data=observer.policy()
    key=origin_credentials._file(profile.state/'capture/private/policy.key',16384)
    public=capture_renew.crypt('public',key,b'',profile=profile.capture,scratch=tempfile.gettempdir())
    path=observer.path
    variants=(data['issued_at'].replace('T',' ',1),data['issued_at'][:-1]+'000Z')
    for bad in variants:
        changed=dict(data,issued_at=bad)
        payload=json.dumps(changed,separators=(',',':')).encode()
        signature=capture_renew.crypt('sign',key,capture_renew.DOMAIN+payload,profile=profile.capture,scratch=tempfile.gettempdir())
        raw=json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=capture_renew.encoded(payload),
            signature_base64url=capture_renew.encoded(signature)),separators=(',',':')).encode()
        # Establish the signature and the broader legacy parser accept the test
        # input; the closed local timestamp rule is the reason for rejection.
        checked=capture_renew.checked_envelope(raw,public,profile.capture,tempfile.gettempdir())
        if checked['issued_at']!=bad: raise AssertionError('invalid fixture baseline')
        try:
            path.write_bytes(raw); os.chmod(path,0o600)
            try: observer.policy()
            except ValueError as error:
                if str(error)!='initial policy timestamp format': raise
            else: raise AssertionError('malformed signed timestamp accepted')
        finally:
            path.write_bytes(original); os.chmod(path,0o600)
    if observer.policy()[0]!=original: raise AssertionError('fixture policy not restored')
    return 'signed timestamp negatives passed'


def check_signed_policy_negatives(profile):
    """Exercise signed scope, revision and expiry using the synthetic signer."""
    import datetime
    from unittest import mock
    calls=[]
    observer=origin_enrollment.Observer(profile,lambda sql:calls.append(sql))
    original,data=observer.policy()
    key=origin_credentials._file(profile.state/'capture/private/policy.key',16384)
    public=capture_renew.crypt('public',key,b'',profile=profile.capture,scratch=tempfile.gettempdir())
    now=datetime.datetime.now(datetime.timezone.utc)
    stamp=lambda value:value.isoformat(timespec='microseconds').replace('+00:00','Z')
    variants=(('scope',dict(data,collector_id='00000000-0000-4000-8000-000000000999')),
              ('revision',dict(data,revision=2)),
              ('expiry',dict(data,issued_at=stamp(now-datetime.timedelta(minutes=20)),
                             expires_at=stamp(now-datetime.timedelta(minutes=10)))))
    for kind,changed in variants:
        payload=json.dumps(changed,separators=(',',':')).encode()
        signature=capture_renew.crypt('sign',key,capture_renew.DOMAIN+payload,profile=profile.capture,scratch=tempfile.gettempdir())
        # Verify the actual signature independently of fixed-scope validation.
        capture_renew.crypt('verify',public,capture_renew.DOMAIN+payload,signature,profile.capture,tempfile.gettempdir())
        raw=json.dumps(dict(key_id='local',signature_profile='ed25519-v1',payload_base64url=capture_renew.encoded(payload),
            signature_base64url=capture_renew.encoded(signature)),separators=(',',':')).encode()
        try:
            observer.path.write_bytes(raw); os.chmod(observer.path,0o600)
            if kind=='expiry':
                parsed=observer.policy()
                if parsed is None: raise AssertionError('expired signed policy unavailable')
                with mock.patch.object(observer,'_new_policy',side_effect=AssertionError('policy reissued')):
                    try: observer.apply()
                    except RuntimeError as error:
                        if str(error)!='initial observer policy not current; pending state retained': raise
                    else: raise AssertionError('expired policy accepted')
                if calls: raise AssertionError('expired policy reached database')
            else:
                try: observer.policy()
                except ValueError as error:
                    expected='policy scope' if kind=='scope' else 'initial policy revision drift'
                    if str(error)!=expected: raise AssertionError('signed policy failed for wrong reason') from None
                else: raise AssertionError('invalid signed policy accepted')
        finally:
            observer.path.write_bytes(original); os.chmod(observer.path,0o600)
    if observer.policy()[0]!=original: raise AssertionError('fixture policy not restored')
    return 'signed policy negatives passed'


def check_registry_negatives(profile, execute):
    """Rollback-isolated public revocation and labelled admin-corruption probes."""
    q=origin_enrollment.Q
    tenant,project,service,environment,collector,source,deployment,_,_=origin_enrollment._scope(profile)
    slot=profile.origins[0]
    lifecycle,credential,grant=map(q,(slot.lifecycle,slot.credential,slot.grant))
    observer=origin_enrollment.Observer(profile,execute)
    facts=[origin_enrollment.Fact(profile,execute,slot,kind) for kind in ('lifecycle','credential','grant')]
    if observer.inspect()!=origin_enrollment.journal.EXACT or any(f.inspect()!=origin_enrollment.journal.EXACT for f in facts):
        raise AssertionError('enrollment negative baseline unavailable')
    lock=f"DO $$ BEGIN PERFORM set_config('apicontour.tenant_id',{tenant},true); PERFORM contour.lock_collector({tenant},{collector}); END $$; "
    scope=f"tenant_id={tenant} AND collector_id={collector}"
    # Admin corruption is explicitly fixture-only, transactional and rolled back.
    corruptions=(
        lock+f"UPDATE contour.collector_authorization SET enabled=false WHERE {scope}; ",
        lock+f"INSERT INTO contour.policy_revisions SELECT tenant_id,collector_id,2,signed_envelope FROM contour.policy_revisions WHERE {scope} AND revision=1; UPDATE contour.collector_authorization SET active_revision=2 WHERE {scope}; ",
        lock+f"UPDATE contour.source_authorization SET parser_profiles=ARRAY['http_xml_v1'] WHERE {scope}; ",
    )
    for mutation in corruptions:
        def changed(sql): return execute('BEGIN; '+mutation+sql+' ROLLBACK;')
        if origin_enrollment.Observer(profile,changed).inspect()!=origin_enrollment.journal.DRIFT:
            raise AssertionError('observer authority drift accepted')
    # This extra row intentionally bypasses insert-only fact guards inside a
    # rollback transaction, solely to model unexpected additional authority.
    extra="""ALTER TABLE contour.origin_observer_grants DISABLE TRIGGER origin_insert_guard;
      ALTER TABLE contour.origin_observer_grants DISABLE TRIGGER origin_z_fact_epoch; """
    extra+=f"""INSERT INTO contour.origin_observer_grants
      (tenant_id,grant_id,lifecycle_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id,granted_at)
      SELECT tenant_id,'00000000-0000-4000-8000-000000000499',lifecycle_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id,clock_timestamp()
      FROM contour.origin_observer_grants WHERE tenant_id={tenant} AND grant_id={grant}; """
    def extra_grant(sql): return execute('BEGIN; '+extra+sql+' ROLLBACK;')
    if origin_enrollment.Fact(profile,extra_grant,slot,'grant').inspect()!=origin_enrollment.journal.DRIFT:
        raise AssertionError('extra origin grant accepted')
    # Exercise the granted public end_origin entrypoint. Each test uses a fresh
    # transaction because the Q gate deliberately forbids preheld locks.
    for kind,target in (('lifecycle_closed',lifecycle),('credential_revoked',credential),('grant_revoked',grant)):
        mutation=("SET LOCAL ROLE contour_admin; DO $$ BEGIN PERFORM set_config('apicontour.tenant_id',"+tenant+
                  ",true); PERFORM contour.end_origin("+tenant+","+q(kind)+","+target+"); END $$; RESET ROLE; ")
        for fact_kind in ('lifecycle','credential','grant'):
            def closed(sql): return execute('BEGIN; '+mutation+sql+' ROLLBACK;')
            if origin_enrollment.Fact(profile,closed,slot,fact_kind).inspect()!=origin_enrollment.journal.DRIFT:
                raise AssertionError('terminal origin fact accepted')
    # Constraints, not the inspector, reject a duplicate leaf and instance.
    for table,columns,select,trigger in (
        ('origin_credentials','tenant_id,credential_id,lifecycle_id,leaf_sha256,enrolled_at',
         "tenant_id,'00000000-0000-4000-8000-000000000498',lifecycle_id,leaf_sha256,clock_timestamp()",'credential_id='+credential),
        ('origin_lifecycles','tenant_id,lifecycle_id,project_id,service_id,environment_id,deployment_id,instance_id,platform_kind,platform_evidence_sha256,enrolled_at',
         "tenant_id,'00000000-0000-4000-8000-000000000497',project_id,service_id,environment_id,deployment_id,instance_id,platform_kind,platform_evidence_sha256,clock_timestamp()",'lifecycle_id='+lifecycle),
    ):
        mutation=(f'BEGIN; ALTER TABLE contour.{table} DISABLE TRIGGER origin_insert_guard; '
                  f'ALTER TABLE contour.{table} DISABLE TRIGGER origin_z_fact_epoch; '
                  f"DO $$ BEGIN BEGIN INSERT INTO contour.{table} ({columns}) SELECT {select} FROM contour.{table} WHERE tenant_id={tenant} AND {trigger}; "
                  "RAISE EXCEPTION 'expected unique violation'; EXCEPTION WHEN unique_violation THEN NULL; END; END $$; SELECT true::text; ROLLBACK;")
        if execute(mutation)!='true': raise AssertionError('conflict constraint probe failed')
    if observer.inspect()!=origin_enrollment.journal.EXACT or any(f.inspect()!=origin_enrollment.journal.EXACT for f in facts):
        raise AssertionError('registry fixture did not restore baseline')
    return 'registry negatives passed'
