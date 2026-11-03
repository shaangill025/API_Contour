"""Disposable admin PostgreSQL fault fixture; caller provides SQL executor.

Starts on a disposable normal schema-14 database. No Docker, listeners, or
credentials are managed here. Never run against an operator's persistent DB.
"""
import json
import tempfile
from pathlib import Path
from unittest import mock

from deploy.local import capture_profiles
from deploy.pilot import origin_credentials, origin_enrollment, origin_enrollment_fixture, origin_logins, origin_schema, origin_setup, origin_setup_state


def run_cases(execute, ca_cert=None, ca_key=None, authenticate=None, sensitive_execute=None, wrong_database_execute=None, enrollment=False):
    if type(enrollment) is not bool or (enrollment and authenticate is None):
        raise ValueError('enrollment fixture requires authentication callbacks')
    if authenticate is not None and (ca_cert is None or ca_key is None or not callable(authenticate) or not callable(sensitive_execute)):
        raise ValueError('authentication fixture requires both synthetic CA paths')
    if (ca_cert is None) != (ca_key is None):
        raise ValueError('both synthetic CA paths are required')
    if origin_setup._ledger(execute) != 14 or origin_setup._groups(execute) != origin_setup_state.ABSENT:
        raise AssertionError('fixture requires untouched schema 14')
    for n in (15,16,17):
        if origin_setup._stage_objects(execute,n) != origin_setup_state.ABSENT:
            raise AssertionError('opt-in artifacts already exist')
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)/'origin-pilot'; directory.mkdir(mode=0o700)
        base = capture_profiles.ORIGIN_PILOT
        slots=tuple(slot._replace(leaf_der=directory/('replica'+str(index))/'client.crt.der')
                    for index,slot in enumerate(base.origins,1))
        profile = base._replace(state=directory,capture=base.capture._replace(capture=directory/'capture'),origins=slots)
        with mock.patch.object(capture_profiles, 'ORIGIN_PILOT', profile):
            if wrong_database_execute is not None:
                calls=[]
                def wrong_database(sql):
                    calls.append(sql)
                    return wrong_database_execute(sql)
                try: origin_setup.prepare_schema(profile,psql=wrong_database)
                except RuntimeError as error:
                    if str(error)!='wrong local database': raise
                else: raise AssertionError('wrong database was accepted')
                if calls != ['SELECT pg_catalog.current_database()::text;'] or (directory/'setup.json').exists():
                    raise AssertionError('wrong database performed setup work')
            # Actual group transaction commits, then the caller loses its ACK.
            def lost_groups(sql):
                output = execute(sql)
                if 'CREATE ROLE contour_v2_ingress NOLOGIN' in sql: raise RuntimeError('lost group ack')
                return output
            try: origin_setup.prepare_schema(profile, psql=lost_groups)
            except RuntimeError as e:
                if str(e) != 'lost group ack': raise
            else: raise AssertionError('expected lost ACK')
            if origin_setup._groups(execute) != origin_setup_state.EXACT or origin_setup._ledger(execute) != 14:
                raise AssertionError('group commit or default ledger mismatch')
            # Actual migration 15 executes with ROLLBACK before its commit.
            def rollback_15(sql):
                if 'CREATE TABLE contour.origin_lifecycles' in sql:
                    execute(sql.rsplit('COMMIT;',1)[0] + 'ROLLBACK;')
                    raise RuntimeError('before migration commit')
                return execute(sql)
            try: origin_setup.prepare_schema(profile, psql=rollback_15)
            except RuntimeError as e:
                if str(e) != 'before migration commit': raise
            else: raise AssertionError('expected rollback')
            if origin_setup._ledger(execute) != 14 or origin_setup._stage_objects(execute,15) != origin_setup_state.ABSENT:
                raise AssertionError('rollback left schema state')
            # Commit migration 15, lose ACK, then resume without duplicate DDL.
            def lost_15(sql):
                output = execute(sql)
                if 'CREATE TABLE contour.origin_lifecycles' in sql: raise RuntimeError('lost migration ack')
                return output
            try: origin_setup.prepare_schema(profile, psql=lost_15)
            except RuntimeError as e:
                if str(e) != 'lost migration ack': raise
            else: raise AssertionError('expected migration ACK loss')
            if origin_setup._ledger(execute) != 15: raise AssertionError('migration did not commit')

            def verify_intermediate(version):
                if not origin_setup._partial_guards(execute,version,version):
                    raise AssertionError('intermediate reference rejected')
                mutations = [
                    'GRANT SELECT ON contour.origin_lifecycles TO contour_runtime;',
                    'GRANT SELECT (lifecycle_id) ON contour.origin_lifecycles TO contour_runtime;',
                    'CREATE POLICY unexpected_read ON contour.origin_lifecycles TO contour_runtime USING (true);',
                    'ALTER FUNCTION contour.enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea) SECURITY INVOKER;',
                ]
                if version == 16:
                    mutations.extend([
                        'REVOKE EXECUTE ON FUNCTION contour.guard_collector(uuid,uuid) FROM contour_v2_ingress;',
                        'GRANT EXECUTE ON FUNCTION contour.guard_collector(uuid,uuid) TO contour_catalog_reader;',
                        'GRANT CREATE ON SCHEMA contour TO contour_runtime;',
                    ])
                    mutations.append('DROP POLICY ingestion_v1_only ON contour.ingestion_batches; CREATE POLICY ingestion_v1_only ON contour.ingestion_batches AS RESTRICTIVE FOR INSERT TO contour_ingestion WITH CHECK (true);')
                for mutation in mutations:
                    def changed(sql): return execute('BEGIN; '+mutation+sql+' ROLLBACK;')
                    if origin_setup._partial_guards(changed,version,version):
                        raise AssertionError('intermediate catalog drift accepted')
            verify_intermediate(15)
            def lost_16(sql):
                output = execute(sql)
                if 'CREATE TABLE contour.ingestion_v2_metadata' in sql: raise RuntimeError('lost migration 16 ack')
                return output
            try: origin_setup.prepare_schema(profile, psql=lost_16)
            except RuntimeError as e:
                if str(e) != 'lost migration 16 ack': raise
            else: raise AssertionError('expected migration 16 ACK loss')
            if origin_setup._ledger(execute) != 16: raise AssertionError('migration 16 did not commit')
            verify_intermediate(16)
            result = origin_setup.prepare_schema(profile, psql=execute)
            if result != {'schema_ready': True, 'pilot_ready': False}: raise AssertionError('incorrect status')
            if origin_setup._ledger(execute) != 17: raise AssertionError('schema not completed')
            origin_schema.require_ready(execute)
            if origin_setup.prepare_schema(profile, psql=execute) != result: raise AssertionError('restart failed')
            # Rolled-back role drift must be refused by the actual group query.
            def role_drift(sql):
                if sql.startswith('SELECT CASE WHEN count(*)=0'):
                    return execute('BEGIN; ALTER ROLE contour_v2_ingress LOGIN; '+sql+' ROLLBACK;')
                return execute(sql)
            if origin_setup.Groups(role_drift).inspect() != origin_setup_state.DRIFT:
                raise AssertionError('role drift accepted')
            # The real database supplies partial/unknown ledger views, but the
            # mutations are rolled back on that same disposable connection.
            for suffix in ('DELETE FROM contour.schema_migrations WHERE version>15;',
                           'INSERT INTO contour.schema_migrations(version) VALUES (18);'):
                raw = execute('BEGIN; '+suffix+' SELECT version FROM contour.schema_migrations ORDER BY version; ROLLBACK;')
                if suffix.startswith('INSERT'):
                    try: origin_setup._ledger(lambda _: raw)
                    except RuntimeError: pass
                    else: raise AssertionError('unknown ledger accepted')
                elif origin_setup._ledger(lambda _: raw) != 15:
                    raise AssertionError('partial ledger view mismatch')
            if ca_cert is not None:
                # Keep the same actual schema, profile, and durable journal.
                # Lose only the acknowledgment after the real bundle was made.
                real_apply = origin_credentials.Credentials.apply
                def lost_credentials_ack(operator):
                    real_apply(operator)
                    raise RuntimeError('lost credentials ack')
                with mock.patch.object(origin_credentials.Credentials, 'apply', lost_credentials_ack):
                    try: origin_setup.prepare_credentials(profile, ca_cert, ca_key, psql=execute)
                    except RuntimeError as error:
                        if str(error) != 'lost credentials ack': raise
                    else: raise AssertionError('expected credentials ACK loss')
                pending = json.loads((directory/'setup.json').read_bytes())
                if pending['pending'] != 'credentials' or pending['completed'] != len(origin_setup_state.SCHEMA_PHASES):
                    raise AssertionError('credential intent not retained')
                credential = origin_credentials.Credentials(profile,ca_cert,ca_key)
                if credential.inspect() != origin_setup_state.EXACT:
                    raise AssertionError('credential bundle not exact after ACK loss')
                identity = credential.commitment()
                expected = {'schema_ready': True, 'credentials_ready': True, 'pilot_ready': False}
                if origin_setup.prepare_credentials(profile,ca_cert,ca_key,psql=execute) != expected:
                    raise AssertionError('credential recovery status mismatch')
                if origin_setup.prepare_credentials(profile,ca_cert,ca_key,psql=execute) != expected:
                    raise AssertionError('credential restart status mismatch')
                if credential.commitment() != identity:
                    raise AssertionError('credential identity changed on recovery')
                final = json.loads((directory/'setup.json').read_bytes())
                if final['pending'] is not None or final['completed'] != len(origin_setup_state.CREDENTIAL_PHASES) or final['credential_digest'] != identity:
                    raise AssertionError('credential journal did not reconcile')
                if authenticate is not None:
                    def rollback_login(sql):
                        if 'CREATE ROLE contour_local_origin_ingress LOGIN' in sql:
                            sensitive_execute(sql.rsplit('COMMIT;',1)[0]+'ROLLBACK;')
                            raise RuntimeError('before login commit')
                        return execute(sql)
                    try: origin_setup.prepare_logins(profile,ca_cert,ca_key,psql=execute,sensitive_execute=rollback_login,authenticate=authenticate)
                    except RuntimeError as error:
                        if str(error)!='login provisioning failed; state retained': raise
                    else: raise AssertionError('expected login transaction rollback')
                    login = origin_logins.Logins(profile,execute,sensitive_execute,authenticate)
                    if login.inspect()!=origin_setup_state.ABSENT: raise AssertionError('rolled-back logins exist')
                    real_login_apply=origin_logins.Logins.apply
                    def lost_login_ack(operator):
                        real_login_apply(operator)
                        raise RuntimeError('lost login ack')
                    with mock.patch.object(origin_logins.Logins,'apply',lost_login_ack):
                        try: origin_setup.prepare_logins(profile,ca_cert,ca_key,psql=execute,sensitive_execute=sensitive_execute,authenticate=authenticate)
                        except RuntimeError as error:
                            if str(error)!='lost login ack': raise
                        else: raise AssertionError('expected login ACK loss')
                    if login.inspect()!=origin_setup_state.EXACT: raise AssertionError('committed login rejected')
                    pending=json.loads((directory/'setup.json').read_bytes())
                    if pending['pending']!='logins': raise AssertionError('login intent not retained')
                    login_ready={'schema_ready':True,'credentials_ready':True,'logins_ready':True,'pilot_ready':False}
                    if origin_setup.prepare_logins(profile,ca_cert,ca_key,psql=execute,sensitive_execute=sensitive_execute,authenticate=authenticate)!=login_ready:
                        raise AssertionError('login recovery status mismatch')
                    if origin_setup.prepare_logins(profile,ca_cert,ca_key,psql=execute,sensitive_execute=sensitive_execute,authenticate=authenticate)!=login_ready:
                        raise AssertionError('login restart status mismatch')
                    if credential.commitment()!=identity: raise AssertionError('login changed credentials')
                    for name,_,_ in origin_logins.ROLES:
                        if authenticate(name,'invalid-fixture-password') is not False:
                            raise AssertionError('wrong password not rejected')
                    mutations=(
                        'ALTER ROLE contour_local_origin_ingress SUPERUSER;',
                        'GRANT contour_ingestion TO contour_local_origin_ingress;',
                        'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH ADMIN TRUE;',
                        'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH INHERIT FALSE;',
                        'GRANT contour_origin_ingress TO contour_local_origin_ingress WITH SET FALSE;',
                        'GRANT CREATE ON SCHEMA contour TO contour_local_origin_ingress;',
                        'CREATE POLICY origin_fixture_policy ON contour.origin_lifecycles TO contour_local_origin_ingress USING (true);',
                        'GRANT CONNECT ON DATABASE contour_local TO contour_local_origin_ingress WITH GRANT OPTION;',
                        'REVOKE CONNECT ON DATABASE contour_local FROM contour_local_origin_worker;',
                        'CREATE ROLE origin_login_fixture NOLOGIN; GRANT contour_local_origin_ingress TO origin_login_fixture;',
                    )
                    for mutation in mutations:
                        def changed(sql): return execute('BEGIN; '+mutation+sql+' ROLLBACK;')
                        if origin_logins.Logins(profile,changed,sensitive_execute,authenticate).inspect()!=origin_setup_state.DRIFT:
                            raise AssertionError('login privilege drift accepted')
                    if enrollment:
                        def rollback_observer(sql):
                            if 'INSERT INTO contour.collectors' in sql:
                                execute(sql.rsplit('COMMIT;',1)[0]+'ROLLBACK;')
                                raise RuntimeError('observer rollback')
                            return execute(sql)
                        try:
                            origin_setup.prepare_enrollment(profile,ca_cert,ca_key,psql=rollback_observer,
                                sensitive_execute=sensitive_execute,authenticate=authenticate)
                        except RuntimeError as error:
                            if str(error)!='observer rollback': raise
                        else: raise AssertionError('expected observer rollback')
                        observer=origin_enrollment.Observer(profile,execute)
                        policy_before=observer.policy()
                        if policy_before is None or observer.inspect()!=origin_setup_state.ABSENT:
                            raise AssertionError('observer rollback state mismatch')
                        # Each wrapper lets the actual transaction commit, then
                        # drops its acknowledgment; the durable journal must
                        # reconcile the exact committed state without repetition.
                        cases=[('observer','INSERT INTO contour.collectors')]
                        for index,slot in enumerate(profile.origins,1):
                            cases += [(f'origin_{index}_target',"INSERT INTO contour.deployments VALUES ('"+profile.capture.collector+"'")]
                            # The target statement is identified by its fixed
                            # deployment ID; observer ID does not share it.
                            cases[-1]=(f'origin_{index}_target',slot.deployment)
                            cases += [(f'origin_{index}_lifecycle','SELECT contour.enroll_origin('),
                                      (f'origin_{index}_credential','SELECT contour.enroll_origin_credential('),
                                      (f'origin_{index}_grant','SELECT contour.grant_origin_observer(')]
                        for phase, token in cases:
                            def lost_enrollment_ack(sql):
                                if token in sql and ('INSERT INTO contour.deployments VALUES' in sql or 'SELECT contour.enroll_origin' in sql or 'SELECT contour.grant_origin_observer' in sql or 'INSERT INTO contour.collectors' in sql):
                                    execute(sql)
                                    raise RuntimeError('lost enrollment ack')
                                return execute(sql)
                            try:
                                origin_setup.prepare_enrollment(profile,ca_cert,ca_key,psql=lost_enrollment_ack,
                                    sensitive_execute=sensitive_execute,authenticate=authenticate)
                            except RuntimeError as error:
                                if str(error)!='lost enrollment ack': raise
                            else: raise AssertionError('expected enrollment ACK loss')
                            pending=json.loads((directory/'setup.json').read_bytes())
                            if pending['pending']!=phase: raise AssertionError('wrong pending enrollment phase')
                        result=origin_setup.prepare_enrollment(profile,ca_cert,ca_key,psql=execute,
                            sensitive_execute=sensitive_execute,authenticate=authenticate)
                        if not result['enrollment_prepared'] or not result['policy_current'] or result['pilot_ready']:
                            raise AssertionError('enrollment status mismatch')
                        if origin_setup.prepare_enrollment(profile,ca_cert,ca_key,psql=execute,
                            sensitive_execute=sensitive_execute,authenticate=authenticate)!=result:
                            raise AssertionError('enrollment restart mismatch')
                        if observer.policy()[0]!=policy_before[0]: raise AssertionError('initial policy was replaced')
                        origin_enrollment_fixture.check_signed_timestamp_negatives(profile)
                        origin_enrollment_fixture.check_signed_policy_negatives(profile)
                        origin_enrollment_fixture.check_registry_negatives(profile,execute)
                        credential.allow_observer_policy=True
                        if credential.commitment()!=identity:
                            raise AssertionError('enrollment changed credential identity')
    return 'origin schema preparation fault fixture passed'
