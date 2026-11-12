"""Closed operator-only origin21 onboarding; no listener or CLI entrypoint.

Callers must supply a local admin SQL callback, a distinct sensitive executor
that disables statement and error-statement logging before SQL is parsed, and
a real password-authentication callback returning a literal boolean. They must
not log SQL, envelopes, credentials, traces or callback exceptions.
"""
import json
import os
from deploy.local import (origin21_configs, origin21_credentials, origin21_enrollment, origin21_evidence,
    origin21_logins, origin21_profile, origin21_renewal, origin21_schema, origin21_state)

LOCK='SELECT pg_catalog.pg_advisory_xact_lock(1330792272, 1);'
MIGRATIONS={v:f'db/opt-in-migrations/{v:04d}_'+name+'.sql' for v,name in (
    (15,'origin_lifecycle'),(16,'v2_unattributed'),(17,'origin_proofs'),
    (18,'causal_runtime_registry'),(19,'causal_sessions'),(20,'causal_inbox'),(21,'origin_admission'))}


def _ledger(psql):
    raw=psql('SELECT version FROM contour.schema_migrations ORDER BY version;')
    try: versions=[int(item) for item in raw.splitlines()]
    except (ValueError,AttributeError): raise RuntimeError('invalid schema ledger') from None
    if versions not in [list(range(1,n+1)) for n in range(14,22)]: raise RuntimeError('unexpected schema ledger')
    return len(versions)


def _phase(stage,context):
    return 'enrolled' if stage==21 and context['login'] else 'pre'


def _check(psql,stage,phase):
    try:
        origin21_schema.require_ready(list(range(1,stage+1)),psql,stage=stage,phase=phase)
        return True
    except (ValueError,RuntimeError): return False


def _guard(stage,phase):
    expected=origin21_schema.require_reference(stage,phase)
    literal=json.dumps(expected,sort_keys=True,separators=(',',':')).replace("'","''")
    query=origin21_schema.inventory_sql().rstrip().removesuffix(';')
    tag='$origin21_guard$'
    if tag in query or tag in literal: raise ValueError('invalid reference delimiter')
    return ("DO "+tag+" BEGIN IF pg_catalog.current_database()<>'contour_local' OR "
            f"(SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,{stage})) OR NOT (({query})::jsonb='{literal}'::jsonb) "
            "THEN RAISE EXCEPTION 'origin21 schema precondition failed'; END IF; END "+tag+";")


class Groups:
    def __init__(self,psql,context): self.psql,self.context=psql,context
    def inspect(self):
        try: stage=_ledger(self.psql)
        except RuntimeError: return origin21_state.DRIFT
        if stage==14:
            if _check(self.psql,14,'groups'): return origin21_state.EXACT
            return origin21_state.ABSENT if _check(self.psql,14,'pre') else origin21_state.DRIFT
        return origin21_state.EXACT if _check(self.psql,stage,_phase(stage,self.context)) else origin21_state.DRIFT
    def apply(self):
        sql=('BEGIN; '+LOCK+_guard(14,'pre')+
             'CREATE ROLE contour_v2_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; '
             'CREATE ROLE contour_origin_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION; COMMIT;')
        self.psql(sql)


class Migration:
    def __init__(self,psql,version,source,context): self.psql,self.version,self.source,self.context=psql,version,source,context
    def inspect(self):
        try: stage=_ledger(self.psql)
        except RuntimeError: return origin21_state.DRIFT
        if stage>=self.version:
            return origin21_state.EXACT if _check(self.psql,stage,_phase(stage,self.context)) else origin21_state.DRIFT
        if stage==self.version-1:
            phase='groups' if stage==14 else 'pre'
            return origin21_state.ABSENT if _check(self.psql,stage,phase) else origin21_state.DRIFT
        return origin21_state.DRIFT
    def apply(self):
        text=self.source.decode('utf-8')
        if text.count('BEGIN;')!=1 or text.count('COMMIT;')!=1: raise ValueError('migration transaction shape')
        stage=self.version-1; phase='groups' if stage==14 else 'pre'
        self.psql(text.replace('BEGIN;', 'BEGIN; LOCK TABLE contour.schema_migrations IN ACCESS EXCLUSIVE MODE; '+_guard(stage,phase),1))


class VerifiedLogins(origin21_logins.Logins):
    def __init__(self,profile,psql,sensitive_execute,authenticate,context):
        super().__init__(profile,psql,sensitive_execute,authenticate)
        self.context=context
    def inspect(self):
        result=super().inspect()
        if result==origin21_state.EXACT:
            if not _check(self.psql,21,'enrolled'): return origin21_state.DRIFT
            self.context['login']=True
        return result


def prepare_identities(*, selected=origin21_profile.STATIC,qualification=None):
    """Create/reconcile only the fixed credential bundle; never enroll or start."""
    if selected is origin21_profile.MANAGED:
        from deploy.local.origin21_managed_qualification import require_matching
        require_matching(qualification)
    elif qualification is not None: raise ValueError('unexpected qualification')
    for stage in range(14,22): origin21_schema.require_reference(stage,'pre')
    origin21_schema.require_reference(14,'groups'); origin21_schema.require_reference(21,'enrolled')
    origin21_profile.require_context(selected)
    snapshot=origin21_state._source_snapshot() if selected is origin21_profile.STATIC else origin21_state._source_snapshot(selected)
    root=selected.profile.state.parent
    credentials=origin21_credentials.Credentials(selected.profile,root/'ca.crt',root/'ca.key')
    origin21_state.run(selected.profile,{'credentials':credentials},snapshot=snapshot,identities_only=True)
    return {'identities_reconciled':True,'enrolled':False,'pilot_ready':False}


def prepare(*, psql=None, sensitive_execute=None, authenticate=None, inspect_slot=None, expected_evidence, renew=False, check_only=False, selected=origin21_profile.STATIC, transport=None):
    """Reconcile the fixed journal. Never returns a runtime readiness claim."""
    origin21_profile.require_context(selected)
    if selected is origin21_profile.MANAGED or selected is origin21_profile.HUMAN:
        from deploy.local import origin21_transport
        if type(transport) is not origin21_transport.ManagedTransport or transport._selected is not selected or inspect_slot is not None or any(x is not None for x in (psql,sensitive_execute,authenticate)): raise ValueError('managed transport required')
        from deploy.local import origin21_products
        inspect_slot=lambda index:origin21_products.inspect_slot(index,selected=selected,**({'qualification':transport.qualification} if transport.qualification is not None else {}))
        transport.verify()
        psql,sensitive_execute,authenticate=transport.admin,transport.sensitive,transport.authenticate
    elif transport is not None: raise ValueError('unexpected managed transport')
    if not all(callable(x) for x in (psql,sensitive_execute,authenticate,inspect_slot)) or sensitive_execute is psql or type(renew) is not bool or type(check_only) is not bool or (renew and check_only) or type(expected_evidence) is not tuple or len(expected_evidence)!=2 or any(type(x) is not bytes or len(x)!=32 for x in expected_evidence):
        raise ValueError('separate trusted callbacks required')
    # All references must be installed before database calls, state or credentials.
    for stage in range(14,22): origin21_schema.require_reference(stage,'pre')
    origin21_schema.require_reference(14,'groups'); origin21_schema.require_reference(21,'enrolled')
    def checked_callback(callback):
        def execute(sql):
            try: result=callback(sql)
            except Exception: raise RuntimeError('origin21 database operation failed') from None
            if not isinstance(result,str) or len(result)>8*1024*1024: raise RuntimeError('invalid origin21 database result')
            return result
        return execute
    psql=checked_callback(psql); sensitive_execute=checked_callback(sensitive_execute)
    if psql('SELECT pg_catalog.current_database()::text;')!='contour_local': raise RuntimeError('wrong local database')
    snapshot=origin21_state._source_snapshot() if selected is origin21_profile.STATIC else origin21_state._source_snapshot(selected)
    profile=selected.profile; bound=selected.bound; context={'login':False}
    root=profile.state.parent
    credential=origin21_credentials.Credentials(profile,root/'ca.crt',root/'ca.key')
    login=VerifiedLogins(profile,psql,sensitive_execute,authenticate,context)
    observer=origin21_enrollment.Observer(bound,sensitive_execute)
    evidence=origin21_evidence.Evidence(profile,inspect_slot,expected_evidence)
    operations={'groups':Groups(psql,context), 'credentials':credential, 'logins':login,
                'observer':observer, 'operator_evidence':evidence, 'runtime_configs':origin21_configs.Configs(profile)}
    operations.update({'migration_'+str(v):Migration(psql,v,snapshot[MIGRATIONS[v]],context) for v in MIGRATIONS})
    for number,slot in enumerate(bound.origins,1):
        operations[f'origin_{number}_target']=origin21_enrollment.Target(bound,psql,slot)
        for kind in ('lifecycle','credential','grant'):
            operations[f'origin_{number}_{kind}']=origin21_enrollment.Fact(bound,psql,slot,kind,evidence.slot_digest)
    def set_context(current, *, checked_evidence=False):
        n=current['completed']; pending=current['pending']
        if n>origin21_state.PHASES.index('observer') or pending=='observer':
            if observer.policy() is not None: credential.allow_observer_policy=True
            allowed,renewal=origin21_renewal.artifacts(bound)
            if renewal is not None and not renew: raise ValueError('origin21 renewal requires reconciliation')
            credential.allow_renewal_artifacts=frozenset(allowed)
        if n>origin21_state.PHASES.index('operator_evidence') or pending=='operator_evidence':
            if checked_evidence or evidence.inspect()==origin21_state.EXACT: credential.allow_operator_evidence=True
            elif os.path.lexists(evidence.path): raise ValueError('operator evidence drift')
        if n>origin21_state.PHASES.index('runtime_configs') or pending=='runtime_configs':
            credential.allow_runtime_configs=origin21_configs.Configs(profile).inspect()==origin21_state.EXACT
        if n>origin21_state.PHASES.index('logins') or pending=='logins':
            if credential.inspect()!=origin21_state.EXACT or credential.commitment()!=current['credential_digest']:
                raise ValueError('login credential commitment drift')
            status=login.inspect()
            if status==origin21_state.EXACT: context['login']=True
            elif status!=origin21_state.ABSENT or n>origin21_state.PHASES.index('logins'): raise ValueError('login context drift')
    def completed(check_source):
        if not renew: return None
        executor=transport.sensitive if selected is not origin21_profile.STATIC else sensitive_execute
        return origin21_renewal.renew_locked(bound,executor,check_source=check_source)
    origin21_state.run(profile,operations,snapshot=snapshot,set_context=set_context,after_complete=completed,require_complete=(renew or check_only), completed_check_only=check_only)
    return {'setup_reconciled':True,'pilot_ready':False}
