"""Closed v21 policy CAS, preserving collector lock and exact history guards.

Executor receives sensitive SQL and must disable statement/error logging.
"""
from deploy.local import capture_renew, origin21_profile
p = capture_renew.p


def locked_transaction(base_bytes,base_revision,proposal,proposal_revision,issued,expires,preflight,profile=None, *, executor=None):
    q=p.base.sql_quote
    selected=origin21_profile.context_for_capture(profile)
    if selected is origin21_profile.MANAGED:
        from deploy.local import origin21_transport
        owner=getattr(executor,'__self__',None)
        if type(owner) is not origin21_transport.ManagedTransport or getattr(executor,'__func__',None) is not origin21_transport.ManagedTransport.sensitive:
            raise ValueError('managed sensitive transport required')
        owner.verify()
    t,c,src,project,service,env,dep,instance,nonce=map(q,[p.TENANT,profile.collector,profile.source,p.PROJECT,p.SERVICE,p.ENVIRONMENT,profile.deployment,profile.instance,profile.nonce])
    # Preflight runs under the same collector lock and authorization checks as
    # commit. It emits only a closed state token, never envelope contents.
    if preflight:
        base_action=f"""IF EXISTS (SELECT 1 FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c} AND revision={proposal_revision}) THEN RAISE EXCEPTION 'proposal revision exists'; END IF;
        IF pg_catalog.clock_timestamp() >= {q(expires)}::timestamptz THEN PERFORM set_config('apicontour.renew_state','base_expired',true);
        ELSE PERFORM set_config('apicontour.renew_state','base_live',true); END IF;"""
        committed_action="PERFORM set_config('apicontour.renew_state','committed',true);"
        result_query="SELECT current_setting('apicontour.renew_state');"
    else:
        base_action=f"""IF pg_catalog.clock_timestamp() < {q(issued)}::timestamptz OR pg_catalog.clock_timestamp() >= {q(expires)}::timestamptz THEN RAISE EXCEPTION 'proposal expired'; END IF;
        INSERT INTO contour.policy_revisions VALUES ({t},{c},{proposal_revision},decode('{proposal.hex()}','hex'));
        UPDATE contour.collector_authorization SET active_revision={proposal_revision} WHERE tenant_id={t} AND collector_id={c} AND enabled AND revoked_at IS NULL AND active_revision={base_revision};
        GET DIAGNOSTICS affected=ROW_COUNT;
        IF affected<>1 THEN RAISE EXCEPTION 'head changed'; END IF;"""
        committed_action="NULL;"
        result_query=""
    # Origin history must remain contiguous at both possible heads while C is held.
    # Existing DEFAULT/PILOT SQL remains unchanged.
    if profile is origin21_profile.BOUND.capture or profile is origin21_profile.MANAGED_BOUND.capture:
        def history_guard(revision):
            return f"IF (SELECT count(*) FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c}) <> {revision} OR EXISTS (SELECT 1 FROM contour.policy_revisions WHERE tenant_id={t} AND collector_id={c} AND revision>{revision}) THEN RAISE EXCEPTION 'policy history drift'; END IF;\n"
        base_action=history_guard(base_revision)+base_action
        committed_action=history_guard(proposal_revision)+committed_action
    # All identity checks and both head comparisons execute after collector lock,
    # through one transaction. No dynamic values are used as SQL identifiers.
    database_guard = "DO $$ BEGIN IF pg_catalog.current_database()<>'contour_local' THEN RAISE EXCEPTION 'wrong local database'; END IF; END $$;" if (profile is origin21_profile.BOUND.capture or profile is origin21_profile.MANAGED_BOUND.capture) else ''
    sql=f'''BEGIN;
{database_guard}
SELECT set_config('apicontour.tenant_id',{t},true),set_config('statement_timeout','15s',true),set_config('lock_timeout','5s',true),set_config('idle_in_transaction_session_timeout','15s',true);
SET LOCAL ROLE contour_admin;
SELECT contour.lock_collector({t},{c});
DO $$ DECLARE current_revision numeric; current_envelope bytea; affected integer; BEGIN
 IF NOT EXISTS (SELECT 1 FROM contour.collector_authorization WHERE tenant_id={t} AND collector_id={c} AND enabled AND revoked_at IS NULL)
 OR (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.sources WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep} AND source_nonce={nonce} AND binding_mode='instance')<>1
 OR (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.source_authorization WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND technique='gateway' AND parser_profiles=ARRAY['http_json_v1'])<>1
 OR (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.source_instance_bindings WHERE tenant_id={t} AND collector_id={c} AND source_id={src} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep} AND instance_id={instance})<>1
 OR (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c})<>1
 OR (SELECT count(*) FROM contour.workload_assignments WHERE tenant_id={t} AND collector_id={c} AND project_id={project} AND service_id={service} AND environment_id={env} AND deployment_id={dep})<>1
 THEN RAISE EXCEPTION 'local authorization drift'; END IF;
 SELECT a.active_revision,r.signed_envelope INTO current_revision,current_envelope FROM contour.collector_authorization a JOIN contour.policy_revisions r ON r.tenant_id=a.tenant_id AND r.collector_id=a.collector_id AND r.revision=a.active_revision WHERE a.tenant_id={t} AND a.collector_id={c};
 IF current_revision={base_revision} AND current_envelope=decode('{base_bytes.hex()}','hex') THEN
   {base_action}
 ELSIF current_revision={proposal_revision} AND current_envelope=decode('{proposal.hex()}','hex') THEN
   {committed_action}
 ELSE RAISE EXCEPTION 'head changed'; END IF;
END $$;
{result_query}
COMMIT;'''
    output=(executor or p.base.psql)(sql)
    if preflight:
        state=output.splitlines()[-1] if output else ''
        if state not in ('base_live','base_expired','committed'): raise ValueError('preflight state')
        return state
