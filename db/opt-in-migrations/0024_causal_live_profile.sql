-- Opt-in exact candidate registration; this is not artifact attestation or qualification.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR pg_catalog.current_setting('row_security') <> 'on'
 OR pg_catalog.current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,23))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted profile migration required' USING ERRCODE='42501'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.causal_runtime_profiles
 DROP CONSTRAINT causal_runtime_profiles_profile_id_check,
 DROP CONSTRAINT causal_runtime_profiles_artifact_sha256_check,
 ADD CONSTRAINT causal_runtime_profiles_profile_artifact_check CHECK (((profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))));
ALTER TABLE contour.causal_runtime_bindings
 DROP CONSTRAINT causal_runtime_bindings_profile_id_check,
 DROP CONSTRAINT causal_runtime_bindings_artifact_sha256_check,
 ADD CONSTRAINT causal_runtime_bindings_profile_artifact_check CHECK (((profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile_id IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact_sha256 IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))));
CREATE OR REPLACE FUNCTION contour.register_causal_profile(t uuid,profile uuid,artifact bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_profiles;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF NOT ((profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))) THEN RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_profiles WHERE tenant_id=t AND profile_id=profile;
 IF FOUND THEN
  IF existing.artifact_sha256=artifact AND existing.point_kind='node_in' AND existing.method='POST' AND existing.route='/run'
     AND existing.technique='runtime' AND existing.parser_profile='http_json_v1' THEN RETURN profile; END IF;
  RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_runtime_profiles VALUES (t,profile,artifact,'node_in','POST','/run','runtime','http_json_v1',pg_catalog.clock_timestamp());
 RETURN profile;
END $$;

CREATE OR REPLACE FUNCTION contour.enroll_causal_runtime(t uuid,runtime uuid,c uuid,src uuid,p uuid,s uuid,e uuid,d uuid,i uuid,lifecycle uuid,profile uuid,artifact bytea,leaf bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_bindings; at_time timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 PERFORM contour.lock_origin_credential(leaf);
 PERFORM contour.lock_origin_collector(t,c);
 IF runtime IS NULL OR lifecycle IS NULL OR NOT ((profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid AND artifact IS NOT DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')) OR (profile IS NOT DISTINCT FROM '00000000-0000-4000-8000-000000000503'::uuid AND artifact IS NOT DISTINCT FROM decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))) THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 IF NOT contour.causal_legacy_authorized(t,c,src,p,s,e,d,i) OR NOT EXISTS (
  SELECT 1 FROM contour.causal_runtime_profiles x WHERE x.tenant_id=t AND x.profile_id=profile AND x.artifact_sha256=artifact
   AND x.point_kind='node_in' AND x.method='POST' AND x.route='/run' AND x.technique='runtime' AND x.parser_profile='http_json_v1')
 OR NOT EXISTS (SELECT 1 FROM contour.origin_lifecycles l WHERE l.tenant_id=t AND l.lifecycle_id=lifecycle
   AND l.project_id=p AND l.service_id=s AND l.environment_id=e AND l.deployment_id=d AND l.instance_id=i
   AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.lifecycle_id=lifecycle AND z.event_kind='lifecycle_closed')
   AND EXISTS (SELECT 1 FROM contour.origin_credentials oc WHERE oc.tenant_id=t AND oc.lifecycle_id=lifecycle
     AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.credential_id=oc.credential_id AND z.event_kind='credential_revoked')))
 THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time<contour.origin_history_highwater(t,lifecycle) THEN RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_bindings WHERE tenant_id=t AND runtime_id=runtime;
 IF FOUND THEN
  IF existing.collector_id=c AND existing.source_id=src AND existing.project_id=p AND existing.service_id=s AND existing.environment_id=e
    AND existing.deployment_id=d AND existing.instance_id=i AND existing.lifecycle_id=lifecycle AND existing.profile_id=profile
    AND existing.artifact_sha256=artifact AND existing.export_leaf_sha256=leaf AND existing.enrolled_at<=at_time
    AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=leaf AND leaf_class='export')
    AND NOT EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=t AND z.runtime_id=runtime)
  THEN RETURN runtime; END IF;
  RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_leaf_reservations VALUES (leaf,'export');
 INSERT INTO contour.causal_runtime_bindings VALUES (t,runtime,c,src,p,s,e,d,i,lifecycle,profile,artifact,leaf,at_time);
 RETURN runtime;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
END $$;

CREATE OR REPLACE FUNCTION contour.causal_runtime_authority_locked(x contour.causal_session_claim, now_at timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; checked_at timestamptz;
BEGIN
 PERFORM contour.require_origin_locks(x.tenant_id,x.collector_id,x.export_leaf);
 checked_at:=pg_catalog.clock_timestamp();
 IF now_at IS NULL OR NOT isfinite(now_at) OR checked_at IS NULL OR NOT isfinite(checked_at) OR checked_at<now_at THEN RETURN false; END IF;
 now_at:=checked_at;
 SELECT * INTO b FROM contour.causal_runtime_bindings WHERE tenant_id=x.tenant_id AND runtime_id=x.runtime_id;
 IF NOT FOUND OR now_at IS NULL OR NOT isfinite(now_at) THEN RETURN false; END IF;
 RETURN coalesce(
  b.collector_id=x.collector_id AND b.source_id=x.source_id AND b.project_id=x.project_id
  AND b.service_id=x.service_id AND b.environment_id=x.environment_id AND b.deployment_id=x.deployment_id
  AND b.instance_id=x.instance_id AND b.lifecycle_id=x.lifecycle_id AND b.export_leaf_sha256=x.export_leaf
  AND b.artifact_sha256=x.profile_hash
  AND ((b.profile_id='00000000-0000-4000-8000-000000000501'::uuid AND x.profile_name='nodered_5_0_9_v1' AND x.profile_hash=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'))
   OR (b.profile_id='00000000-0000-4000-8000-000000000503'::uuid AND x.profile_name='nodered_5_0_9_wire_v1' AND x.profile_hash=decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex')))
  AND b.enrolled_at<=now_at AND now_at>=contour.origin_history_highwater(x.tenant_id,x.lifecycle_id)
  AND now_at>=x.grant_issued AND now_at<x.grant_expires AND now_at>=x.policy_issued AND now_at<x.policy_expires
  AND contour.causal_legacy_authorized(x.tenant_id,x.collector_id,x.source_id,x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id)
  AND contour.causal_policy_exact(x.tenant_id,x.collector_id,x.policy_revision,x.policy_envelope)
  AND EXISTS (SELECT 1 FROM contour.causal_runtime_profiles p WHERE p.tenant_id=x.tenant_id AND p.profile_id=b.profile_id AND p.artifact_sha256=x.profile_hash AND p.point_kind='node_in' AND p.method='POST' AND p.route='/run' AND p.technique='runtime' AND p.parser_profile='http_json_v1')
  AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations l WHERE l.leaf_sha256=x.export_leaf AND l.leaf_class='export')
  AND NOT EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=x.tenant_id AND z.runtime_id=x.runtime_id)
  AND EXISTS (SELECT 1 FROM contour.origin_lifecycles l WHERE l.tenant_id=x.tenant_id AND l.lifecycle_id=x.lifecycle_id
   AND l.project_id=x.project_id AND l.service_id=x.service_id AND l.environment_id=x.environment_id AND l.deployment_id=x.deployment_id AND l.instance_id=x.instance_id
   AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=l.tenant_id AND z.lifecycle_id=l.lifecycle_id AND z.event_kind='lifecycle_closed')
   AND EXISTS (SELECT 1 FROM contour.origin_credentials oc WHERE oc.tenant_id=l.tenant_id AND oc.lifecycle_id=l.lifecycle_id
    AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=oc.tenant_id AND z.credential_id=oc.credential_id AND z.event_kind='credential_revoked')))
  ,false);
END $$;
INSERT INTO contour.schema_migrations(version) VALUES (24);
COMMIT;
