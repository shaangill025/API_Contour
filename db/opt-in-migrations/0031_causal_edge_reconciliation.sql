-- Committed causal edge reconciliation; opt-in only.
-- The caller must already hold the complete origin/credential/collector gates.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,30))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted causal reconciler migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_reconciler NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
CREATE FUNCTION contour.causal_committed_batch_valid(t uuid, runtime uuid, ep numeric, bid uuid)
RETURNS boolean LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_inbox_batches; s contour.causal_sessions; j jsonb;
BEGIN
 -- This verifies stored data, not current authority or peer possession.
 IF t IS DISTINCT FROM contour.tenant_context() THEN
  RAISE EXCEPTION 'stored causal batch unavailable' USING ERRCODE='23514';
 END IF;
 SELECT * INTO b FROM contour.causal_inbox_batches x
  WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid);
 IF NOT FOUND THEN RAISE EXCEPTION 'stored causal batch unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO s FROM contour.causal_sessions x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,runtime,ep);
 IF NOT FOUND OR (s.claim).max_batch_bytes IS NULL OR (s.claim).max_batch_bytes NOT BETWEEN 1 AND 1048576
 OR (s.claim).max_batch_events IS NULL OR (s.claim).max_batch_events NOT BETWEEN 1 AND 500
 OR octet_length(b.canonical_batch) NOT BETWEEN 1 AND (s.claim).max_batch_bytes
 THEN RAISE EXCEPTION 'stored causal batch unavailable' USING ERRCODE='23514'; END IF;
 BEGIN
  j:=contour.causal_parse(b.canonical_batch);
 EXCEPTION WHEN data_exception OR check_violation THEN
  RAISE EXCEPTION 'stored causal batch unavailable' USING ERRCODE='23514';
 END;
 IF b.batch_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-events/1\n','UTF8')||b.canonical_batch)
 OR (j->>'tenant_id')::uuid IS DISTINCT FROM t OR (j->>'runtime_id')::uuid IS DISTINCT FROM runtime
 OR (j->>'session_epoch')::numeric IS DISTINCT FROM ep OR (j->>'batch_id')::uuid IS DISTINCT FROM bid
 OR b.event_count IS DISTINCT FROM jsonb_array_length(j->'events') OR b.event_count>(s.claim).max_batch_events
 OR b.receipt_id IS NULL OR b.accepted_at IS NULL OR NOT isfinite(b.accepted_at)
 OR b.receipt_digest IS DISTINCT FROM contour.causal_receipt_digest(t,runtime,ep,bid,b.receipt_id,b.accepted_at,b.batch_digest,b.event_count)
 OR EXISTS (SELECT 1 FROM (
  (SELECT * FROM contour.causal_decoded_events(j) EXCEPT
   SELECT x.seq,x.event_id,x.kind,x.root,x.activity,x.parent,x.attempt,x.marker_digest,x.first_missing_seq,x.last_missing_seq,x.reason,x.event_digest
   FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid))
  UNION ALL
  (SELECT x.seq,x.event_id,x.kind,x.root,x.activity,x.parent,x.attempt,x.marker_digest,x.first_missing_seq,x.last_missing_seq,x.reason,x.event_digest
   FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,runtime,ep,bid)
   EXCEPT SELECT * FROM contour.causal_decoded_events(j))) differences)
 THEN RAISE EXCEPTION 'stored causal batch unavailable' USING ERRCODE='23514'; END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION contour.causal_committed_batch_valid(uuid,uuid,numeric,uuid) FROM PUBLIC;
-- Only call under the complete sorted gates; no current-authority assertion.
-- False means a required fact/predecessor has not arrived. Corrupt, conflicting,
-- ambiguous, cyclic or overlong committed state is always a closed failure.
CREATE FUNCTION contour.causal_join_facts_valid(t uuid, gw uuid, gen text, handle text, at_time timestamptz)
RETURNS boolean LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE a contour.causal_receiver_assignments; o contour.causal_observer_inbox; q contour.causal_observer_inbox;
 ri contour.causal_receiver_inbox; tomb contour.causal_receiver_tombstones;
 attempt_event contour.causal_inbox_events; root_event contour.causal_inbox_events;
 oj jsonb; binding jsonb; rj jsonb; marker_digest text; seen text[]:='{}'; next_handle text; n integer; total integer:=0;
BEGIN
 IF t IS DISTINCT FROM contour.tenant_context() OR NOT isfinite(at_time) THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO a FROM contour.causal_receiver_assignments x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO o FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF NOT FOUND THEN RETURN false; END IF;
 SELECT * INTO ri FROM contour.causal_receiver_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF NOT FOUND THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO tomb FROM contour.causal_receiver_tombstones x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF NOT FOUND THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 BEGIN
  oj:=contour.observer_wire(o.canonical_fact); binding:=oj->'binding'; rj:=contour.receiver_inbox_wire(ri.canonical_fact);
 EXCEPTION WHEN data_exception OR check_violation THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END;
 IF (binding->>'tenant_id',binding->>'gateway_id',binding->>'gateway_generation',binding->>'delivery_handle',binding->>'receiver_runtime_id',binding->>'receiver_session_epoch')
 IS DISTINCT FROM (t::text,gw::text,gen,handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text)
 OR (rj->>'tenant_id',rj->>'gateway_id',rj->>'gateway_generation',rj->>'delivery_handle',rj->>'receiver_runtime_id',rj->>'receiver_session_epoch',rj->>'local_root',rj->>'binding_digest')
 IS DISTINCT FROM (t::text,gw::text,gen,handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text,a.local_root,a.binding_digest)
 OR a.binding_digest IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(binding),'UTF8')),'hex')
 OR a.metadata IS DISTINCT FROM contour.receiver_assignment_metadata(a) OR a.charged_bytes<>octet_length(a.metadata)+256
 OR ri.fact_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||ri.canonical_fact)
 OR ri.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver','fact_digest',encode(ri.fact_digest,'hex'),'receipt_id',ri.receipt_id,'status','stored')),'UTF8')
 OR ri.charged_bytes<>octet_length(ri.canonical_fact)+octet_length(ri.receipt)+512
 OR tomb.fact_digest IS DISTINCT FROM ri.fact_digest OR tomb.metadata IS DISTINCT FROM contour.receiver_tombstone_metadata(a,ri.fact_digest) OR tomb.charged_bytes<>octet_length(tomb.metadata)+256
 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 marker_digest:=binding->>'marker_digest';
 -- Traverse the complete connected predecessor/successor chain. Missing earlier
 -- predecessors are unresolved, while duplicate successors and cycles fail.
 next_handle:=handle;
 LOOP
  IF next_handle=ANY(seen) OR total>=64 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO q FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,next_handle);
  IF NOT FOUND THEN RETURN false; END IF;
  -- Only the selected delivery and its required predecessors constrain this
  -- join. Future successors must not extend or shorten its original window.
  IF NOT isfinite(q.accepted_at) OR NOT isfinite(q.expires_at)
   OR q.expires_at IS DISTINCT FROM q.accepted_at+interval '24 hours'
   OR at_time<q.accepted_at OR at_time>=q.expires_at
  THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  seen:=array_append(seen,next_handle);total:=total+1;
  IF (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id,q.proof_id,q.marker_root,q.marker_activity,q.marker_public)
   IS DISTINCT FROM (o.runtime_id,o.session_epoch,o.attempt,o.collector_id,o.batch_id,o.record_id,o.proof_id,o.marker_root,o.marker_activity,o.marker_public)
  THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  BEGIN oj:=contour.observer_wire(q.canonical_fact); EXCEPTION WHEN data_exception OR check_violation THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END;
  binding:=oj->'binding';
  IF (binding->>'tenant_id',binding->>'gateway_id',binding->>'gateway_generation',binding->>'delivery_handle',binding->>'producer_runtime_id',binding->>'producer_session_epoch',binding->>'producer_attempt_id',binding->>'collector_id',binding->>'record_id',oj->>'batch_id',binding->>'retry_of')
   IS DISTINCT FROM (t::text,gw::text,gen,q.delivery_handle,q.runtime_id::text,q.session_epoch::text,q.attempt,q.collector_id::text,q.record_id::text,q.batch_id::text,q.retry_of)
  OR binding->>'marker_digest' IS DISTINCT FROM marker_digest
  OR binding->>'marker_digest' IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(oj->>'signed_marker'),'UTF8')),'hex')
  OR q.fact_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||q.canonical_fact)
  OR q.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(q.fact_digest,'hex'),'receipt_id',q.receipt_id,'status','stored')),'UTF8')
  OR q.charged_bytes<>octet_length(q.canonical_fact)+octet_length(q.receipt)+512
  THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  IF q.retry_of IS NULL THEN EXIT; END IF;
  -- A fork at any ancestor is ambiguous even when the selected branch is
  -- internally consistent. The unique successor must be this exact handle.
  SELECT count(*) INTO n FROM contour.causal_observer_inbox x
   WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.retry_of)=(t,gw,gen,q.retry_of);
  IF n<>1 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  next_handle:=q.retry_of;
 END LOOP;
 -- Walk successors starting from the originally requested delivery. A later
 -- absent successor is not a missing predecessor and does not block this edge.
 next_handle:=handle;
 LOOP
  SELECT count(*) INTO n FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.retry_of)=(t,gw,gen,next_handle);
  IF n=0 THEN EXIT; ELSIF n<>1 OR total>=64 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  SELECT * INTO q FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.retry_of)=(t,gw,gen,next_handle);
  IF q.delivery_handle=ANY(seen) THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  -- Every descendant must itself pass the same full predecessor verification.
  -- The selection below validates its immutable scope and fact bytes directly.
  IF (q.runtime_id,q.session_epoch,q.attempt,q.collector_id,q.batch_id,q.record_id,q.proof_id,q.marker_root,q.marker_activity,q.marker_public)
   IS DISTINCT FROM (o.runtime_id,o.session_epoch,o.attempt,o.collector_id,o.batch_id,o.record_id,o.proof_id,o.marker_root,o.marker_activity,o.marker_public)
  THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  BEGIN oj:=contour.observer_wire(q.canonical_fact); EXCEPTION WHEN data_exception OR check_violation THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END;
  binding:=oj->'binding';
  IF (binding->>'tenant_id',binding->>'gateway_id',binding->>'gateway_generation',binding->>'delivery_handle',binding->>'producer_runtime_id',binding->>'producer_session_epoch',binding->>'producer_attempt_id',binding->>'collector_id',binding->>'record_id',oj->>'batch_id',binding->>'retry_of')
   IS DISTINCT FROM (t::text,gw::text,gen,q.delivery_handle,q.runtime_id::text,q.session_epoch::text,q.attempt,q.collector_id::text,q.record_id::text,q.batch_id::text,q.retry_of)
  OR binding->>'marker_digest' IS DISTINCT FROM marker_digest
  OR binding->>'marker_digest' IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(oj->>'signed_marker'),'UTF8')),'hex')
  OR q.fact_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||q.canonical_fact)
  OR q.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(q.fact_digest,'hex'),'receipt_id',q.receipt_id,'status','stored')),'UTF8')
  OR q.charged_bytes<>octet_length(q.canonical_fact)+octet_length(q.receipt)+512
  THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
  seen:=array_append(seen,q.delivery_handle);total:=total+1;next_handle:=q.delivery_handle;
 END LOOP;
 -- Restore selected binding; descendants may target different receiver instances.
 oj:=contour.observer_wire(o.canonical_fact);binding:=oj->'binding';
 SELECT count(*) INTO n FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.attempt)=(t,o.runtime_id,o.session_epoch,'attempt',o.attempt);
 IF n=0 THEN RETURN false; ELSIF n<>1 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO attempt_event FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.attempt)=(t,o.runtime_id,o.session_epoch,'attempt',o.attempt);
 IF (attempt_event.root,attempt_event.activity,attempt_event.marker_digest) IS DISTINCT FROM (o.marker_root,o.marker_activity,binding->>'marker_digest')
 OR contour.causal_committed_batch_valid(t,o.runtime_id,o.session_epoch,attempt_event.batch_id) IS NOT TRUE
 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 SELECT count(*) INTO n FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.root)=(t,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root);
 IF n=0 THEN RETURN false; ELSIF n<>1 THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO root_event FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.root)=(t,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root);
 IF contour.causal_committed_batch_valid(t,a.receiver_runtime_id,a.receiver_session_epoch,root_event.batch_id) IS NOT TRUE THEN RAISE EXCEPTION 'causal facts unavailable' USING ERRCODE='23514'; END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION contour.causal_join_facts_valid(uuid,uuid,text,text,timestamptz) FROM PUBLIC;
-- Private SQL31 authority copies return each server-clock high-water.
-- Predicate mappings and required differential review are documented separately.
CREATE TYPE contour.causal31_clock_result AS (valid boolean, checked_at timestamptz);
REVOKE ALL ON TYPE contour.causal31_clock_result FROM PUBLIC;
CREATE FUNCTION contour.causal31_runtime_checked(x contour.causal_session_claim, now_at timestamptz) RETURNS contour.causal31_clock_result
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; checked_at timestamptz; valid boolean;
BEGIN
 PERFORM contour.require_origin_locks(x.tenant_id,x.collector_id,x.export_leaf);
 checked_at:=pg_catalog.clock_timestamp();
 IF now_at IS NULL OR NOT isfinite(now_at) OR checked_at IS NULL OR NOT isfinite(checked_at) OR checked_at<now_at THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 now_at:=checked_at;
 SELECT * INTO b FROM contour.causal_runtime_bindings WHERE tenant_id=x.tenant_id AND runtime_id=x.runtime_id;
 IF NOT FOUND OR now_at IS NULL OR NOT isfinite(now_at) THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 valid:=coalesce(
  b.collector_id=x.collector_id AND b.source_id=x.source_id AND b.project_id=x.project_id
  AND b.service_id=x.service_id AND b.environment_id=x.environment_id AND b.deployment_id=x.deployment_id
  AND b.instance_id=x.instance_id AND b.lifecycle_id=x.lifecycle_id AND b.export_leaf_sha256=x.export_leaf
  AND b.artifact_sha256=x.profile_hash
  AND ((b.profile_id='00000000-0000-4000-8000-000000000501'::uuid AND x.profile_name='nodered_5_0_9_v1' AND x.profile_hash=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex'))
   OR (b.profile_id='00000000-0000-4000-8000-000000000503'::uuid AND x.profile_name='nodered_5_0_9_wire_v1' AND x.profile_hash=decode('a4d698a75a25589aeee3cccde89c1d3abbff8ec0f70304ca33b205e5e7b69c0e','hex'))
   OR (b.profile_id='00000000-0000-4000-8000-000000000504'::uuid AND x.profile_name='nodered_5_0_9_receiver_v1' AND x.profile_hash=decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex')))
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
 RETURN (valid,checked_at)::contour.causal31_clock_result;
END $$;

-- Derived from SQL19 causal_session_locked. The second server clock is
-- compared to the runtime sample, not merely the original lower bound.
CREATE FUNCTION contour.causal31_session_checked(x contour.causal_session_claim, ep numeric, now_at timestamptz)
RETURNS contour.causal31_clock_result LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE checked_at timestamptz; runtime_result contour.causal31_clock_result; valid boolean;
BEGIN
 IF ep IS NULL OR ep<>trunc(ep) OR ep NOT BETWEEN 1 AND 18446744073709551615 THEN RETURN (false,now_at)::contour.causal31_clock_result; END IF;
 PERFORM contour.require_origin_locks(x.tenant_id,x.collector_id,x.export_leaf);
 IF now_at IS NULL OR NOT isfinite(now_at) THEN RETURN (false,now_at)::contour.causal31_clock_result; END IF;
 runtime_result:=contour.causal31_runtime_checked(x,now_at);
 IF runtime_result.valid IS NOT TRUE OR runtime_result.checked_at IS NULL OR NOT isfinite(runtime_result.checked_at) OR runtime_result.checked_at<now_at
 THEN RETURN (false,now_at)::contour.causal31_clock_result; END IF;
 checked_at:=pg_catalog.clock_timestamp();
 IF checked_at IS NULL OR NOT isfinite(checked_at) OR checked_at<runtime_result.checked_at
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 valid:=EXISTS (SELECT 1 FROM contour.causal_sessions s WHERE s.tenant_id=x.tenant_id AND s.runtime_id=x.runtime_id
    AND s.epoch=ep AND s.claim IS NOT DISTINCT FROM x AND s.issued_at<=checked_at AND checked_at<s.expires_at
    AND checked_at>=x.grant_issued AND checked_at<x.grant_expires AND checked_at>=x.policy_issued AND checked_at<x.policy_expires
    AND s.epoch=(SELECT max(y.epoch) FROM contour.causal_sessions y WHERE y.tenant_id=x.tenant_id AND y.runtime_id=x.runtime_id));
 RETURN (valid,checked_at)::contour.causal31_clock_result;
END $$;
REVOKE ALL ON FUNCTION contour.causal31_runtime_checked(contour.causal_session_claim,timestamptz),
 contour.causal31_session_checked(contour.causal_session_claim,numeric,timestamptz) FROM PUBLIC;

-- Private nested authority call graph; source predicates remain unchanged.
CREATE FUNCTION contour.causal31_receiver_claim_checked(x contour.receiver_enrollment_claim,
 s contour.causal_sessions, b contour.causal_runtime_bindings, at_time timestamptz, lower_at timestamptz)
RETURNS contour.causal31_clock_result LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE checked_at timestamptz:=lower_at; valid boolean; nested contour.causal31_clock_result;
BEGIN
 IF at_time IS NULL OR lower_at IS NULL OR NOT isfinite(at_time) OR NOT isfinite(lower_at) OR lower_at<at_time
 THEN RETURN (false,lower_at)::contour.causal31_clock_result; END IF;
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.product_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.export_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.backend_leaf);
 PERFORM contour.require_origin_locks(x.tenant_id,b.collector_id,x.evidence_leaf);
 nested:=contour.causal31_session_checked(s.claim,s.epoch,checked_at);
 IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 checked_at:=nested.checked_at;
 valid:=coalesce(x.tenant_id=contour.tenant_context()
  AND (s.tenant_id,s.runtime_id,s.epoch)=(x.tenant_id,x.runtime_id,x.session_epoch)
  AND (b.tenant_id,b.runtime_id)=(x.tenant_id,x.runtime_id)
  AND x.instance_id=b.instance_id AND x.lifecycle_id=b.lifecycle_id
  AND x.export_leaf=b.export_leaf_sha256 AND x.export_leaf=(s.claim).export_leaf
  AND b.profile_id='00000000-0000-4000-8000-000000000504'::uuid
  AND b.artifact_sha256=decode('af3171bdf0ca4bfc70c63aaf998fdfd4cf988b4409e7f7f47e015325608b302d','hex')
  AND (s.claim).profile_name='nodered_5_0_9_receiver_v1'
  AND (s.claim).profile_hash=b.artifact_sha256
  AND at_time>=x.backend_not_before AND at_time<x.backend_not_after
  AND at_time>=x.evidence_not_before AND at_time<x.evidence_not_after
  AND nested.valid
  AND contour.causal_marker_product_current(x.tenant_id,b,x.product_credential,x.product_leaf,at_time),false);
 RETURN (valid,checked_at)::contour.causal31_clock_result;
END $$;

CREATE FUNCTION contour.causal31_receiver_enrollment_checked(a contour.causal_receiver_assignments, at_time timestamptz, lower_at timestamptz) RETURNS contour.causal31_clock_result
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE r contour.causal_receiver_enrollments; s contour.causal_sessions; b contour.causal_runtime_bindings; checked_at timestamptz:=lower_at; valid boolean; nested contour.causal31_clock_result;
BEGIN
 IF at_time IS NULL OR lower_at IS NULL OR NOT isfinite(at_time) OR NOT isfinite(lower_at) OR lower_at<at_time
 THEN RETURN (false,lower_at)::contour.causal31_clock_result; END IF;
 SELECT * INTO STRICT r FROM contour.causal_receiver_enrollments x
  WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
 SELECT * INTO STRICT s FROM contour.causal_sessions x
  WHERE (x.tenant_id,x.runtime_id,x.epoch)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
 SELECT * INTO STRICT b FROM contour.causal_runtime_bindings x
  WHERE (x.tenant_id,x.runtime_id)=(a.tenant_id,a.receiver_runtime_id) FOR SHARE;
 nested:=contour.causal31_receiver_claim_checked(r.claim,s,b,at_time,checked_at);
 IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 checked_at:=nested.checked_at;
 valid:=coalesce(a.tenant_id=contour.tenant_context() AND isfinite(at_time)
  AND a.enrollment_generation=r.enrollment_generation AND a.evidence_credential_id=r.evidence_credential_id
  AND a.evidence_peer_leaf=(r.claim).evidence_leaf AND at_time>=r.issued_at AND at_time<r.expires_at
  AND a.metadata=contour.receiver_assignment_metadata(a) AND a.charged_bytes=octet_length(a.metadata)+256
  AND r.metadata=contour.receiver_enrollment_metadata(r.claim,s,r.enrollment_generation,r.evidence_credential_id,r.issued_at,r.expires_at)
  AND r.commitment=contour.receiver_enrollment_commitment(r.metadata)
  AND nested.valid
  AND NOT EXISTS(SELECT 1 FROM contour.causal_receiver_terminals z WHERE (z.tenant_id,z.runtime_id,z.session_epoch)=(r.tenant_id,r.runtime_id,r.session_epoch))
  AND EXISTS(SELECT 1 FROM contour.causal_receiver_terminal_reservations z WHERE (z.tenant_id,z.runtime_id,z.session_epoch,z.charged_bytes)=(r.tenant_id,r.runtime_id,r.session_epoch,1024))
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).product_leaf AND z.leaf_class='product')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).export_leaf AND z.leaf_class='export')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).backend_leaf AND z.leaf_class='receiver_backend')
  AND EXISTS(SELECT 1 FROM contour.causal_leaf_reservations z WHERE z.leaf_sha256=(r.claim).evidence_leaf AND z.leaf_class='receiver_evidence'),false);
 RETURN (valid,checked_at)::contour.causal31_clock_result;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN (false,checked_at)::contour.causal31_clock_result;
END $$;

CREATE FUNCTION contour.causal31_receiver_assignment_checked(a contour.causal_receiver_assignments, at_time timestamptz, lower_at timestamptz) RETURNS contour.causal31_clock_result
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE i contour.causal_receiver_inbox; tomb contour.causal_receiver_tombstones; wire jsonb; checked_at timestamptz:=lower_at; valid boolean; nested contour.causal31_clock_result;
BEGIN
 IF at_time IS NULL OR lower_at IS NULL OR NOT isfinite(at_time) OR NOT isfinite(lower_at) OR lower_at<at_time
 THEN RETURN (false,lower_at)::contour.causal31_clock_result; END IF;
 nested:=contour.causal31_receiver_enrollment_checked(a,at_time,checked_at);
 IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 checked_at:=nested.checked_at;
 IF nested.valid IS NOT TRUE THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 SELECT * INTO STRICT i FROM contour.causal_receiver_inbox x
  WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 SELECT * INTO STRICT tomb FROM contour.causal_receiver_tombstones x
  WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 wire:=contour.receiver_inbox_wire(i.canonical_fact);
 valid:=coalesce((wire->>'tenant_id',wire->>'gateway_id',wire->>'gateway_generation',wire->>'delivery_handle',wire->>'receiver_runtime_id',wire->>'receiver_session_epoch',wire->>'local_root',wire->>'binding_digest')
      =(a.tenant_id::text,a.gateway_id::text,a.gateway_generation,a.delivery_handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text,a.local_root,a.binding_digest)
  AND i.fact_digest=sha256(convert_to(E'apicontour/causal-evidence/receiver/1\n','UTF8')||i.canonical_fact)
  AND tomb.fact_digest=i.fact_digest AND tomb.metadata=contour.receiver_tombstone_metadata(a,i.fact_digest) AND tomb.charged_bytes=octet_length(tomb.metadata)+256
  AND i.receipt=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','receiver','fact_digest',encode(i.fact_digest,'hex'),'receipt_id',i.receipt_id,'status','stored')),'UTF8')
  AND i.charged_bytes=octet_length(i.canonical_fact)+octet_length(i.receipt)+512
  AND at_time>=i.accepted_at AND at_time<i.expires_at,false);
 RETURN (valid,checked_at)::contour.causal31_clock_result;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RETURN (false,checked_at)::contour.causal31_clock_result;
END $$;

CREATE FUNCTION contour.causal31_receiver_observer_checked(a contour.causal_receiver_assignments, at_time timestamptz, lower_at timestamptz) RETURNS contour.causal31_clock_result
LANGUAGE plpgsql VOLATILE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE o contour.causal_observer_inbox; j jsonb; binding jsonb; x contour.causal_session_claim;
 ps contour.causal_sessions; pb contour.causal_runtime_bindings; m contour.causal_marker_bindings;
 gw contour.causal_gateway_enrollments; ar contour.causal_observer_attempt_reservations;
 w contour.observation_windows; origin contour.origin_proofs; verified record; payload bytea; request_record jsonb; meta bytea; checked_at timestamptz:=lower_at; valid boolean; nested contour.causal31_clock_result;
BEGIN
 IF at_time IS NULL OR lower_at IS NULL OR NOT isfinite(at_time) OR NOT isfinite(lower_at) OR lower_at<at_time
 THEN RETURN (false,lower_at)::contour.causal31_clock_result; END IF;
 SELECT * INTO STRICT gw FROM contour.causal_gateway_enrollments q WHERE (q.tenant_id,q.gateway_id,q.generation)=(a.tenant_id,a.gateway_id,a.gateway_generation);
 SELECT * INTO STRICT o FROM contour.causal_observer_inbox q WHERE (q.tenant_id,q.gateway_id,q.gateway_generation,q.delivery_handle)=(a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle);
 SELECT * INTO STRICT ps FROM contour.causal_sessions q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(o.tenant_id,o.runtime_id,o.session_epoch) FOR SHARE;
 SELECT * INTO STRICT pb FROM contour.causal_runtime_bindings q WHERE (q.tenant_id,q.runtime_id)=(o.tenant_id,o.runtime_id) FOR SHARE;
 SELECT * INTO STRICT m FROM contour.causal_marker_bindings q WHERE (q.tenant_id,q.runtime_id,q.epoch)=(o.tenant_id,o.runtime_id,o.session_epoch) FOR SHARE;
 SELECT * INTO STRICT ar FROM contour.causal_observer_attempt_reservations q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,o.attempt);
 j:=contour.observer_wire(o.canonical_fact);binding:=j->'binding';x:=ps.claim;
 meta:=convert_to(contour.causal_json_canonical(jsonb_build_object('tenant_id',o.tenant_id,'runtime_id',o.runtime_id,'session_epoch',o.session_epoch::text,'attempt',o.attempt,'gateway_id',o.gateway_id,'gateway_generation',o.gateway_generation,'collector_id',o.collector_id,'batch_id',o.batch_id,'record_id',o.record_id,'marker_digest',encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')),'hex'),'marker_root',o.marker_root,'marker_activity',o.marker_activity)),'UTF8');
 nested:=contour.causal31_session_checked(x,o.session_epoch,checked_at);
 IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 checked_at:=nested.checked_at;
 IF (binding->>'tenant_id',binding->>'gateway_id',binding->>'gateway_generation',binding->>'delivery_handle',binding->>'receiver_runtime_id',binding->>'receiver_session_epoch')
    IS DISTINCT FROM (a.tenant_id::text,a.gateway_id::text,a.gateway_generation,a.delivery_handle,a.receiver_runtime_id::text,a.receiver_session_epoch::text)
 OR a.binding_digest IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(binding),'UTF8')),'hex')
 OR (binding->>'producer_runtime_id',binding->>'producer_session_epoch',binding->>'producer_attempt_id',binding->>'collector_id',binding->>'record_id',j->>'batch_id',binding->>'retry_of')
    IS DISTINCT FROM (o.runtime_id::text,o.session_epoch::text,o.attempt,o.collector_id::text,o.record_id::text,o.batch_id::text,o.retry_of)
 OR at_time<o.accepted_at OR at_time>=o.expires_at OR o.fact_digest IS DISTINCT FROM sha256(convert_to(E'apicontour/causal-evidence/observer/1\n','UTF8')||o.canonical_fact)
 OR o.receipt IS DISTINCT FROM convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','observer','fact_digest',encode(o.fact_digest,'hex'),'receipt_id',o.receipt_id,'status','stored')),'UTF8')
 OR o.charged_bytes<>octet_length(o.canonical_fact)+octet_length(o.receipt)+512
 OR (ar.gateway_id,ar.gateway_generation,ar.collector_id,ar.batch_id,ar.record_id,ar.marker_digest,ar.marker_root,ar.marker_activity)
    IS DISTINCT FROM (o.gateway_id,o.gateway_generation,o.collector_id,o.batch_id,o.record_id,binding->>'marker_digest',o.marker_root,o.marker_activity)
 OR o.collector_id IS DISTINCT FROM (gw.claim).collector_id
 OR binding->>'marker_digest' IS DISTINCT FROM encode(sha256(convert_to(E'apicontour/causal-marker-wire/1\n'||(j->>'signed_marker'),'UTF8')),'hex')
 OR ar.metadata IS DISTINCT FROM meta OR ar.charged_bytes<>octet_length(meta)+256
 OR NOT EXISTS(SELECT 1 FROM contour.causal_observer_epoch_reservations q WHERE (q.tenant_id,q.runtime_id,q.session_epoch,q.charged_bytes)=(o.tenant_id,o.runtime_id,o.session_epoch,1024))
 OR o.marker_public IS DISTINCT FROM m.marker_public_key OR m.nonce IS DISTINCT FROM x.nonce
 OR (m.lifecycle_id,m.instance_id,m.profile_id,m.artifact_sha256) IS DISTINCT FROM (pb.lifecycle_id,pb.instance_id,pb.profile_id,pb.artifact_sha256)
 OR nested.valid IS NOT TRUE
 OR NOT contour.causal_marker_product_current(a.tenant_id,pb,m.product_credential_id,m.product_leaf_sha256,at_time)
 OR EXISTS(SELECT 1 FROM contour.causal_inbox_events e WHERE (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.attempt)=(o.tenant_id,o.runtime_id,o.session_epoch,'attempt',o.attempt) AND (e.root,e.activity,e.marker_digest) IS DISTINCT FROM (o.marker_root,o.marker_activity,binding->>'marker_digest'))
 THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
 SELECT * INTO STRICT w FROM contour.observation_windows q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.record_id)=(o.tenant_id,o.collector_id,o.batch_id,o.record_id);
 SELECT * INTO STRICT verified FROM contour.human_observation_origin(a.tenant_id,w.project_id,w.service_id,w.environment_id,w.operation_id,w.observation_id);
 SELECT * INTO STRICT origin FROM contour.origin_proofs q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.record_id)=(o.tenant_id,o.collector_id,o.batch_id,o.record_id);
 SELECT q.checked_batch INTO STRICT payload FROM contour.ingestion_payloads q WHERE (q.tenant_id,q.collector_id,q.batch_id,q.payload_format)=(o.tenant_id,o.collector_id,o.batch_id,2);
 SELECT item.value->'record' INTO STRICT request_record FROM jsonb_array_elements((convert_from(payload,'UTF8')::jsonb)->'records') item(value) WHERE item.value->'record'->>'record_id'=o.record_id::text;
 valid:=coalesce(request_record->>'direction'='request' AND origin.proof_id=o.proof_id AND origin.source_id=(gw.claim).source_id
  AND (origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id,origin.leaf_sha256)=(x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id,x.lifecycle_id,m.product_credential_id,m.product_leaf_sha256)
  AND (verified.origin_project_id,verified.origin_service_id,verified.origin_environment_id,verified.origin_deployment_id,verified.instance_id,verified.lifecycle_id,verified.credential_id)=(origin.origin_project_id,origin.origin_service_id,origin.origin_environment_id,origin.origin_deployment_id,origin.instance_id,origin.lifecycle_id,origin.credential_id),false);
 RETURN (valid,checked_at)::contour.causal31_clock_result;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN RETURN (false,checked_at)::contour.causal31_clock_result;
END $$;
REVOKE ALL ON FUNCTION contour.causal31_receiver_claim_checked(contour.receiver_enrollment_claim,contour.causal_sessions,contour.causal_runtime_bindings,timestamptz,timestamptz),
 contour.causal31_receiver_enrollment_checked(contour.causal_receiver_assignments,timestamptz,timestamptz),
 contour.causal31_receiver_assignment_checked(contour.causal_receiver_assignments,timestamptz,timestamptz),
 contour.causal31_receiver_observer_checked(contour.causal_receiver_assignments,timestamptz,timestamptz) FROM PUBLIC;
-- Resolver-only composition; all returned samples are checked before carry.
CREATE FUNCTION contour.causal31_scopes_checked(a contour.causal_receiver_assignments,
 observer_scope contour.causal_receiver_assignments, ob contour.causal_observer_inbox,
 ps contour.causal_sessions, at_time timestamptz, lower_at timestamptz)
RETURNS contour.causal31_clock_result LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE checked_at timestamptz:=lower_at; nested contour.causal31_clock_result;
BEGIN
 IF at_time IS NULL OR lower_at IS NULL OR NOT isfinite(at_time) OR NOT isfinite(lower_at) OR lower_at<at_time
 THEN RETURN (false,lower_at)::contour.causal31_clock_result; END IF;
 IF a.tenant_id IS NOT NULL THEN
  nested:=contour.causal31_receiver_assignment_checked(a,at_time,checked_at);
 ELSIF ob.tenant_id IS NOT NULL THEN
  nested:=contour.causal31_receiver_enrollment_checked(observer_scope,at_time,checked_at);
 END IF;
 IF a.tenant_id IS NOT NULL OR ob.tenant_id IS NOT NULL THEN
  IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
  THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
  checked_at:=nested.checked_at;
 END IF;
 IF ob.tenant_id IS NOT NULL THEN
  IF a.tenant_id IS NOT NULL THEN
   nested:=contour.causal31_receiver_observer_checked(a,at_time,checked_at);
  ELSE
   nested:=contour.causal31_receiver_observer_checked(observer_scope,at_time,checked_at);
  END IF;
  IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
  THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
  checked_at:=nested.checked_at;
  nested:=contour.causal31_session_checked(ps.claim,ob.session_epoch,checked_at);
  IF nested.valid IS NOT TRUE OR nested.checked_at IS NULL OR NOT isfinite(nested.checked_at) OR nested.checked_at<checked_at
  THEN RETURN (false,checked_at)::contour.causal31_clock_result; END IF;
  checked_at:=nested.checked_at;
 END IF;
 RETURN (true,checked_at)::contour.causal31_clock_result;
END $$;
REVOKE ALL ON FUNCTION contour.causal31_scopes_checked(contour.causal_receiver_assignments,contour.causal_receiver_assignments,contour.causal_observer_inbox,contour.causal_sessions,timestamptz,timestamptz) FROM PUBLIC;

-- Immutable edge and provenance, visible only through a future human boundary.
CREATE TABLE contour.causal_resolved_edges (
 tenant_id uuid NOT NULL,gateway_id uuid NOT NULL,gateway_generation text NOT NULL,delivery_handle text NOT NULL,
 request_collector_id uuid NOT NULL,request_batch_id uuid NOT NULL,request_record_id uuid NOT NULL,
 producer_project_id uuid NOT NULL,producer_service_id uuid NOT NULL,
 receiver_project_id uuid NOT NULL,receiver_service_id uuid NOT NULL,
 canonical_edge bytea NOT NULL CHECK(octet_length(canonical_edge) BETWEEN 1 AND 8192),
 provenance bytea NOT NULL CHECK(octet_length(provenance) BETWEEN 1 AND 16384),
 resolved_at timestamptz NOT NULL CHECK(isfinite(resolved_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at=resolved_at+interval '30 days'),
 edge_charge bigint NOT NULL CHECK(edge_charge=octet_length(canonical_edge)+256),
 provenance_charge bigint NOT NULL CHECK(provenance_charge=octet_length(provenance)+256),
 PRIMARY KEY(tenant_id,gateway_id,gateway_generation,delivery_handle),
 FOREIGN KEY(tenant_id,gateway_id,gateway_generation,delivery_handle) REFERENCES contour.causal_receiver_assignments
);
ALTER TABLE contour.causal_resolved_edges ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_resolved_edges FORCE ROW LEVEL SECURITY;
CREATE POLICY resolved_edge_owner ON contour.causal_resolved_edges TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.causal_resolved_edges FROM PUBLIC,contour_runtime;
CREATE TRIGGER resolved_edge_immutable BEFORE UPDATE OR DELETE ON contour.causal_resolved_edges FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER resolved_edge_no_truncate BEFORE TRUNCATE ON contour.causal_resolved_edges FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();
-- Current-authority checks are repeated after writes, before returning.
CREATE FUNCTION contour.resolve_causal_delivery(t uuid, gw uuid, gen text, handle text)
RETURNS bytea LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog SET TimeZone='UTC' AS $$
DECLARE gateway contour.causal_gateway_enrollments; gateway2 contour.causal_gateway_enrollments;
 a contour.causal_receiver_assignments; a2 contour.causal_receiver_assignments; observer_scope contour.causal_receiver_assignments; observer_wire jsonb;
 receiver contour.causal_receiver_enrollments; receiver2 contour.causal_receiver_enrollments;
 rb contour.causal_runtime_bindings; rb2 contour.causal_runtime_bindings;
 ob contour.causal_observer_inbox; ob2 contour.causal_observer_inbox;
 pb contour.causal_runtime_bindings; pb2 contour.causal_runtime_bindings;
 marker contour.causal_marker_bindings; marker2 contour.causal_marker_bindings; ps contour.causal_sessions; rs contour.causal_sessions;
 attempt_event contour.causal_inbox_events; root_event contour.causal_inbox_events;
 attempt_batch contour.causal_inbox_batches; root_batch contour.causal_inbox_batches;
 prior contour.causal_resolved_edges; parent_provenance jsonb; leaf bytea; col uuid; floor_at timestamptz;
 initial_at timestamptz; final_at timestamptz; return_at timestamptz; checked_at timestamptz; scope_result contour.causal31_clock_result; used bigint; edge bytea; provenance bytea; charge bigint; rb_at timestamptz;
BEGIN
 IF t IS NULL OR gw IS NULL OR gen IS NULL OR handle IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR handle COLLATE "C" !~ '^[0-9a-f]{32}$'
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 PERFORM contour.begin_origin_operation(t);
 SELECT * INTO gateway FROM contour.causal_gateway_enrollments x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen);
 SELECT * INTO a FROM contour.causal_receiver_assignments x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 SELECT * INTO ob FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF gateway.tenant_id IS NULL THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 IF a.tenant_id IS NOT NULL THEN
  SELECT * INTO receiver FROM contour.causal_receiver_enrollments x WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,a.receiver_runtime_id,a.receiver_session_epoch);
  SELECT * INTO rb FROM contour.causal_runtime_bindings x WHERE (x.tenant_id,x.runtime_id)=(t,a.receiver_runtime_id);
 ELSIF ob.tenant_id IS NOT NULL THEN
  observer_wire:=contour.observer_wire(ob.canonical_fact)->'binding';
  SELECT * INTO receiver FROM contour.causal_receiver_enrollments x
   WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,(observer_wire->>'receiver_runtime_id')::uuid,(observer_wire->>'receiver_session_epoch')::numeric);
  SELECT * INTO rb FROM contour.causal_runtime_bindings x
   WHERE (x.tenant_id,x.runtime_id)=(t,(observer_wire->>'receiver_runtime_id')::uuid);
 END IF;
 IF ob.tenant_id IS NOT NULL THEN
  SELECT * INTO pb FROM contour.causal_runtime_bindings x WHERE (x.tenant_id,x.runtime_id)=(t,ob.runtime_id);
  SELECT * INTO marker FROM contour.causal_marker_bindings x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,ob.runtime_id,ob.session_epoch);
 END IF;
 FOR leaf IN SELECT DISTINCT ON(k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM
  (VALUES((gateway.claim).observer_leaf),((gateway.claim).backend_client_leaf),((receiver.claim).product_leaf),((receiver.claim).export_leaf),((receiver.claim).backend_leaf),((receiver.claim).evidence_leaf),(pb.export_leaf_sha256),(marker.product_leaf_sha256)) leaves(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 FOR col IN SELECT DISTINCT ON(k) v FROM (SELECT v,contour.collector_lock_key(t,v) k FROM
  (VALUES((gateway.claim).collector_id),(rb.collector_id),(pb.collector_id)) cols(v) WHERE v IS NOT NULL) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_collector(t,col); END LOOP;
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=t FOR UPDATE;
 SELECT * INTO gateway2 FROM contour.causal_gateway_enrollments x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen) FOR SHARE;
 SELECT * INTO a2 FROM contour.causal_receiver_assignments x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 SELECT * INTO ob2 FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF a.tenant_id IS NOT NULL THEN
  SELECT * INTO receiver2 FROM contour.causal_receiver_enrollments x WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
  SELECT * INTO rs FROM contour.causal_sessions x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,a.receiver_runtime_id,a.receiver_session_epoch) FOR SHARE;
  SELECT * INTO rb2 FROM contour.causal_runtime_bindings x WHERE (x.tenant_id,x.runtime_id)=(t,a.receiver_runtime_id) FOR SHARE;
 ELSIF ob.tenant_id IS NOT NULL THEN
  SELECT * INTO receiver2 FROM contour.causal_receiver_enrollments x
   WHERE (x.tenant_id,x.runtime_id,x.session_epoch)=(t,(observer_wire->>'receiver_runtime_id')::uuid,(observer_wire->>'receiver_session_epoch')::numeric) FOR SHARE;
  SELECT * INTO rs FROM contour.causal_sessions x
   WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,(observer_wire->>'receiver_runtime_id')::uuid,(observer_wire->>'receiver_session_epoch')::numeric) FOR SHARE;
  SELECT * INTO rb2 FROM contour.causal_runtime_bindings x
   WHERE (x.tenant_id,x.runtime_id)=(t,(observer_wire->>'receiver_runtime_id')::uuid) FOR SHARE;
 END IF;
 IF ob.tenant_id IS NOT NULL THEN
  SELECT * INTO pb2 FROM contour.causal_runtime_bindings x WHERE (x.tenant_id,x.runtime_id)=(t,ob.runtime_id) FOR SHARE;
  SELECT * INTO marker2 FROM contour.causal_marker_bindings x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,ob.runtime_id,ob.session_epoch) FOR SHARE;
  SELECT * INTO ps FROM contour.causal_sessions x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,ob.runtime_id,ob.session_epoch) FOR SHARE;
 END IF;
 -- The observer supplies its intended receiver scope even before receiver
 -- admission. This is only an input to the private origin/proof predicate;
 -- it does not assert a committed receiver assignment.
 IF ob.tenant_id IS NOT NULL AND a.tenant_id IS NULL THEN
  observer_wire:=contour.observer_wire(ob.canonical_fact)->'binding';
  observer_scope.tenant_id:=t; observer_scope.gateway_id:=gw;
  observer_scope.gateway_generation:=gen; observer_scope.delivery_handle:=handle;
  observer_scope.receiver_runtime_id:=(observer_wire->>'receiver_runtime_id')::uuid;
  observer_scope.receiver_session_epoch:=(observer_wire->>'receiver_session_epoch')::numeric;
  observer_scope.binding_digest:=encode(sha256(convert_to(E'apicontour/causal-evidence/binding/1\n','UTF8')||convert_to(contour.causal_json_canonical(observer_wire),'UTF8')),'hex');
  observer_scope.local_root:=repeat('0',32);
  observer_scope.enrollment_generation:=receiver.enrollment_generation;
  observer_scope.evidence_credential_id:=receiver.evidence_credential_id;
  observer_scope.evidence_peer_leaf:=(receiver.claim).evidence_leaf;
  observer_scope.metadata:=contour.receiver_assignment_metadata(observer_scope);
  observer_scope.charged_bytes:=octet_length(observer_scope.metadata)+256;
 END IF;
 initial_at:=clock_timestamp();
 IF initial_at IS NULL OR NOT isfinite(initial_at) OR (floor_at IS NOT NULL AND initial_at<floor_at)
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 checked_at:=initial_at;
 scope_result:=contour.causal31_scopes_checked(a,observer_scope,ob,ps,initial_at,checked_at);
 IF scope_result.valid IS NOT TRUE OR scope_result.checked_at IS NULL OR NOT isfinite(scope_result.checked_at) OR scope_result.checked_at<checked_at
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 checked_at:=scope_result.checked_at;
 IF gateway2 IS DISTINCT FROM gateway OR a2 IS DISTINCT FROM a OR ob2 IS DISTINCT FROM ob OR receiver2 IS DISTINCT FROM receiver OR rb2 IS DISTINCT FROM rb OR pb2 IS DISTINCT FROM pb OR marker2 IS DISTINCT FROM marker
 OR initial_at IS NULL OR NOT isfinite(initial_at) OR (floor_at IS NOT NULL AND initial_at<floor_at)
 OR initial_at<gateway.issued_at OR initial_at>=gateway.expires_at OR contour.gateway_claim_current(gateway.claim,initial_at) IS NOT TRUE
 OR gateway.metadata IS DISTINCT FROM contour.gateway_enrollment_metadata(gateway.claim,gateway.generation,gateway.issued_at,gateway.expires_at)
 OR gateway.charged_bytes<>octet_length(gateway.metadata)+octet_length((gateway.claim).policy_envelope)+256
 OR NOT EXISTS(SELECT 1 FROM contour.causal_gateway_terminal_reservations x WHERE (x.tenant_id,x.gateway_id,x.generation,x.charged_bytes)=(t,gw,gen,1024))
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen))
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations x WHERE x.leaf_sha256=(gateway.claim).observer_leaf AND x.leaf_class='gateway_observer')
 OR NOT EXISTS(SELECT 1 FROM contour.causal_leaf_reservations x WHERE x.leaf_sha256=(gateway.claim).backend_client_leaf AND x.leaf_class='gateway_backend')
 OR (ob.tenant_id IS NOT NULL AND contour.causal_marker_product_current(t,pb,marker.product_credential_id,marker.product_leaf_sha256,initial_at) IS NOT TRUE)
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 IF a.tenant_id IS NULL OR ob.tenant_id IS NULL THEN
  -- A missing fact must not bypass the final authority and clock check.
  final_at:=clock_timestamp();
  IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<checked_at
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  checked_at:=final_at;
  scope_result:=contour.causal31_scopes_checked(a,observer_scope,ob,ps,final_at,checked_at);
  IF scope_result.valid IS NOT TRUE OR scope_result.checked_at IS NULL OR NOT isfinite(scope_result.checked_at) OR scope_result.checked_at<checked_at
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  checked_at:=scope_result.checked_at;
  IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at
   OR (floor_at IS NOT NULL AND final_at<floor_at)
   OR final_at>=gateway.expires_at OR contour.gateway_claim_current(gateway.claim,final_at) IS NOT TRUE
   OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen))
   OR (ob.tenant_id IS NOT NULL AND contour.causal_marker_product_current(t,pb,marker.product_credential_id,marker.product_leaf_sha256,final_at) IS NOT TRUE)
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  return_at:=clock_timestamp();
  IF return_at IS NULL OR NOT isfinite(return_at) OR return_at<checked_at
   OR return_at>=gateway.expires_at OR return_at>=(gateway.claim).policy_expires
   OR ((a.tenant_id IS NOT NULL OR ob.tenant_id IS NOT NULL) AND
       (return_at>=receiver.expires_at OR return_at>=(receiver.claim).backend_not_after
        OR return_at>=(receiver.claim).evidence_not_after OR return_at>=rs.expires_at
        OR return_at>=(rs.claim).grant_expires OR return_at>=(rs.claim).policy_expires))
   OR (a.tenant_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM contour.causal_receiver_inbox x
       WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle)
        AND return_at>=x.accepted_at AND return_at<x.expires_at))
   OR (ob.tenant_id IS NOT NULL AND (return_at>=ps.expires_at OR return_at>=(ps.claim).grant_expires
       OR return_at>=(ps.claim).policy_expires OR return_at<ob.accepted_at OR return_at>=ob.expires_at))
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  IF a.tenant_id IS NOT NULL AND ob.tenant_id IS NOT NULL THEN
   PERFORM contour.causal_join_facts_valid(t,gw,gen,handle,return_at);
  END IF;
  UPDATE contour.origin_tenant_state SET clock_floor=return_at WHERE tenant_id=t;
  RETURN NULL;
 END IF;
 -- Lock attempt assignment, delivery assignment and facts after enrollment rows.
 PERFORM 1 FROM contour.causal_observer_attempt_reservations x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.attempt)=(t,ob.runtime_id,ob.session_epoch,ob.attempt) FOR SHARE;
 PERFORM 1 FROM contour.causal_receiver_assignments x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle) FOR SHARE;
 PERFORM 1 FROM contour.causal_observer_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle) FOR SHARE;
 PERFORM 1 FROM contour.causal_receiver_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle) FOR SHARE;
 IF contour.causal_join_facts_valid(t,gw,gen,handle,initial_at) IS NOT TRUE THEN
  final_at:=clock_timestamp();
  IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<checked_at
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  checked_at:=final_at;
  scope_result:=contour.causal31_scopes_checked(a,observer_scope,ob,ps,final_at,checked_at);
  IF scope_result.valid IS NOT TRUE OR scope_result.checked_at IS NULL OR NOT isfinite(scope_result.checked_at) OR scope_result.checked_at<checked_at
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  checked_at:=scope_result.checked_at;
  IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at
   OR (floor_at IS NOT NULL AND final_at<floor_at) OR final_at>=gateway.expires_at
   OR contour.gateway_claim_current(gateway.claim,final_at) IS NOT TRUE
   OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen))
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  return_at:=clock_timestamp();
  IF return_at IS NULL OR NOT isfinite(return_at) OR return_at<checked_at
   OR return_at>=gateway.expires_at OR return_at>=(gateway.claim).policy_expires
   OR ((a.tenant_id IS NOT NULL OR ob.tenant_id IS NOT NULL) AND
       (return_at>=receiver.expires_at OR return_at>=(receiver.claim).backend_not_after
        OR return_at>=(receiver.claim).evidence_not_after OR return_at>=rs.expires_at
        OR return_at>=(rs.claim).grant_expires OR return_at>=(rs.claim).policy_expires))
   OR (a.tenant_id IS NOT NULL AND NOT EXISTS(SELECT 1 FROM contour.causal_receiver_inbox x
       WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle)
        AND return_at>=x.accepted_at AND return_at<x.expires_at))
   OR (ob.tenant_id IS NOT NULL AND (return_at>=ps.expires_at OR return_at>=(ps.claim).grant_expires
       OR return_at>=(ps.claim).policy_expires OR return_at<ob.accepted_at OR return_at>=ob.expires_at))
  THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  IF a.tenant_id IS NOT NULL AND ob.tenant_id IS NOT NULL THEN
   PERFORM contour.causal_join_facts_valid(t,gw,gen,handle,return_at);
  END IF;
  UPDATE contour.origin_tenant_state SET clock_floor=return_at WHERE tenant_id=t;
  RETURN NULL;
 END IF;
 SELECT * INTO STRICT attempt_event FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.attempt)=(t,ob.runtime_id,ob.session_epoch,'attempt',ob.attempt);
 SELECT * INTO STRICT root_event FROM contour.causal_inbox_events x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.kind,x.root)=(t,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root);
 SELECT * INTO STRICT attempt_batch FROM contour.causal_inbox_batches x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,ob.runtime_id,ob.session_epoch,attempt_event.batch_id);
 SELECT * INTO STRICT root_batch FROM contour.causal_inbox_batches x WHERE (x.tenant_id,x.runtime_id,x.session_epoch,x.batch_id)=(t,a.receiver_runtime_id,a.receiver_session_epoch,root_event.batch_id);
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<checked_at
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 checked_at:=final_at;
 scope_result:=contour.causal31_scopes_checked(a,observer_scope,ob,ps,final_at,checked_at);
 IF scope_result.valid IS NOT TRUE OR scope_result.checked_at IS NULL OR NOT isfinite(scope_result.checked_at) OR scope_result.checked_at<checked_at
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 checked_at:=scope_result.checked_at;
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at)
 OR final_at>=gateway.expires_at OR contour.gateway_claim_current(gateway.claim,final_at) IS NOT TRUE
 OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals x WHERE (x.tenant_id,x.gateway_id,x.generation)=(t,gw,gen))
 OR contour.causal_marker_product_current(t,pb,marker.product_credential_id,marker.product_leaf_sha256,final_at) IS NOT TRUE
 OR final_at<attempt_batch.accepted_at OR final_at>=attempt_batch.accepted_at+interval '24 hours'
 OR final_at<root_batch.accepted_at OR final_at>=root_batch.accepted_at+interval '24 hours'
 OR contour.causal_join_facts_valid(t,gw,gen,handle,final_at) IS NOT TRUE
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 -- Record only required predecessors, ordered from the selected delivery
 -- backwards. A successor committed later cannot change this retry body.
 WITH RECURSIVE parents AS (
  SELECT x.delivery_handle,x.retry_of,x.fact_digest,1 AS depth
   FROM contour.causal_observer_inbox x
   WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,ob.retry_of)
  UNION ALL
  SELECT x.delivery_handle,x.retry_of,x.fact_digest,p.depth+1
   FROM parents p JOIN contour.causal_observer_inbox x
    ON (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,p.retry_of)
 )
 SELECT coalesce(jsonb_agg(jsonb_build_object('delivery_handle',delivery_handle,
   'observer_digest',encode(fact_digest,'hex')) ORDER BY depth),'[]'::jsonb)
 INTO parent_provenance FROM parents;
 SELECT * INTO prior FROM contour.causal_resolved_edges x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle);
 IF FOUND THEN
  rb_at:=prior.resolved_at;
 ELSE
  rb_at:=final_at;
 END IF;

  IF rb_at IS NULL OR NOT isfinite(rb_at) OR (prior.tenant_id IS NULL AND rb_at<initial_at) OR rb_at<timestamptz '0001-01-01 00:00:00+00' OR rb_at>=timestamptz '9999-12-01 00:00:00+00' THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  edge:=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'tenant_id',t,'gateway_id',gw,'gateway_generation',gen,'delivery_handle',handle,
   'producer_runtime_id',ob.runtime_id,'producer_session_epoch',ob.session_epoch::text,'producer_root',ob.marker_root,'producer_activity',ob.marker_activity,
   'receiver_runtime_id',a.receiver_runtime_id,'receiver_session_epoch',a.receiver_session_epoch::text,'receiver_root',a.local_root,
   'resolved_at',to_char(rb_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),'UTF8');
  provenance:=convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'tenant_id',t,'gateway_id',gw,'gateway_generation',gen,'delivery_handle',handle,
   'producer_project_id',pb.project_id,'producer_service_id',pb.service_id,'producer_environment_id',pb.environment_id,'producer_deployment_id',pb.deployment_id,'producer_instance_id',pb.instance_id,
   'receiver_project_id',rb.project_id,'receiver_service_id',rb.service_id,'receiver_environment_id',rb.environment_id,'receiver_deployment_id',rb.deployment_id,'receiver_instance_id',rb.instance_id,
   'producer_batch_id',attempt_event.batch_id,'producer_event_id',attempt_event.event_id,'producer_event_digest',encode(attempt_event.event_digest,'hex'),
   'producer_batch_digest',encode(attempt_batch.batch_digest,'hex'),'producer_receipt_id',attempt_batch.receipt_id,'producer_receipt_digest',encode(attempt_batch.receipt_digest,'hex'),
   'receiver_batch_digest',encode(root_batch.batch_digest,'hex'),'receiver_receipt_id',root_batch.receipt_id,'receiver_receipt_digest',encode(root_batch.receipt_digest,'hex'),
   'receiver_batch_id',root_event.batch_id,'receiver_event_id',root_event.event_id,'receiver_event_digest',encode(root_event.event_digest,'hex'),
   'observer_digest',encode(ob.fact_digest,'hex'),'observer_predecessors',parent_provenance,'receiver_digest',(SELECT encode(x.fact_digest,'hex') FROM contour.causal_receiver_inbox x WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle)),
   'collector_id',ob.collector_id,'request_batch_id',ob.batch_id,'request_record_id',ob.record_id,'origin_proof_id',ob.proof_id,
   'producer_attempt',ob.attempt,'marker_root',ob.marker_root,'marker_activity',ob.marker_activity,'marker_public',encode(ob.marker_public,'hex'),
   'marker_nonce',marker.nonce,'marker_generation',encode(marker.generation,'hex'),
   'marker_credential_id',marker.product_credential_id,'marker_product_leaf',encode(marker.product_leaf_sha256,'hex'),
   'marker_lifecycle_id',marker.lifecycle_id,'marker_instance_id',marker.instance_id,'marker_profile_id',marker.profile_id,'marker_artifact',encode(marker.artifact_sha256,'hex'),
   'request_source_id',(gateway.claim).source_id,
   'marker_digest',attempt_event.marker_digest,'binding_digest',a.binding_digest,
   'resolved_at',to_char(rb_at AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),'UTF8');
  IF prior.tenant_id IS NOT NULL THEN
   IF (prior.request_collector_id,prior.request_batch_id,prior.request_record_id,
       prior.producer_project_id,prior.producer_service_id,prior.receiver_project_id,prior.receiver_service_id)
      IS DISTINCT FROM (ob.collector_id,ob.batch_id,ob.record_id,pb.project_id,pb.service_id,rb.project_id,rb.service_id)
    OR prior.canonical_edge IS DISTINCT FROM edge OR prior.provenance IS DISTINCT FROM provenance
    OR prior.expires_at IS DISTINCT FROM prior.resolved_at+interval '30 days'
    OR prior.edge_charge IS DISTINCT FROM octet_length(edge)+256
    OR prior.provenance_charge IS DISTINCT FROM octet_length(provenance)+256
   THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
  ELSE
  charge:=octet_length(edge)+256+octet_length(provenance)+256;
  IF octet_length(edge)>8192 OR octet_length(provenance)>16384 OR charge>1073741824-used THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='54000'; END IF;
  INSERT INTO contour.causal_resolved_edges(
   tenant_id,gateway_id,gateway_generation,delivery_handle,
   request_collector_id,request_batch_id,request_record_id,
   producer_project_id,producer_service_id,receiver_project_id,receiver_service_id,
   canonical_edge,provenance,resolved_at,expires_at,edge_charge,provenance_charge)
  VALUES(t,gw,gen,handle,ob.collector_id,ob.batch_id,ob.record_id,
   pb.project_id,pb.service_id,rb.project_id,rb.service_id,
   edge,provenance,rb_at,rb_at+interval '30 days',octet_length(edge)+256,octet_length(provenance)+256);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge WHERE tenant_id=t;
 END IF;
 -- final_at is the logical time supplied to the last complete authority
 -- evaluation under the held gates. SQL19/28 session helpers also take their
 -- own later clock samples. After immutable insertion and quota accounting,
 -- a fresh clock checks every time-dependent bound; any expiry rolls back all
 -- writes. The gates must continue to serialize all authority mutations.
 return_at:=clock_timestamp();
 IF return_at IS NULL OR NOT isfinite(return_at) OR return_at<checked_at
 OR (floor_at IS NOT NULL AND return_at<floor_at)
 OR return_at>=gateway.expires_at OR return_at>=(gateway.claim).policy_expires
 OR return_at>=receiver.expires_at OR return_at>=(receiver.claim).backend_not_after
 OR return_at>=(receiver.claim).evidence_not_after
 OR return_at>=ps.expires_at OR return_at>=(ps.claim).grant_expires OR return_at>=(ps.claim).policy_expires
 OR return_at>=rs.expires_at OR return_at>=(rs.claim).grant_expires OR return_at>=(rs.claim).policy_expires
 OR return_at<attempt_batch.accepted_at OR return_at>=attempt_batch.accepted_at+interval '24 hours'
 OR return_at<root_batch.accepted_at OR return_at>=root_batch.accepted_at+interval '24 hours'
 OR NOT EXISTS(SELECT 1 FROM contour.causal_receiver_inbox x
  WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle)
   AND return_at>=x.accepted_at AND return_at<x.expires_at)
 OR EXISTS(WITH RECURSIVE required AS (
  SELECT x.delivery_handle,x.retry_of,x.accepted_at,x.expires_at
   FROM contour.causal_observer_inbox x
   WHERE (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,handle)
  UNION ALL
  SELECT x.delivery_handle,x.retry_of,x.accepted_at,x.expires_at
   FROM required r JOIN contour.causal_observer_inbox x
    ON (x.tenant_id,x.gateway_id,x.gateway_generation,x.delivery_handle)=(t,gw,gen,r.retry_of)
 ) SELECT 1 FROM required r WHERE return_at<r.accepted_at OR return_at>=r.expires_at)
 THEN RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=return_at WHERE tenant_id=t;
 RETURN edge;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
 RAISE EXCEPTION 'causal resolution unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.resolve_causal_delivery(uuid,uuid,text,text) FROM PUBLIC,contour_runtime;
GRANT USAGE ON SCHEMA contour TO contour_causal_reconciler;
GRANT EXECUTE ON FUNCTION contour.resolve_causal_delivery(uuid,uuid,text,text) TO contour_causal_reconciler;
INSERT INTO contour.schema_migrations(version) VALUES(31);
COMMIT;
