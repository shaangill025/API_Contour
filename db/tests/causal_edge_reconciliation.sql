-- Disposable SQL31 controls: the harness must commit valid observer-first
-- receiver_pairs plus matching SQL20 attempt/root through the public writers.
-- Run only after independent review of SQL31. These controls do not prove TLS.
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM pg_proc p WHERE p.oid='contour.resolve_causal_delivery(uuid,uuid,text,text)'::regprocedure
  AND 'TimeZone=UTC'=ANY(p.proconfig)) THEN RAISE EXCEPTION 'resolver timezone not fixed'; END IF;
 IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_causal_reconciler'
  AND NOT rolcanlogin AND NOT rolsuper AND NOT rolbypassrls)
 OR NOT has_function_privilege('contour_causal_reconciler','contour.resolve_causal_delivery(uuid,uuid,text,text)','EXECUTE')
 OR has_function_privilege('contour_runtime','contour.resolve_causal_delivery(uuid,uuid,text,text)','EXECUTE')
 OR has_function_privilege('contour_causal_reconciler','contour.causal_join_facts_valid(uuid,uuid,text,text,timestamp with time zone)','EXECUTE')
 OR has_table_privilege('contour_causal_reconciler','contour.causal_resolved_edges','SELECT,INSERT,UPDATE,DELETE,TRUNCATE')
 THEN RAISE EXCEPTION 'reconciler privileges incorrect'; END IF;
END $$;
CREATE TEMP TABLE edge_control AS
 SELECT (j->>'tenant_id')::uuid tenant_id,(j->>'gateway_id')::uuid gateway_id,
  j->>'gateway_generation' generation,j->>'delivery_handle' handle
 FROM (SELECT convert_from(receiver_raw,'UTF8')::jsonb j FROM receiver_pairs WHERE name='observer-first') q;
GRANT SELECT ON edge_control TO contour_causal_reconciler;
-- Removing the committed root in a disposable transaction leaves the join
-- unresolved and must not allocate an edge. The production API creates it.
BEGIN;
ALTER TABLE contour.causal_inbox_events DISABLE TRIGGER causal_inbox_event_immutable;
DELETE FROM contour.causal_inbox_events e USING contour.causal_receiver_assignments a,edge_control k
 WHERE (a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle)
 AND (e.tenant_id,e.runtime_id,e.session_epoch,e.kind,e.root)=(a.tenant_id,a.receiver_runtime_id,a.receiver_session_epoch,'root',a.local_root);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 IF contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle) IS NOT NULL
 THEN RAISE EXCEPTION 'missing root resolved'; END IF;
END $$;
ROLLBACK;
CREATE TEMP TABLE edge_result(edge bytea);
GRANT INSERT ON edge_result TO contour_causal_reconciler;
SET TIME ZONE 'America/Los_Angeles';
SET ROLE contour_causal_reconciler;
INSERT INTO edge_result SELECT contour.resolve_causal_delivery(tenant_id,gateway_id,generation,handle) FROM edge_control;
RESET ROLE;
RESET TIME ZONE;
DO $$ BEGIN
 IF (SELECT count(*) FROM edge_result WHERE edge IS NOT NULL)<>1 THEN RAISE EXCEPTION 'edge missing'; END IF;
 IF NOT EXISTS(SELECT 1 FROM contour.causal_resolved_edges e JOIN edge_control k
  ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle)
  WHERE e.canonical_edge=(SELECT edge FROM edge_result) AND e.expires_at=e.resolved_at+interval '720 hours'
   AND e.edge_charge=octet_length(e.canonical_edge)+256 AND e.provenance_charge=octet_length(e.provenance)+256)
 THEN RAISE EXCEPTION 'edge retention or charge mismatch'; END IF;
 IF NOT EXISTS(SELECT 1 FROM contour.causal_resolved_edges e
  JOIN contour.causal_observer_inbox o ON (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=(e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)
  JOIN contour.causal_receiver_assignments a ON (a.tenant_id,a.gateway_id,a.gateway_generation,a.delivery_handle)=(e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)
  JOIN contour.causal_runtime_bindings p ON (p.tenant_id,p.runtime_id)=(o.tenant_id,o.runtime_id)
  JOIN contour.causal_runtime_bindings r ON (r.tenant_id,r.runtime_id)=(a.tenant_id,a.receiver_runtime_id)
  JOIN edge_control k ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle)
  WHERE (e.request_collector_id,e.request_batch_id,e.request_record_id,e.producer_project_id,e.producer_service_id,e.receiver_project_id,e.receiver_service_id)
   IS NOT DISTINCT FROM (o.collector_id,o.batch_id,o.record_id,p.project_id,p.service_id,r.project_id,r.service_id))
 THEN RAISE EXCEPTION 'edge typed provenance mismatch'; END IF;
END $$;
CREATE TEMP TABLE edge_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT tenant_id FROM edge_control);
SET ROLE contour_causal_reconciler;
INSERT INTO edge_result SELECT contour.resolve_causal_delivery(tenant_id,gateway_id,generation,handle) FROM edge_control;
RESET ROLE;
DO $$ BEGIN
 IF (SELECT count(DISTINCT edge) FROM edge_result)<>1 OR (SELECT count(*) FROM edge_result)<>2
 OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT tenant_id FROM edge_control)) IS DISTINCT FROM (SELECT used_bytes FROM edge_usage)
 THEN RAISE EXCEPTION 'edge retry changed result or charge'; END IF;
END $$;
-- Test corruption only in a rolled-back disposable transaction.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET provenance=provenance||decode('20','hex'), provenance_charge=provenance_charge+1
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,generation,handle FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'corrupt provenance accepted'; END IF;
END $$;
ROLLBACK;

-- A changed typed request_collector_id must deny exact retry even when bytes match.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET request_collector_id=CASE WHEN request_collector_id='00000000-0000-0000-0000-000000000000'::uuid
 THEN 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid ELSE '00000000-0000-0000-0000-000000000000'::uuid END
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,generation,handle FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'typed request_collector_id corruption accepted'; END IF;
END $$;
ROLLBACK;

-- A changed typed producer_project_id must deny exact retry even when bytes match.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET producer_project_id=CASE WHEN producer_project_id='00000000-0000-0000-0000-000000000000'::uuid
 THEN 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid ELSE '00000000-0000-0000-0000-000000000000'::uuid END
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,generation,handle FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'typed producer_project_id corruption accepted'; END IF;
END $$;
ROLLBACK;

-- A changed typed receiver_service_id must deny exact retry even when bytes match.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET receiver_service_id=CASE WHEN receiver_service_id='00000000-0000-0000-0000-000000000000'::uuid
 THEN 'ffffffff-ffff-ffff-ffff-ffffffffffff'::uuid ELSE '00000000-0000-0000-0000-000000000000'::uuid END
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,generation,handle FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'typed receiver_service_id corruption accepted'; END IF;
END $$;
ROLLBACK;

-- Quota exhaustion cannot retain an edge or change usage in the transaction.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
DELETE FROM contour.causal_resolved_edges e USING edge_control k
 WHERE (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle);
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id=(SELECT tenant_id FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN program_limit_exceeded THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'quota exhaustion accepted'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM contour.causal_resolved_edges e JOIN edge_control k
  ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle))
 OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT tenant_id FROM edge_control))<>1073741824
 THEN RAISE EXCEPTION 'quota failure left partial state'; END IF;
END $$;
ROLLBACK;
-- Wrong tenant cannot retrieve the already committed edge.
SET ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery('ffffffff-ffff-4fff-8fff-ffffffffffff'::uuid,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation OR insufficient_privilege THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'cross-tenant edge lookup accepted'; END IF;
END $$;
RESET ROLE;
-- Trigger protection applies even to the table owner.
BEGIN;
DO $$ DECLARE rejected boolean:=false; BEGIN
 BEGIN UPDATE contour.causal_resolved_edges SET resolved_at=resolved_at WHERE
  (tenant_id,gateway_id,gateway_generation,delivery_handle)=(SELECT tenant_id,gateway_id,generation,handle FROM edge_control);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'edge update accepted'; END IF;
END $$;
ROLLBACK;

-- A closed gateway denies retry but cannot alter the historical edge.
BEGIN;
INSERT INTO contour.causal_gateway_terminals(tenant_id,gateway_id,generation,reason,effective_at,canonical_body)
 SELECT tenant_id,gateway_id,generation,'operator_revoked',clock_timestamp(),convert_to('test closure','UTF8') FROM edge_control;
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'closed gateway returned edge'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF NOT EXISTS(SELECT 1 FROM contour.causal_resolved_edges e JOIN edge_control k
  ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle)
  WHERE e.canonical_edge=(SELECT edge FROM edge_result LIMIT 1) AND e.expires_at=e.resolved_at+interval '30 days')
 THEN RAISE EXCEPTION 'revocation changed historical edge'; END IF;
END $$;
ROLLBACK;
-- Original observer cutoff applies even to an already resolved delivery.
BEGIN;
ALTER TABLE contour.causal_observer_inbox DISABLE TRIGGER observer_immutable;
UPDATE contour.causal_observer_inbox o SET accepted_at=statement_timestamp()-interval '25 hours', expires_at=statement_timestamp()-interval '1 hour'
 FROM edge_control k WHERE (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected THEN RAISE EXCEPTION 'expired observer returned edge'; END IF;
END $$;
ROLLBACK;
-- Force the observer cutoff to pass during insertion. The disposable trigger
-- proves the failure follows the write attempt and rolls back edge and quota.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
DELETE FROM contour.causal_resolved_edges e USING edge_control k
 WHERE (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle);
ALTER TABLE contour.causal_observer_inbox DISABLE TRIGGER observer_immutable;
UPDATE contour.causal_observer_inbox o
 SET accepted_at=statement_timestamp()-interval '24 hours'+interval '2 seconds',
     expires_at=statement_timestamp()+interval '2 seconds'
 FROM edge_control k WHERE (o.tenant_id,o.gateway_id,o.gateway_generation,o.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle);
CREATE FUNCTION pg_temp.edge31_delay_insert() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_sleep(3); RETURN NEW; END $$;
CREATE TRIGGER edge31_delay BEFORE INSERT ON contour.causal_resolved_edges FOR EACH ROW EXECUTE FUNCTION pg_temp.edge31_delay_insert();
CREATE TEMP TABLE edge31_before_late AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT tenant_id FROM edge_control);
SET LOCAL ROLE contour_causal_reconciler;
DO $$ DECLARE k record; rejected boolean:=false; started timestamptz:=clock_timestamp(); BEGIN
 SELECT * INTO STRICT k FROM edge_control;
 BEGIN PERFORM contour.resolve_causal_delivery(k.tenant_id,k.gateway_id,k.generation,k.handle);
 EXCEPTION WHEN check_violation THEN rejected:=true; END;
 IF NOT rejected OR clock_timestamp()-started<interval '3 seconds'
 THEN RAISE EXCEPTION 'late expiry did not reach insert or was accepted'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM contour.causal_resolved_edges e JOIN edge_control k
  ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle))
 OR (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=(SELECT tenant_id FROM edge_control)) IS DISTINCT FROM (SELECT used_bytes FROM edge31_before_late)
 THEN RAISE EXCEPTION 'late expiry left edge or quota charge'; END IF;
END $$;
ROLLBACK;
