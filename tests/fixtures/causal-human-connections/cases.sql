-- SQL31 committed edge and the public catalog observation must agree exactly.
-- This fixture may use the same service at both ends; it does not establish
-- independent cross-service authorization.
CREATE TEMP TABLE human32_case AS
 SELECT e.tenant_id, w.project_id, w.service_id, w.environment_id, w.operation_id,
        w.observation_id, e.gateway_id, e.gateway_generation, e.delivery_handle,
        jsonb_build_object('producer',jsonb_build_object('project_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_project_id','service_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_service_id','environment_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_environment_id','deployment_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_deployment_id','instance_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_instance_id','batch_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_batch_id','event_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_event_id','receipt_id',convert_from(e.provenance,'UTF8')::jsonb->>'producer_receipt_id'),'receiver',jsonb_build_object('project_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_project_id','service_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_service_id','environment_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_environment_id','deployment_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_deployment_id','instance_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_instance_id','batch_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_batch_id','event_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_event_id','receipt_id',convert_from(e.provenance,'UTF8')::jsonb->>'receiver_receipt_id')) AS expected_refs,
        e.resolved_at, e.expires_at
 FROM contour.causal_resolved_edges e JOIN edge_control k
 ON (e.tenant_id,e.gateway_id,e.gateway_generation,e.delivery_handle)=(k.tenant_id,k.gateway_id,k.generation,k.handle)
 JOIN contour.observation_windows w ON (w.tenant_id,w.collector_id,w.batch_id,w.record_id)=
 (e.tenant_id,e.request_collector_id,e.request_batch_id,e.request_record_id);
DO $$ BEGIN IF (SELECT count(*) FROM human32_case)<>1 THEN RAISE EXCEPTION 'exact committed observation missing'; END IF; END $$;
GRANT SELECT ON human32_case TO contour_catalog_reader, contour_human_provisioner;
BEGIN;
SET LOCAL ROLE contour_catalog_reader;
DO $$ DECLARE c record; result jsonb; item jsonb; side text; key text; denied boolean;
BEGIN
 SELECT * INTO STRICT c FROM human32_case;
 BEGIN PERFORM count(*) FROM contour.causal_resolved_edges; RAISE EXCEPTION 'raw edge read allowed';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
 result:=contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
  'https://idp.example.test/realms/demo','synthetic-user',NULL,NULL,NULL,1);
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(result) k) IS DISTINCT FROM ARRAY['items','next_cursor']
 OR jsonb_array_length(result->'items')<>1 OR result->'next_cursor'<>'null'::jsonb THEN RAISE EXCEPTION 'reader page shape'; END IF;
 item:=result->'items'->0;
 IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(item) k) IS DISTINCT FROM ARRAY['expires_at','producer','receiver','resolved_at']
 OR (item->>'resolved_at')::timestamptz IS DISTINCT FROM c.resolved_at
 OR (item->>'expires_at')::timestamptz IS DISTINCT FROM c.expires_at THEN RAISE EXCEPTION 'reader item shape'; END IF;
 FOREACH side IN ARRAY ARRAY['producer','receiver'] LOOP
  IF (SELECT array_agg(k ORDER BY k) FROM jsonb_object_keys(item->side) k) IS DISTINCT FROM
   ARRAY['batch_id','deployment_id','environment_id','event_id','instance_id','project_id','receipt_id','service_id'] THEN RAISE EXCEPTION 'endpoint shape'; END IF;
  FOREACH key IN ARRAY ARRAY['project_id','service_id','environment_id','deployment_id','instance_id','batch_id','event_id','receipt_id'] LOOP
   IF jsonb_typeof(item->side->key) IS DISTINCT FROM 'string'
    OR item->side->>key IS DISTINCT FROM c.expected_refs->side->>key THEN RAISE EXCEPTION 'endpoint reference mismatch'; END IF;
  END LOOP;
 END LOOP;
 denied:=false; BEGIN
  PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
   'https://idp.example.test/realms/demo','synthetic-user','ffffffff-ffff-ffff-ffff-ffffffffffff',repeat('0',32),repeat('0',32),1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'absent cursor accepted'; END IF;
 denied:=false; BEGIN
  PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
   'https://idp.example.test/realms/demo','synthetic-user',c.gateway_id,NULL,c.delivery_handle,1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'partial cursor accepted'; END IF;
 denied:=false; BEGIN
  PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
   'https://idp.example.test/realms/demo','synthetic-user',c.gateway_id,repeat('A',32),c.delivery_handle,1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'invalid cursor generation accepted'; END IF;
 denied:=false; BEGIN
  PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
   'https://idp.example.test/realms/demo','synthetic-user',c.gateway_id,c.gateway_generation,repeat('0',31),1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'invalid cursor handle accepted'; END IF;
 denied:=false; BEGIN
  PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
   'https://idp.example.test/realms/demo','unknown-user',NULL,NULL,NULL,1);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'unknown user accepted'; END IF;
END $$;
ROLLBACK;
-- Revoke the provisioned configured service role in a rolled-back transaction.
BEGIN;
SET LOCAL ROLE contour_human_provisioner;
UPDATE contour.human_service_roles SET enabled=false WHERE actor_id='00000000-0000-0000-0000-00000000ef01'
 AND (tenant_id,project_id,service_id)=(SELECT tenant_id,project_id,service_id FROM human32_case);
RESET ROLE;
SET LOCAL ROLE contour_catalog_reader;
DO $$ DECLARE c record; denied boolean:=false; BEGIN
 SELECT * INTO STRICT c FROM human32_case;
 BEGIN PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',NULL,NULL,NULL,1);
 EXCEPTION WHEN insufficient_privilege THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'revoked configured scope accepted'; END IF;
END $$;
ROLLBACK;
-- Rolled-back fault injection: SQL31 produced the real edge above.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET producer_service_id='ffffffff-ffff-ffff-ffff-ffffffffffff'
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,gateway_generation,delivery_handle FROM human32_case);
ALTER TABLE contour.causal_resolved_edges ENABLE TRIGGER resolved_edge_immutable;
-- Hidden corrupt rows must not leak through a cursor or page count.
SET LOCAL ROLE contour_catalog_reader;
DO $$ DECLARE c record; result jsonb; denied boolean:=false; BEGIN
 SELECT * INTO STRICT c FROM human32_case;
 result:=contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',NULL,NULL,NULL,1);
 IF result IS DISTINCT FROM '{"items":[],"next_cursor":null}'::jsonb THEN RAISE EXCEPTION 'hidden edge leaked'; END IF;
 BEGIN PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',c.gateway_id,c.gateway_generation,c.delivery_handle,1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'hidden cursor accepted'; END IF;
END $$;
ROLLBACK;
-- The same authorized row with inconsistent provenance fails closed.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET provenance=convert_to('{}','UTF8'), provenance_charge=258
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,gateway_generation,delivery_handle FROM human32_case);
ALTER TABLE contour.causal_resolved_edges ENABLE TRIGGER resolved_edge_immutable;
SET LOCAL ROLE contour_catalog_reader;
DO $$ DECLARE c record; denied boolean:=false; BEGIN
 SELECT * INTO STRICT c FROM human32_case;
 BEGIN PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',NULL,NULL,NULL,1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'mismatched provenance accepted'; END IF;
END $$;
ROLLBACK;
-- Expiry filters before provenance parsing and yields the same empty page and
-- generic cursor failure as an absent key.
BEGIN;
ALTER TABLE contour.causal_resolved_edges DISABLE TRIGGER resolved_edge_immutable;
UPDATE contour.causal_resolved_edges SET resolved_at=transaction_timestamp()-interval '31 days', expires_at=transaction_timestamp()-interval '1 day',
 provenance=convert_to('{}','UTF8'), provenance_charge=258
 WHERE (tenant_id,gateway_id,gateway_generation,delivery_handle)=
 (SELECT tenant_id,gateway_id,gateway_generation,delivery_handle FROM human32_case);
ALTER TABLE contour.causal_resolved_edges ENABLE TRIGGER resolved_edge_immutable;
SET LOCAL ROLE contour_catalog_reader;
DO $$ DECLARE c record; result jsonb; denied boolean:=false; BEGIN
 SELECT * INTO STRICT c FROM human32_case;
 result:=contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',NULL,NULL,NULL,1);
 IF result IS DISTINCT FROM '{"items":[],"next_cursor":null}'::jsonb THEN RAISE EXCEPTION 'expired edge leaked'; END IF;
 BEGIN PERFORM contour.human_causal_connections(c.tenant_id,c.project_id,c.service_id,c.environment_id,c.operation_id,c.observation_id,
 'https://idp.example.test/realms/demo','synthetic-user',c.gateway_id,c.gateway_generation,c.delivery_handle,1);
 EXCEPTION WHEN check_violation THEN denied:=true; END;
 IF NOT denied THEN RAISE EXCEPTION 'expired cursor accepted'; END IF;
END $$;
ROLLBACK;
