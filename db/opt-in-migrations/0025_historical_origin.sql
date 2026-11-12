-- Opt-in exact immutable observation origin, never a current operation head.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR pg_catalog.current_setting('row_security') <> 'on'
 OR pg_catalog.current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,24))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted profile migration required' USING ERRCODE='42501'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
CREATE FUNCTION contour.human_observation_origin(tenant uuid, target_project uuid, target_service uuid,
 target_environment uuid, operation uuid, observation uuid)
RETURNS TABLE(origin_project_id uuid,origin_service_id uuid,origin_environment_id uuid,
 origin_deployment_id uuid,instance_id uuid,lifecycle_id uuid,credential_id uuid,grant_id uuid)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE w contour.observation_windows; m contour.ingestion_v2_metadata; p contour.origin_proofs;
 payload bytea; envelope jsonb; checked_record jsonb; payload_format integer; digest_version integer;
BEGIN
 IF tenant IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() OR target_project IS NULL OR target_service IS NULL OR target_environment IS NULL OR operation IS NULL OR observation IS NULL THEN
   RAISE EXCEPTION 'invalid catalog scope' USING ERRCODE='42501'; END IF;
 SELECT x.* INTO STRICT w FROM contour.observation_windows x
 WHERE (x.tenant_id,x.project_id,x.service_id,x.environment_id,x.operation_id,x.observation_id)=(tenant,target_project,target_service,target_environment,operation,observation);
 SELECT b.digest_version INTO STRICT digest_version FROM contour.ingestion_batches b
 WHERE (b.tenant_id,b.collector_id,b.batch_id)=(tenant,w.collector_id,w.batch_id);
 SELECT b.payload_format,b.checked_batch INTO payload_format,payload FROM contour.ingestion_payloads b
 WHERE (b.tenant_id,b.collector_id,b.batch_id)=(tenant,w.collector_id,w.batch_id);
 IF NOT FOUND THEN RAISE EXCEPTION 'origin payload unavailable' USING ERRCODE='23514'; END IF;
 IF digest_version=1 AND payload_format=1 THEN
   IF EXISTS (SELECT 1 FROM contour.origin_batch_proof_completion x WHERE (x.tenant_id,x.collector_id,x.batch_id)=(tenant,w.collector_id,w.batch_id))
    OR EXISTS (SELECT 1 FROM contour.ingestion_v2_metadata x WHERE (x.tenant_id,x.collector_id,x.batch_id,x.record_id)=(tenant,w.collector_id,w.batch_id,w.record_id))
    OR EXISTS (SELECT 1 FROM contour.origin_proofs x WHERE (x.tenant_id,x.collector_id,x.batch_id,x.record_id)=(tenant,w.collector_id,w.batch_id,w.record_id))
    OR EXISTS (SELECT 1 FROM contour.catalog_origin_projection x WHERE (x.tenant_id,x.collector_id,x.batch_id,x.record_id)=(tenant,w.collector_id,w.batch_id,w.record_id))
   THEN RAISE EXCEPTION 'origin attribution mismatch' USING ERRCODE='23514'; END IF;
   RETURN;
 END IF;
 IF digest_version IS DISTINCT FROM 2 OR payload_format IS DISTINCT FROM 2 OR payload IS NULL OR pg_catalog.octet_length(payload) NOT BETWEEN 1 AND 1048576 THEN
   RAISE EXCEPTION 'origin payload invalid' USING ERRCODE='23514'; END IF;
 envelope:=pg_catalog.convert_from(payload,'UTF8')::jsonb;
 IF EXISTS (SELECT 1 FROM pg_catalog.jsonb_array_elements(envelope->'records') AS item(value)
   LEFT JOIN contour.ingestion_v2_metadata x ON (x.tenant_id,x.collector_id,x.batch_id,x.record_id::text)=(tenant,w.collector_id,w.batch_id,item.value->'record'->>'record_id')
   WHERE (item.value->'origin_witness'->>'kind'='downstream_mtls_leaf_sha256_v1' AND x.attribution_class IS DISTINCT FROM 'verified_origin_v1')
      OR (item.value->'origin_witness'->>'kind'='unattributed' AND x.attribution_class IS DISTINCT FROM 'unattributed')) THEN
   RAISE EXCEPTION 'origin attribution mismatch' USING ERRCODE='23514'; END IF;
 IF EXISTS (WITH verified AS MATERIALIZED (SELECT * FROM contour.catalog_origin_mapping(tenant,w.collector_id,w.batch_id,payload))
   SELECT 1 FROM ((SELECT x.record_id,x.proof_id,x.origin_project_id,x.origin_service_id,x.origin_environment_id,x.origin_deployment_id,x.instance_id
     FROM contour.catalog_origin_projection x WHERE (x.tenant_id,x.collector_id,x.batch_id)=(tenant,w.collector_id,w.batch_id)
     EXCEPT SELECT * FROM verified)
   UNION ALL (SELECT * FROM verified EXCEPT SELECT x.record_id,x.proof_id,x.origin_project_id,x.origin_service_id,x.origin_environment_id,x.origin_deployment_id,x.instance_id
     FROM contour.catalog_origin_projection x WHERE (x.tenant_id,x.collector_id,x.batch_id)=(tenant,w.collector_id,w.batch_id))) differences) THEN
   RAISE EXCEPTION 'origin projection mismatch' USING ERRCODE='23514'; END IF;
 SELECT item.value->'record' INTO STRICT checked_record FROM pg_catalog.jsonb_array_elements(envelope->'records') AS item(value)
 WHERE item.value->'record'->>'record_id'=w.record_id::text;
 IF w.last_seen IS DISTINCT FROM checked_record->>'last_seen' OR w.visibility IS DISTINCT FROM checked_record->>'visibility' OR w.completeness IS DISTINCT FROM checked_record->>'completeness' THEN
   RAISE EXCEPTION 'origin observation mismatch' USING ERRCODE='23514'; END IF;
 SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x WHERE (x.tenant_id,x.collector_id,x.batch_id,x.record_id)=(tenant,w.collector_id,w.batch_id,w.record_id);
 IF (m.source_id,m.project_id,m.service_id,m.environment_id,m.deployment_id) IS DISTINCT FROM
    (w.source_id,w.project_id,w.service_id,w.environment_id,w.deployment_id) THEN
   RAISE EXCEPTION 'origin observation scope mismatch' USING ERRCODE='23514'; END IF;
 IF m.attribution_class='unattributed' THEN RETURN; END IF;
 IF m.attribution_class IS DISTINCT FROM 'verified_origin_v1' THEN RAISE EXCEPTION 'origin attribution mismatch' USING ERRCODE='23514'; END IF;
 SELECT x.* INTO STRICT p FROM contour.origin_proofs x WHERE (x.tenant_id,x.collector_id,x.batch_id,x.record_id)=(tenant,w.collector_id,w.batch_id,w.record_id);
 origin_project_id:=p.origin_project_id; origin_service_id:=p.origin_service_id; origin_environment_id:=p.origin_environment_id;
 origin_deployment_id:=p.origin_deployment_id; instance_id:=p.instance_id; lifecycle_id:=p.lifecycle_id; credential_id:=p.credential_id; grant_id:=p.grant_id;
 RETURN NEXT;
EXCEPTION WHEN no_data_found OR too_many_rows THEN RAISE EXCEPTION 'origin history unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.human_observation_origin(uuid,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.human_observation_origin(uuid,uuid,uuid,uuid,uuid,uuid) TO contour_catalog_reader;
INSERT INTO contour.schema_migrations(version) VALUES (25);
COMMIT;
