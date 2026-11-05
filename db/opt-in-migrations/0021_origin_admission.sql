-- Opt-in combined profile: classify only a missing live origin resolution.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,20))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted origin admission migration required' USING ERRCODE='42501'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
CREATE OR REPLACE FUNCTION contour.resolve_origin_record_checked(tenant uuid, collector uuid,
    m contour.ingestion_v2_metadata, witness jsonb) RETURNS contour.origin_resolution
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE result contour.origin_resolution; leaf bytea; now_time timestamptz; ctx contour.origin_ingress_context; floor_time timestamptz;
BEGIN
    PERFORM contour.require_origin_ingress(tenant,collector);
    IF m.tenant_id IS DISTINCT FROM tenant OR m.collector_id IS DISTINCT FROM collector
       OR witness->>'kind' IS DISTINCT FROM 'downstream_mtls_leaf_sha256_v1'
       OR pg_catalog.jsonb_typeof(witness) IS DISTINCT FROM 'object'
       OR witness->>'leaf_sha256' IS NULL OR (witness->>'leaf_sha256') COLLATE "C" !~ '^[0-9a-f]{64}$'
       OR witness - 'kind' - 'leaf_sha256' <> '{}'::jsonb THEN
        RAISE EXCEPTION 'origin witness unavailable' USING ERRCODE='23514';
    END IF;
    leaf := pg_catalog.decode(witness->>'leaf_sha256','hex');
    SELECT c.* INTO STRICT ctx FROM contour.origin_ingress_context c
      WHERE c.transaction_id=pg_catalog.txid_current() AND c.backend_pid=pg_catalog.pg_backend_pid()
        AND c.tenant_id=tenant AND c.collector_id=collector;
    SELECT s.clock_floor INTO floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant;
    now_time := contour.origin_server_time();
    IF now_time IS NULL OR NOT pg_catalog.isfinite(now_time) OR now_time < ctx.started_at
       OR (floor_time IS NOT NULL AND now_time < floor_time) OR now_time < m.accepted_at THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    BEGIN
    SELECT l.lifecycle_id,c.credential_id,g.grant_id,l.project_id,l.service_id,l.environment_id,
        l.deployment_id,l.instance_id,l.platform_evidence_sha256,l.fact_epoch,c.fact_epoch,g.fact_epoch,
        ctx.fact_epoch,ctx.started_at
      INTO STRICT result
      FROM contour.origin_credentials c
      JOIN contour.origin_lifecycles l ON l.tenant_id=c.tenant_id AND l.lifecycle_id=c.lifecycle_id
      JOIN contour.origin_observer_grants g ON g.tenant_id=l.tenant_id AND g.lifecycle_id=l.lifecycle_id
      WHERE c.tenant_id=tenant AND c.leaf_sha256=leaf
        AND g.source_id=m.source_id AND g.collector_id=collector AND g.project_id=m.project_id
        AND g.service_id=m.service_id AND g.environment_id=m.environment_id AND g.deployment_id=m.deployment_id
        AND l.enrolled_at<=m.accepted_at AND c.enrolled_at<=m.accepted_at AND g.granted_at<=m.accepted_at
        AND l.fact_epoch<=ctx.fact_epoch AND c.fact_epoch<=ctx.fact_epoch AND g.fact_epoch<=ctx.fact_epoch
        AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant AND
          ((e.event_kind='lifecycle_closed' AND e.lifecycle_id=l.lifecycle_id)
           OR (e.event_kind='credential_revoked' AND e.credential_id=c.credential_id)
           OR (e.event_kind='grant_revoked' AND e.grant_id=g.grant_id)));
    EXCEPTION WHEN no_data_found THEN
        RAISE EXCEPTION 'origin unavailable' USING ERRCODE='23514', CONSTRAINT='origin_live_resolution_unavailable';
    END;
    RETURN result;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION 'origin unavailable' USING ERRCODE='23514';
END $$;

INSERT INTO contour.schema_migrations(version) VALUES(21);
COMMIT;
