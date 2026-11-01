-- Opt-in origin ingress capability and origin epoch/clock state. This does not admit proofs.
-- A trusted application must authenticate its collector independently.
BEGIN;
SET LOCAL ROLE contour_owner;

-- Facts present at activation have unknown relative ordering, represented by 0.
ALTER TABLE contour.origin_lifecycles ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_credentials ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_observer_grants ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_terminal_events ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);

CREATE TABLE contour.origin_tenant_state (
    tenant_id uuid PRIMARY KEY,
    epoch bigint NOT NULL CHECK (epoch >= 0),
    clock_floor timestamptz CHECK (clock_floor IS NULL OR pg_catalog.isfinite(clock_floor))
);
ALTER TABLE contour.origin_tenant_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_tenant_state FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_tenant_state_owner ON contour.origin_tenant_state TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_tenant_state FROM PUBLIC, contour_origin_ingress;

-- Bound the lazy terminal-event seed to one tenant, including all event kinds.
CREATE INDEX origin_terminal_tenant_time ON contour.origin_terminal_events (tenant_id,event_at);

-- Called only under Q. The history scan occurs once per tenant, at lazy seed.
CREATE FUNCTION contour.ensure_origin_tenant_state(tenant uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM contour.require_origin_locks(tenant,NULL,NULL);
    IF NOT EXISTS (SELECT 1 FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant) THEN
        INSERT INTO contour.origin_tenant_state (tenant_id,epoch,clock_floor)
        SELECT tenant,0,max(h.at_time) FROM (
          SELECT l.enrolled_at AS at_time FROM contour.origin_lifecycles l WHERE l.tenant_id=tenant
          UNION ALL SELECT c.enrolled_at FROM contour.origin_credentials c WHERE c.tenant_id=tenant
          UNION ALL SELECT g.granted_at FROM contour.origin_observer_grants g WHERE g.tenant_id=tenant
          UNION ALL SELECT e.event_at FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant
        ) h;
    END IF;
END $$;

-- The existing mutation entrypoints supply server time and hold Q. The trigger
-- overrides any supplied epoch and advances both fields transactionally.
CREATE FUNCTION contour.assign_origin_fact_epoch() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE at_time timestamptz; state_epoch bigint; floor_time timestamptz;
BEGIN
    PERFORM contour.ensure_origin_tenant_state(NEW.tenant_id);
    IF TG_TABLE_NAME IN ('origin_lifecycles','origin_credentials') THEN at_time := NEW.enrolled_at;
    ELSIF TG_TABLE_NAME='origin_observer_grants' THEN at_time := NEW.granted_at;
    ELSE at_time := NEW.event_at; END IF;
    SELECT s.epoch,s.clock_floor INTO state_epoch,floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=NEW.tenant_id FOR UPDATE;
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR (floor_time IS NOT NULL AND at_time < floor_time) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    IF state_epoch = 9223372036854775807 THEN
        RAISE EXCEPTION 'origin epoch exhausted' USING ERRCODE='54000';
    END IF;
    NEW.fact_epoch := state_epoch + 1;
    UPDATE contour.origin_tenant_state SET epoch=NEW.fact_epoch,clock_floor=at_time WHERE tenant_id=NEW.tenant_id;
    RETURN NEW;
END $$;
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'] LOOP
        EXECUTE pg_catalog.format('CREATE TRIGGER origin_z_fact_epoch BEFORE INSERT ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.assign_origin_fact_epoch()',relation);
    END LOOP;
END $$;
-- Preserve the existing lifecycle history check, and extend it by the tenant
-- floor. Proof acceptance can advance this same floor in a later phase.
ALTER FUNCTION contour.origin_history_highwater(uuid,uuid) RENAME TO origin_lifecycle_highwater;
CREATE FUNCTION contour.origin_history_highwater(tenant uuid, lifecycle uuid) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE history_time timestamptz; floor_time timestamptz;
BEGIN
    history_time := contour.origin_lifecycle_highwater(tenant,lifecycle);
    SELECT s.clock_floor INTO floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant;
    RETURN greatest(history_time,floor_time);
END $$;
REVOKE ALL ON FUNCTION contour.ensure_origin_tenant_state(uuid), contour.assign_origin_fact_epoch(),
    contour.origin_lifecycle_highwater(uuid,uuid), contour.origin_history_highwater(uuid,uuid) FROM PUBLIC;

CREATE TABLE contour.origin_ingress_context (
    transaction_id bigint NOT NULL,
    backend_pid integer NOT NULL,
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    started_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(started_at)),
    fact_epoch bigint NOT NULL CHECK (fact_epoch >= 0),
    PRIMARY KEY (transaction_id, backend_pid)
);
ALTER TABLE contour.origin_ingress_context ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_ingress_context FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_ingress_context_owner ON contour.origin_ingress_context TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_ingress_context FROM PUBLIC, contour_origin_ingress;

-- Deferred cleanup is transactional: rollback removes the insertion, commit
-- deletes it. Temporarily restore the row's tenant even if the caller changed
-- its tenant setting since beginning the operation. Forced RLS remains active.
CREATE FUNCTION contour.cleanup_origin_ingress_context() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior text;
BEGIN
    prior := pg_catalog.current_setting('apicontour.tenant_id', true);
    PERFORM pg_catalog.set_config('apicontour.tenant_id', NEW.tenant_id::text, true);
    DELETE FROM contour.origin_ingress_context c
      WHERE c.transaction_id=NEW.transaction_id AND c.backend_pid=NEW.backend_pid
        AND c.tenant_id=NEW.tenant_id AND c.collector_id=NEW.collector_id;
    PERFORM pg_catalog.set_config('apicontour.tenant_id', coalesce(prior,''), true);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER cleanup_origin_ingress_context
    AFTER INSERT ON contour.origin_ingress_context DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION contour.cleanup_origin_ingress_context();

CREATE FUNCTION contour.begin_origin_ingress(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE at_time timestamptz; current_epoch bigint; floor_time timestamptz;
BEGIN
    -- This guard refuses any preheld advisory lock, including session locks,
    -- and acquires Q first. The collector gate is then held through transaction end.
    PERFORM contour.begin_origin_operation(tenant);
    PERFORM contour.lock_origin_collector(tenant,collector);
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    PERFORM contour.ensure_origin_tenant_state(tenant);
    SELECT s.epoch,s.clock_floor INTO current_epoch,floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant;
    IF floor_time IS NOT NULL AND at_time < floor_time THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_ingress_context
        VALUES (pg_catalog.txid_current(),pg_catalog.pg_backend_pid(),tenant,collector,at_time,current_epoch);
END $$;

-- The private row is required in addition to advisory locks; locks and GUCs
-- alone cannot establish authority. A later proof writer must invoke this.
CREATE FUNCTION contour.require_origin_ingress(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM contour.require_origin_locks(tenant,collector,NULL);
    IF collector IS NULL OR NOT EXISTS (
        SELECT 1 FROM contour.origin_ingress_context c
        WHERE c.transaction_id=pg_catalog.txid_current()
          AND c.backend_pid=pg_catalog.pg_backend_pid()
          AND c.tenant_id=tenant AND c.collector_id=collector
    ) THEN
        RAISE EXCEPTION 'origin ingress context required' USING ERRCODE='42501';
    END IF;
END $$;
REVOKE ALL ON FUNCTION contour.cleanup_origin_ingress_context(),
    contour.begin_origin_ingress(uuid,uuid), contour.require_origin_ingress(uuid,uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA contour TO contour_origin_ingress;
GRANT EXECUTE ON FUNCTION contour.begin_origin_ingress(uuid,uuid), contour.require_origin_ingress(uuid,uuid)
    TO contour_origin_ingress;
-- Owner reads only the active tenant's existing inbox and metadata. The
-- resolver is a current-transaction decision, not a durable proof or authority
-- after the Q/C locks are released. It never promotes metadata.
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['ingestion_batches','ingestion_payloads','ingestion_v2_metadata'] LOOP
        EXECUTE pg_catalog.format('CREATE POLICY origin_resolver_owner_read ON contour.%I FOR SELECT TO contour_owner USING (tenant_id=contour.tenant_context())',relation);
    END LOOP;
END $$;
CREATE TYPE contour.origin_resolution AS (
    lifecycle_id uuid, credential_id uuid, grant_id uuid,
    origin_project_id uuid, origin_service_id uuid, origin_environment_id uuid,
    origin_deployment_id uuid, instance_id uuid, platform_evidence_sha256 bytea,
    lifecycle_epoch bigint, credential_epoch bigint, grant_epoch bigint,
    context_epoch bigint, context_time timestamptz
);
-- Private helper assumes a Rust strict-decoded canonical input; SQL is not a strict JSON codec.
-- The trusted application must strict-decode stored bytes before originating a call.
-- Private helper accepts a row already read by the owner; it is not granted to
-- callers. A future batch writer can reuse it with records parsed once.
CREATE FUNCTION contour.resolve_origin_record_checked(tenant uuid, collector uuid,
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
    RETURN result;
EXCEPTION WHEN no_data_found OR too_many_rows THEN
    RAISE EXCEPTION 'origin unavailable' USING ERRCODE='23514';
END $$;

CREATE FUNCTION contour.resolve_origin_record(tenant uuid, collector uuid, batch uuid,
    record uuid, canonical_checked_payload bytea) RETURNS contour.origin_resolution
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b contour.ingestion_batches; p contour.ingestion_payloads; m contour.ingestion_v2_metadata;
    envelope jsonb; wrapper jsonb; rec jsonb; matches integer; row_count integer; revision numeric;
BEGIN
    PERFORM contour.require_origin_ingress(tenant,collector);
    IF pg_catalog.octet_length(canonical_checked_payload) NOT BETWEEN 1 AND 1048576 THEN
        RAISE EXCEPTION 'invalid checked payload' USING ERRCODE='23514';
    END IF;
    SELECT x.* INTO STRICT b FROM contour.ingestion_batches x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.digest_version=2;
    SELECT x.* INTO STRICT p FROM contour.ingestion_payloads x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.payload_format=2 AND pg_catalog.octet_length(x.checked_batch) BETWEEN 1 AND 1048576;
    SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id=record;
    IF pg_catalog.sha256(pg_catalog.convert_to(E'apicontour/batch/2\n','UTF8') || canonical_checked_payload) IS DISTINCT FROM b.request_digest THEN
        RAISE EXCEPTION 'checked payload digest mismatch' USING ERRCODE='23514';
    END IF;
    envelope := pg_catalog.convert_from(canonical_checked_payload,'UTF8')::jsonb;
    IF p.checked_batch IS DISTINCT FROM canonical_checked_payload OR envelope->>'wire_version' IS DISTINCT FROM '2'
       OR envelope->>'tenant_id' IS DISTINCT FROM tenant::text OR envelope->>'collector_id' IS DISTINCT FROM collector::text
       OR envelope->>'batch_id' IS DISTINCT FROM batch::text OR pg_catalog.jsonb_typeof(envelope->'records') IS DISTINCT FROM 'array'
       OR pg_catalog.jsonb_array_length(envelope->'records') IS DISTINCT FROM b.record_count OR b.record_count NOT BETWEEN 1 AND 500 THEN
        RAISE EXCEPTION 'checked payload mismatch' USING ERRCODE='23514';
    END IF;
    SELECT count(*) INTO row_count FROM (
        SELECT 1 FROM contour.ingestion_v2_metadata x
        WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch
        LIMIT 501
    ) bounded_metadata;
    IF row_count IS DISTINCT FROM b.record_count OR NOT pg_catalog.isfinite(b.accepted_at) THEN
        RAISE EXCEPTION 'metadata cardinality mismatch' USING ERRCODE='23514';
    END IF;
    SELECT count(DISTINCT x.value->'record'->>'record_id') INTO matches
      FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value);
    IF matches IS DISTINCT FROM b.record_count THEN
        RAISE EXCEPTION 'duplicate or missing record' USING ERRCODE='23514';
    END IF;
    FOR wrapper IN SELECT x.value FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value) LOOP
        rec := wrapper->'record';
        IF pg_catalog.jsonb_typeof(rec->'policy_revision') IS DISTINCT FROM 'number' THEN
            RAISE EXCEPTION 'invalid record' USING ERRCODE='23514';
        END IF;
        SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x
          WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id::text=rec->>'record_id';
        revision := (rec->>'policy_revision')::numeric;
        IF revision < 1 OR revision > 18446744073709551615 OR revision <> pg_catalog.trunc(revision)
           OR m.policy_revision < 1 OR m.policy_revision > 18446744073709551615
           OR m.policy_revision <> pg_catalog.trunc(m.policy_revision) OR m.policy_revision <> revision
           OR rec->>'source_id' IS DISTINCT FROM m.source_id::text OR rec->>'project_id' IS DISTINCT FROM m.project_id::text
           OR rec->>'service_id' IS DISTINCT FROM m.service_id::text OR rec->>'environment_id' IS DISTINCT FROM m.environment_id::text
           OR rec->>'deployment_id' IS DISTINCT FROM m.deployment_id::text OR rec->>'parser_profile' IS DISTINCT FROM m.parser_profile
           OR m.digest_version IS DISTINCT FROM 2 OR m.request_digest IS DISTINCT FROM b.request_digest
           OR m.accepted_at IS DISTINCT FROM b.accepted_at OR NOT pg_catalog.isfinite(m.accepted_at)
           OR m.attribution_class IS DISTINCT FROM 'unattributed' THEN
            RAISE EXCEPTION 'metadata mismatch' USING ERRCODE='23514';
        END IF;
    END LOOP;
    SELECT x.value INTO STRICT wrapper FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value)
      WHERE x.value->'record'->>'record_id'=record::text;
    SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id=record;
    RETURN contour.resolve_origin_record_checked(tenant,collector,m,wrapper->'origin_witness');
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'checked record unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.resolve_origin_record_checked(uuid,uuid,contour.ingestion_v2_metadata,jsonb),
    contour.resolve_origin_record(uuid,uuid,uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.resolve_origin_record(uuid,uuid,uuid,uuid,bytea) TO contour_origin_ingress;

-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (17);
COMMIT;
