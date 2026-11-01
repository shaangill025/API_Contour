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

CREATE FUNCTION contour.parse_origin_batch(tenant uuid, collector uuid, batch uuid, canonical_checked_payload bytea) RETURNS jsonb
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE b contour.ingestion_batches; p contour.ingestion_payloads; m contour.ingestion_v2_metadata;
    envelope jsonb; wrapper jsonb; rec jsonb; matches integer; row_count integer; revision numeric;
BEGIN
    IF tenant IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'origin context mismatch' USING ERRCODE='42501';
    END IF;
    IF pg_catalog.octet_length(canonical_checked_payload) NOT BETWEEN 1 AND 1048576 THEN
        RAISE EXCEPTION 'invalid checked payload' USING ERRCODE='23514';
    END IF;
    SELECT x.* INTO STRICT b FROM contour.ingestion_batches x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.digest_version=2 AND pg_catalog.octet_length(x.request_digest)=32;
    SELECT x.* INTO STRICT p FROM contour.ingestion_payloads x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.payload_format=2 AND pg_catalog.octet_length(x.checked_batch) BETWEEN 1 AND 1048576;
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
          WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id::text=rec->>'record_id'
            AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64
            AND x.attribution_class='unattributed';
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
    RETURN envelope;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'checked batch unavailable' USING ERRCODE='23514';
END $$;
CREATE FUNCTION contour.resolve_origin_record(tenant uuid, collector uuid, batch uuid,
    record uuid, canonical_checked_payload bytea) RETURNS contour.origin_resolution
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE envelope jsonb; wrapper jsonb; m contour.ingestion_v2_metadata;
BEGIN
    PERFORM contour.require_origin_ingress(tenant,collector);
    envelope := contour.parse_origin_batch(tenant,collector,batch,canonical_checked_payload);
    SELECT x.value INTO STRICT wrapper FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value)
      WHERE x.value->'record'->>'record_id'=record::text;
    SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id=record
      AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64 AND x.attribution_class='unattributed';
    RETURN contour.resolve_origin_record_checked(tenant,collector,m,wrapper->'origin_witness');
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'checked record unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.parse_origin_batch(uuid,uuid,uuid,bytea), contour.resolve_origin_record_checked(uuid,uuid,contour.ingestion_v2_metadata,jsonb),
    contour.resolve_origin_record(uuid,uuid,uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.resolve_origin_record(uuid,uuid,uuid,uuid,bytea) TO contour_origin_ingress;

-- Historical proof profile 1 is a compact PostgreSQL JSON array of typed
-- UUID strings, lowercase hex digests, integral numbers and UTC epoch
-- microseconds. Field order is fixed below. It contains no request values.
CREATE TABLE contour.origin_proofs (
    tenant_id uuid NOT NULL, proof_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    collector_id uuid NOT NULL, batch_id uuid NOT NULL, record_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (pg_catalog.octet_length(request_digest)=32),
    accepted_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(accepted_at)),
    proof_accepted_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(proof_accepted_at)),
    source_id uuid NOT NULL, project_id uuid NOT NULL, service_id uuid NOT NULL,
    environment_id uuid NOT NULL, deployment_id uuid NOT NULL,
    policy_revision numeric NOT NULL CHECK (policy_revision BETWEEN 1 AND 18446744073709551615 AND policy_revision=pg_catalog.trunc(policy_revision)),
    parser_profile text NOT NULL CHECK (parser_profile COLLATE "C" ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$'),
    lifecycle_id uuid NOT NULL, credential_id uuid NOT NULL, grant_id uuid NOT NULL,
    origin_project_id uuid NOT NULL, origin_service_id uuid NOT NULL, origin_environment_id uuid NOT NULL,
    origin_deployment_id uuid NOT NULL, instance_id uuid NOT NULL,
    leaf_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(leaf_sha256)=32),
    platform_evidence_sha256 bytea NOT NULL CHECK (pg_catalog.octet_length(platform_evidence_sha256)=32),
    lifecycle_epoch bigint NOT NULL CHECK (lifecycle_epoch>=0), credential_epoch bigint NOT NULL CHECK (credential_epoch>=0),
    grant_epoch bigint NOT NULL CHECK (grant_epoch>=0), context_epoch bigint NOT NULL CHECK (context_epoch>=0),
    context_time timestamptz NOT NULL CHECK (pg_catalog.isfinite(context_time)),
    canonical_proof bytea NOT NULL CHECK (pg_catalog.octet_length(canonical_proof) BETWEEN 1 AND 4096),
    PRIMARY KEY (tenant_id,proof_id), UNIQUE (tenant_id,collector_id,batch_id,record_id),
    FOREIGN KEY (tenant_id,collector_id,batch_id,record_id) REFERENCES contour.ingestion_v2_metadata,
    FOREIGN KEY (tenant_id,lifecycle_id) REFERENCES contour.origin_lifecycles,
    FOREIGN KEY (tenant_id,credential_id) REFERENCES contour.origin_credentials,
    FOREIGN KEY (tenant_id,grant_id) REFERENCES contour.origin_observer_grants
);
ALTER TABLE contour.origin_proofs ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_proofs FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_proofs_owner ON contour.origin_proofs TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_proofs FROM PUBLIC, contour_origin_ingress, contour_catalog_worker;
CREATE TRIGGER origin_proof_immutable BEFORE UPDATE OR DELETE ON contour.origin_proofs
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER origin_proof_no_truncate BEFORE TRUNCATE ON contour.origin_proofs
    FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();

CREATE FUNCTION contour.encode_origin_proof(p contour.origin_proofs) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT pg_catalog.convert_to(pg_catalog.jsonb_build_array(
   1,p.proof_id,p.tenant_id,p.collector_id,p.batch_id,p.record_id,2,pg_catalog.encode(p.request_digest,'hex'),
   (extract(epoch FROM p.accepted_at)*1000000)::numeric(30,0),
   (extract(epoch FROM p.proof_accepted_at)*1000000)::numeric(30,0),
   p.source_id,p.project_id,p.service_id,p.environment_id,p.deployment_id,
   pg_catalog.trunc(p.policy_revision),p.parser_profile,p.lifecycle_id,p.credential_id,p.grant_id,
   p.origin_project_id,p.origin_service_id,p.origin_environment_id,p.origin_deployment_id,p.instance_id,
   pg_catalog.encode(p.leaf_sha256,'hex'),pg_catalog.encode(p.platform_evidence_sha256,'hex'),
   p.lifecycle_epoch,p.credential_epoch,p.grant_epoch,p.context_epoch,
   (extract(epoch FROM p.context_time)*1000000)::numeric(30,0))::text,'UTF8')
$$;

-- Internal consistency of privately admitted, immutable proof data only. A
-- forged privileged seed or context cannot be authenticated by this verifier.
-- No current-liveness check is used.
-- Checked payload bytes originate in the trusted strict Rust decoder; this is
-- not an independent strict JSON decoder or an authorization decision.
CREATE FUNCTION contour.verify_origin_proof_parsed(tenant uuid, p contour.origin_proofs,
    b contour.ingestion_batches, m contour.ingestion_v2_metadata, wrapper jsonb) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE l contour.origin_lifecycles; c contour.origin_credentials; g contour.origin_observer_grants;
BEGIN
    IF p.tenant_id IS DISTINCT FROM tenant OR b.tenant_id IS DISTINCT FROM tenant OR m.tenant_id IS DISTINCT FROM tenant
       OR b.collector_id IS DISTINCT FROM p.collector_id OR b.batch_id IS DISTINCT FROM p.batch_id
       OR m.collector_id IS DISTINCT FROM p.collector_id OR m.batch_id IS DISTINCT FROM p.batch_id OR m.record_id IS DISTINCT FROM p.record_id
       OR pg_catalog.octet_length(p.canonical_proof) NOT BETWEEN 1 AND 4096
       OR pg_catalog.octet_length(p.request_digest)<>32 OR pg_catalog.octet_length(p.leaf_sha256)<>32
       OR pg_catalog.octet_length(p.platform_evidence_sha256)<>32 OR pg_catalog.octet_length(p.parser_profile) NOT BETWEEN 1 AND 64 THEN
        RAISE EXCEPTION 'origin proof mismatch' USING ERRCODE='23514';
    END IF;
    SELECT x.* INTO STRICT l FROM contour.origin_lifecycles x WHERE x.tenant_id=tenant AND x.lifecycle_id=p.lifecycle_id AND pg_catalog.octet_length(x.platform_evidence_sha256)=32 AND x.platform_kind='trusted_platform_v1';
    SELECT x.* INTO STRICT c FROM contour.origin_credentials x WHERE x.tenant_id=tenant AND x.credential_id=p.credential_id AND pg_catalog.octet_length(x.leaf_sha256)=32;
    SELECT x.* INTO STRICT g FROM contour.origin_observer_grants x WHERE x.tenant_id=tenant AND x.grant_id=p.grant_id;
    IF p.policy_revision < 1 OR p.policy_revision > 18446744073709551615
       OR p.policy_revision <> pg_catalog.trunc(p.policy_revision)
       OR p.lifecycle_epoch<0 OR p.credential_epoch<0 OR p.grant_epoch<0 OR p.context_epoch<0
       OR l.fact_epoch<0 OR c.fact_epoch<0 OR g.fact_epoch<0
       OR NOT pg_catalog.isfinite(p.accepted_at) OR NOT pg_catalog.isfinite(p.proof_accepted_at)
       OR NOT pg_catalog.isfinite(p.context_time) OR NOT pg_catalog.isfinite(b.accepted_at)
       OR NOT pg_catalog.isfinite(m.accepted_at) OR NOT pg_catalog.isfinite(l.enrolled_at)
       OR NOT pg_catalog.isfinite(c.enrolled_at) OR NOT pg_catalog.isfinite(g.granted_at) THEN
        RAISE EXCEPTION 'origin proof mismatch' USING ERRCODE='23514';
    END IF;
    IF p.canonical_proof IS DISTINCT FROM contour.encode_origin_proof(p)
       OR b.digest_version IS DISTINCT FROM 2 OR p.request_digest IS DISTINCT FROM b.request_digest
       OR m.digest_version IS DISTINCT FROM 2 OR m.request_digest IS DISTINCT FROM p.request_digest
       OR m.accepted_at IS DISTINCT FROM p.accepted_at OR b.accepted_at IS DISTINCT FROM p.accepted_at
       OR m.source_id IS DISTINCT FROM p.source_id OR m.project_id IS DISTINCT FROM p.project_id
       OR m.service_id IS DISTINCT FROM p.service_id OR m.environment_id IS DISTINCT FROM p.environment_id
       OR m.deployment_id IS DISTINCT FROM p.deployment_id OR m.policy_revision IS DISTINCT FROM p.policy_revision
       OR m.parser_profile IS DISTINCT FROM p.parser_profile OR m.attribution_class IS DISTINCT FROM 'unattributed'
       OR c.lifecycle_id IS DISTINCT FROM p.lifecycle_id OR g.lifecycle_id IS DISTINCT FROM p.lifecycle_id
       OR c.leaf_sha256 IS DISTINCT FROM p.leaf_sha256 OR l.platform_evidence_sha256 IS DISTINCT FROM p.platform_evidence_sha256
       OR l.project_id IS DISTINCT FROM p.origin_project_id OR l.service_id IS DISTINCT FROM p.origin_service_id
       OR l.environment_id IS DISTINCT FROM p.origin_environment_id OR l.deployment_id IS DISTINCT FROM p.origin_deployment_id
       OR l.instance_id IS DISTINCT FROM p.instance_id OR g.collector_id IS DISTINCT FROM p.collector_id
       OR g.source_id IS DISTINCT FROM p.source_id OR g.project_id IS DISTINCT FROM p.project_id
       OR g.service_id IS DISTINCT FROM p.service_id OR g.environment_id IS DISTINCT FROM p.environment_id
       OR g.deployment_id IS DISTINCT FROM p.deployment_id OR l.fact_epoch IS DISTINCT FROM p.lifecycle_epoch
       OR c.fact_epoch IS DISTINCT FROM p.credential_epoch OR g.fact_epoch IS DISTINCT FROM p.grant_epoch
       OR greatest(p.lifecycle_epoch,p.credential_epoch,p.grant_epoch)>p.context_epoch
       OR greatest(l.enrolled_at,c.enrolled_at,g.granted_at)>p.accepted_at
       OR greatest(l.enrolled_at,c.enrolled_at,g.granted_at)>p.context_time
       OR p.accepted_at>p.proof_accepted_at OR p.context_time>p.proof_accepted_at
       OR EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant
          AND ((e.event_kind='lifecycle_closed' AND e.lifecycle_id=p.lifecycle_id)
            OR (e.event_kind='credential_revoked' AND e.credential_id=p.credential_id)
            OR (e.event_kind='grant_revoked' AND e.grant_id=p.grant_id))
          AND (NOT pg_catalog.isfinite(e.event_at) OR e.fact_epoch=0
            OR e.fact_epoch<=p.context_epoch OR e.event_at<p.proof_accepted_at)) THEN
        RAISE EXCEPTION 'origin proof mismatch' USING ERRCODE='23514';
    END IF;
    IF wrapper->'record'->>'source_id' IS DISTINCT FROM p.source_id::text
       OR wrapper->'record'->>'project_id' IS DISTINCT FROM p.project_id::text
       OR wrapper->'record'->>'service_id' IS DISTINCT FROM p.service_id::text
       OR wrapper->'record'->>'environment_id' IS DISTINCT FROM p.environment_id::text
       OR wrapper->'record'->>'deployment_id' IS DISTINCT FROM p.deployment_id::text
       OR wrapper->'record'->>'parser_profile' IS DISTINCT FROM p.parser_profile
       OR pg_catalog.jsonb_typeof(wrapper->'record'->'policy_revision') IS DISTINCT FROM 'number'
       OR (wrapper->'record'->>'policy_revision')::numeric IS DISTINCT FROM p.policy_revision
       OR wrapper->'origin_witness'->>'kind' IS DISTINCT FROM 'downstream_mtls_leaf_sha256_v1'
       OR wrapper->'origin_witness'->>'leaf_sha256' IS DISTINCT FROM pg_catalog.encode(p.leaf_sha256,'hex')
       OR (wrapper->'origin_witness') - 'kind' - 'leaf_sha256' IS DISTINCT FROM '{}'::jsonb THEN
        RAISE EXCEPTION 'origin proof mismatch' USING ERRCODE='23514';
    END IF;
    RETURN true;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'origin proof unavailable' USING ERRCODE='23514';
END $$;
CREATE FUNCTION contour.verify_origin_proof(tenant uuid, proof uuid) RETURNS boolean
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE p contour.origin_proofs; b contour.ingestion_batches; m contour.ingestion_v2_metadata;
    payload bytea; envelope jsonb; wrapper jsonb;
BEGIN
    IF tenant IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'origin context mismatch' USING ERRCODE='42501';
    END IF;
    SELECT x.* INTO STRICT p FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.proof_id=proof
      AND pg_catalog.octet_length(x.canonical_proof) BETWEEN 1 AND 4096
      AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.leaf_sha256)=32
      AND pg_catalog.octet_length(x.platform_evidence_sha256)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64;
    SELECT x.* INTO STRICT b FROM contour.ingestion_batches x WHERE x.tenant_id=tenant AND x.collector_id=p.collector_id AND x.batch_id=p.batch_id AND pg_catalog.octet_length(x.request_digest)=32;
    SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x WHERE x.tenant_id=tenant AND x.collector_id=p.collector_id AND x.batch_id=p.batch_id AND x.record_id=p.record_id
      AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64 AND x.attribution_class='unattributed';
    SELECT x.checked_batch INTO STRICT payload FROM contour.ingestion_payloads x WHERE x.tenant_id=tenant AND x.collector_id=p.collector_id AND x.batch_id=p.batch_id AND x.payload_format=2 AND pg_catalog.octet_length(x.checked_batch) BETWEEN 1 AND 1048576;
    envelope := contour.parse_origin_batch(tenant,p.collector_id,p.batch_id,payload);
    SELECT x.value INTO STRICT wrapper FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value)
      WHERE x.value->'record'->>'record_id'=p.record_id::text;
    RETURN contour.verify_origin_proof_parsed(tenant,p,b,m,wrapper);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'origin proof unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.encode_origin_proof(contour.origin_proofs), contour.verify_origin_proof_parsed(uuid,contour.origin_proofs,contour.ingestion_batches,contour.ingestion_v2_metadata,jsonb), contour.verify_origin_proof(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.verify_origin_proof(uuid,uuid) TO contour_origin_ingress, contour_catalog_worker;

-- Logical retained proof bytes, serialized by the tenant gate. No caller can
-- mutate this ledger directly; future retained-event charges may share it.
CREATE TABLE contour.origin_logical_usage (
    tenant_id uuid PRIMARY KEY,
    used_bytes bigint NOT NULL CHECK (used_bytes BETWEEN 0 AND 1073741824)
);
ALTER TABLE contour.origin_logical_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_logical_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_logical_usage_owner ON contour.origin_logical_usage TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_logical_usage FROM PUBLIC, contour_origin_ingress, contour_catalog_worker;

-- Internal completion bookkeeping, not an exported proof encoding. Logical
-- quota counts canonical_proof bytes only, not this fixed-size receipt row.
CREATE TABLE contour.origin_batch_proof_completion (
    tenant_id uuid NOT NULL, collector_id uuid NOT NULL, batch_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (pg_catalog.octet_length(request_digest)=32),
    receipt_id uuid NOT NULL, accepted_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(accepted_at)),
    proof_count integer NOT NULL CHECK (proof_count BETWEEN 1 AND 500),
    proof_set_digest bytea NOT NULL CHECK (pg_catalog.octet_length(proof_set_digest)=32),
    PRIMARY KEY (tenant_id,collector_id,batch_id),
    FOREIGN KEY (tenant_id,collector_id,batch_id) REFERENCES contour.ingestion_batches
);
ALTER TABLE contour.origin_batch_proof_completion ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_batch_proof_completion FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_batch_completion_owner ON contour.origin_batch_proof_completion TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_batch_proof_completion FROM PUBLIC, contour_origin_ingress, contour_catalog_worker;
CREATE TRIGGER origin_batch_completion_immutable BEFORE UPDATE OR DELETE ON contour.origin_batch_proof_completion
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER origin_batch_completion_no_truncate BEFORE TRUNCATE ON contour.origin_batch_proof_completion
    FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();

-- Call only after checking the bounded count and per-proof byte lengths. The
-- fixed-length UUID and digest fields have unambiguous delimiters and ordering.
CREATE FUNCTION contour.origin_proof_set_digest(tenant uuid, collector uuid, batch uuid) RETURNS bytea
LANGUAGE sql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT pg_catalog.sha256(pg_catalog.convert_to(E'apicontour/origin-proof-set/1\n' ||
    coalesce(pg_catalog.string_agg(x.record_id::text || ':' || x.proof_id::text || ':' ||
      pg_catalog.encode(pg_catalog.sha256(x.canonical_proof),'hex'), ',' ORDER BY x.record_id),''),'UTF8'))
 FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch
$$;
REVOKE ALL ON FUNCTION contour.origin_proof_set_digest(uuid,uuid,uuid) FROM PUBLIC;

-- Shared read-only validation of an already decoded, bounded batch. An absent
-- completion marker for a fingerprint batch is an error, even if all proofs
-- were removed. Only the trusted fresh-admission writer may create a marker.
CREATE FUNCTION contour.verify_origin_batch_parsed(tenant uuid, collector uuid, batch uuid,
    b contour.ingestion_batches, envelope jsonb) RETURNS integer
LANGUAGE plpgsql STABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE wrapper jsonb; witness jsonb; m contour.ingestion_v2_metadata; p contour.origin_proofs;
    completion contour.origin_batch_proof_completion; has_completion boolean;
    expected integer; actual integer; set_digest bytea;
BEGIN
    -- First classify the complete checked batch. A zero-fingerprint batch needs
    -- no marker: its immutable canonical digest cannot later gain a witness.
    expected := 0;
    FOR wrapper IN SELECT x.value FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value) LOOP
        witness := wrapper->'origin_witness';
        IF witness = '{"kind":"unattributed"}'::jsonb THEN CONTINUE; END IF;
        IF pg_catalog.jsonb_typeof(witness) IS DISTINCT FROM 'object'
           OR witness->>'kind' IS DISTINCT FROM 'downstream_mtls_leaf_sha256_v1'
           OR (witness->>'leaf_sha256') COLLATE "C" !~ '^[0-9a-f]{64}$'
           OR witness->>'leaf_sha256' IS NULL OR witness - 'kind' - 'leaf_sha256' <> '{}'::jsonb THEN
            RAISE EXCEPTION 'origin witness unavailable' USING ERRCODE='23514';
        END IF;
        expected := expected+1;
    END LOOP;
    SELECT x.* INTO completion FROM contour.origin_batch_proof_completion x
      WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch
        AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.proof_set_digest)=32;
    has_completion := FOUND;
    IF NOT has_completion AND EXISTS (SELECT 1 FROM contour.origin_batch_proof_completion x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch) THEN
        RAISE EXCEPTION 'origin completion mismatch' USING ERRCODE='23514';
    END IF;
    SELECT count(*) INTO actual FROM (SELECT 1 FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch LIMIT 501) bounded_proofs;
    IF has_completion THEN
        IF completion.request_digest IS DISTINCT FROM b.request_digest OR completion.receipt_id IS DISTINCT FROM b.receipt_id
           OR completion.accepted_at IS DISTINCT FROM b.accepted_at OR NOT pg_catalog.isfinite(completion.accepted_at)
           OR completion.proof_count IS DISTINCT FROM expected OR actual IS DISTINCT FROM expected OR expected NOT BETWEEN 1 AND 500
           OR EXISTS (SELECT 1 FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch
             AND (pg_catalog.octet_length(x.canonical_proof) NOT BETWEEN 1 AND 4096 OR pg_catalog.octet_length(x.request_digest)<>32
                  OR pg_catalog.octet_length(x.leaf_sha256)<>32 OR pg_catalog.octet_length(x.platform_evidence_sha256)<>32
                  OR pg_catalog.octet_length(x.parser_profile) NOT BETWEEN 1 AND 64)) THEN
            RAISE EXCEPTION 'origin completion mismatch' USING ERRCODE='23514';
        END IF;
        set_digest := contour.origin_proof_set_digest(tenant,collector,batch);
        IF set_digest IS DISTINCT FROM completion.proof_set_digest THEN
            RAISE EXCEPTION 'origin completion mismatch' USING ERRCODE='23514';
        END IF;
    ELSIF actual <> 0 OR expected <> 0 THEN
        RAISE EXCEPTION 'origin completion missing' USING ERRCODE='23514';
    ELSE
        RETURN 0;
    END IF;
    FOR wrapper IN SELECT x.value FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value) LOOP
        witness := wrapper->'origin_witness';
        IF witness = '{"kind":"unattributed"}'::jsonb THEN
            IF EXISTS (SELECT 1 FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id::text=wrapper->'record'->>'record_id') THEN
                RAISE EXCEPTION 'unexpected origin proof' USING ERRCODE='23514';
            END IF;
            CONTINUE;
        END IF;
        SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x
          WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id::text=wrapper->'record'->>'record_id'
            AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64 AND x.attribution_class='unattributed';
        SELECT x.* INTO STRICT p FROM contour.origin_proofs x
          WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id=m.record_id
            AND pg_catalog.octet_length(x.canonical_proof) BETWEEN 1 AND 4096
            AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.leaf_sha256)=32
            AND pg_catalog.octet_length(x.platform_evidence_sha256)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64;
        PERFORM contour.verify_origin_proof_parsed(tenant,p,b,m,wrapper);
    END LOOP;
    RETURN expected;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'origin batch unavailable' USING ERRCODE='23514';
END $$;
CREATE FUNCTION contour.verify_origin_batch_proofs(tenant uuid, collector uuid, batch uuid, canonical_checked_payload bytea) RETURNS integer
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE envelope jsonb; b contour.ingestion_batches;
BEGIN
    envelope := contour.parse_origin_batch(tenant,collector,batch,canonical_checked_payload);
    SELECT x.* INTO STRICT b FROM contour.ingestion_batches x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND pg_catalog.octet_length(x.request_digest)=32;
    RETURN contour.verify_origin_batch_parsed(tenant,collector,batch,b,envelope);
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'origin batch unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.verify_origin_batch_parsed(uuid,uuid,uuid,contour.ingestion_batches,jsonb), contour.verify_origin_batch_proofs(uuid,uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.verify_origin_batch_proofs(uuid,uuid,uuid,bytea) TO contour_origin_ingress, contour_catalog_worker;

CREATE FUNCTION contour.write_origin_batch_proofs(tenant uuid, collector uuid, batch uuid, canonical_checked_payload bytea) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE envelope jsonb; wrapper jsonb; witness jsonb; m contour.ingestion_v2_metadata;
    b contour.ingestion_batches; p contour.origin_proofs; resolution contour.origin_resolution;
    floor_time timestamptz; at_time timestamptz; used bigint; n integer := 0; size_bytes bigint;
    set_digest bytea;
BEGIN
    PERFORM contour.require_origin_ingress(tenant,collector);
    envelope := contour.parse_origin_batch(tenant,collector,batch,canonical_checked_payload);
    SELECT x.* INTO STRICT b FROM contour.ingestion_batches x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND pg_catalog.octet_length(x.request_digest)=32;
    IF EXISTS (SELECT 1 FROM contour.origin_batch_proof_completion x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch) THEN
        PERFORM contour.verify_origin_batch_parsed(tenant,collector,batch,b,envelope);
        RETURN 0;
    END IF;
    IF EXISTS (SELECT 1 FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch) THEN
        RAISE EXCEPTION 'origin completion missing' USING ERRCODE='23514';
    END IF;
    FOR wrapper IN SELECT x.value FROM pg_catalog.jsonb_array_elements(envelope->'records') x(value) LOOP
        witness := wrapper->'origin_witness';
        SELECT x.* INTO STRICT m FROM contour.ingestion_v2_metadata x
          WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch AND x.record_id::text=wrapper->'record'->>'record_id'
            AND pg_catalog.octet_length(x.request_digest)=32 AND pg_catalog.octet_length(x.parser_profile) BETWEEN 1 AND 64 AND x.attribution_class='unattributed';
        IF witness = '{"kind":"unattributed"}'::jsonb THEN CONTINUE; END IF;
        resolution := contour.resolve_origin_record_checked(tenant,collector,m,witness);
        SELECT s.clock_floor INTO STRICT floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant FOR UPDATE;
        at_time := contour.origin_server_time();
        IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time < resolution.context_time
           OR at_time < m.accepted_at OR (floor_time IS NOT NULL AND at_time < floor_time) THEN
            RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
        END IF;
        p := NULL;
        p.tenant_id:=tenant; p.proof_id:=pg_catalog.gen_random_uuid(); p.collector_id:=collector;
        p.batch_id:=batch; p.record_id:=m.record_id; p.request_digest:=m.request_digest;
        p.accepted_at:=m.accepted_at; p.proof_accepted_at:=at_time;
        p.source_id:=m.source_id; p.project_id:=m.project_id; p.service_id:=m.service_id;
        p.environment_id:=m.environment_id; p.deployment_id:=m.deployment_id;
        p.policy_revision:=m.policy_revision; p.parser_profile:=m.parser_profile;
        p.lifecycle_id:=resolution.lifecycle_id; p.credential_id:=resolution.credential_id; p.grant_id:=resolution.grant_id;
        p.origin_project_id:=resolution.origin_project_id; p.origin_service_id:=resolution.origin_service_id;
        p.origin_environment_id:=resolution.origin_environment_id; p.origin_deployment_id:=resolution.origin_deployment_id;
        p.instance_id:=resolution.instance_id; p.leaf_sha256:=pg_catalog.decode(witness->>'leaf_sha256','hex');
        p.platform_evidence_sha256:=resolution.platform_evidence_sha256;
        p.lifecycle_epoch:=resolution.lifecycle_epoch; p.credential_epoch:=resolution.credential_epoch;
        p.grant_epoch:=resolution.grant_epoch; p.context_epoch:=resolution.context_epoch; p.context_time:=resolution.context_time;
        p.canonical_proof:=contour.encode_origin_proof(p);
        size_bytes:=pg_catalog.octet_length(p.canonical_proof);
        INSERT INTO contour.origin_logical_usage (tenant_id,used_bytes) VALUES (tenant,0) ON CONFLICT (tenant_id) DO NOTHING;
        SELECT u.used_bytes INTO STRICT used FROM contour.origin_logical_usage u WHERE u.tenant_id=tenant FOR UPDATE;
        IF size_bytes > 1073741824 - used THEN
            RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000', CONSTRAINT='origin_logical_quota_exhausted';
        END IF;
        INSERT INTO contour.origin_proofs SELECT (p).*;
        UPDATE contour.origin_logical_usage SET used_bytes=used+size_bytes WHERE tenant_id=tenant;
        UPDATE contour.origin_tenant_state SET clock_floor=at_time WHERE tenant_id=tenant;
        n:=n+1;
    END LOOP;
    IF n>0 THEN
        -- This statement sees proofs inserted earlier in this transaction.
        SELECT pg_catalog.sha256(pg_catalog.convert_to(E'apicontour/origin-proof-set/1\n' ||
          coalesce(pg_catalog.string_agg(x.record_id::text || ':' || x.proof_id::text || ':' ||
            pg_catalog.encode(pg_catalog.sha256(x.canonical_proof),'hex'), ',' ORDER BY x.record_id),''),'UTF8'))
          INTO set_digest FROM contour.origin_proofs x WHERE x.tenant_id=tenant AND x.collector_id=collector AND x.batch_id=batch;
        INSERT INTO contour.origin_batch_proof_completion (tenant_id,collector_id,batch_id,request_digest,receipt_id,accepted_at,proof_count,proof_set_digest)
        VALUES (tenant,collector,batch,b.request_digest,b.receipt_id,b.accepted_at,n,set_digest);
    END IF;
    RETURN n;
EXCEPTION WHEN no_data_found OR too_many_rows OR invalid_text_representation OR character_not_in_repertoire THEN
    RAISE EXCEPTION 'origin batch unavailable' USING ERRCODE='23514';
END $$;
REVOKE ALL ON FUNCTION contour.write_origin_batch_proofs(uuid,uuid,uuid,bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.write_origin_batch_proofs(uuid,uuid,uuid,bytea) TO contour_origin_ingress;

-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (17);
COMMIT;
