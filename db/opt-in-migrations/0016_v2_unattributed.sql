-- Opt-in storage contract only. Trusted ingress must perform admission; these
-- rows never establish origin identity. Apply after the standard schema.
BEGIN;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.ingestion_batches DROP CONSTRAINT ingestion_batches_digest_version_check;
ALTER TABLE contour.ingestion_batches ADD CHECK (digest_version IN (1,2));
ALTER TABLE contour.ingestion_payloads DROP CONSTRAINT ingestion_payloads_payload_format_check;
ALTER TABLE contour.ingestion_payloads ADD CHECK (payload_format IN (1,2));
-- Existing ingestion privileges remain V1-only even after widening the checks.
CREATE POLICY ingestion_v1_only ON contour.ingestion_batches AS RESTRICTIVE FOR INSERT TO contour_ingestion WITH CHECK (digest_version=1);
CREATE POLICY payload_v1_only ON contour.ingestion_payloads AS RESTRICTIVE FOR INSERT TO contour_ingestion WITH CHECK (payload_format=1);
CREATE POLICY v2_ingress_batches ON contour.ingestion_batches TO contour_v2_ingress
    USING (tenant_id=contour.tenant_context())
    WITH CHECK (tenant_id=contour.tenant_context() AND digest_version=2);
CREATE POLICY v2_ingress_payloads ON contour.ingestion_payloads TO contour_v2_ingress
    USING (tenant_id=contour.tenant_context())
    WITH CHECK (tenant_id=contour.tenant_context() AND payload_format=2);
GRANT USAGE ON SCHEMA contour TO contour_v2_ingress;
GRANT EXECUTE ON FUNCTION contour.tenant_context(), contour.collector_lock_key(uuid,uuid), contour.guard_collector(uuid,uuid), contour.lock_collector(uuid,uuid) TO contour_v2_ingress;
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['sources','policy_revisions','collector_authorization','source_authorization'] LOOP
        EXECUTE pg_catalog.format('CREATE POLICY v2_authority_read ON contour.%I FOR SELECT TO contour_v2_ingress USING (tenant_id=contour.tenant_context())', relation);
        EXECUTE pg_catalog.format('GRANT SELECT ON contour.%I TO contour_v2_ingress', relation);
    END LOOP;
END $$;
GRANT SELECT ON contour.ingestion_batches, contour.ingestion_payloads TO contour_v2_ingress;
-- The database, not ingress, supplies receipt and acceptance time.
GRANT INSERT (tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
    ON contour.ingestion_batches TO contour_v2_ingress;
GRANT INSERT ON contour.ingestion_payloads TO contour_v2_ingress;
ALTER TABLE contour.ingestion_batches ADD CONSTRAINT v2_batch_binding UNIQUE
    (tenant_id,collector_id,batch_id,digest_version,request_digest,accepted_at);
CREATE TABLE contour.ingestion_v2_metadata (
    tenant_id uuid NOT NULL, collector_id uuid NOT NULL, batch_id uuid NOT NULL,
    record_id uuid NOT NULL, digest_version smallint NOT NULL CHECK (digest_version=2),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest)=32),
    accepted_at timestamptz NOT NULL CHECK (isfinite(accepted_at)),
    source_id uuid NOT NULL, project_id uuid NOT NULL, service_id uuid NOT NULL,
    environment_id uuid NOT NULL, deployment_id uuid NOT NULL,
    policy_revision numeric NOT NULL, parser_profile text NOT NULL
      CHECK (parser_profile COLLATE "C" ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$'),
    attribution_class text NOT NULL CHECK (attribution_class='unattributed'),
    PRIMARY KEY (tenant_id,collector_id,batch_id,record_id),
    FOREIGN KEY (tenant_id,collector_id,batch_id,digest_version,request_digest,accepted_at)
      REFERENCES contour.ingestion_batches (tenant_id,collector_id,batch_id,digest_version,request_digest,accepted_at),
    FOREIGN KEY (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id)
      REFERENCES contour.sources (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id),
    FOREIGN KEY (tenant_id,collector_id,policy_revision) REFERENCES contour.policy_revisions
);
ALTER TABLE contour.ingestion_v2_metadata ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.ingestion_v2_metadata FORCE ROW LEVEL SECURITY;
CREATE POLICY v2_metadata_ingress ON contour.ingestion_v2_metadata TO contour_v2_ingress
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE POLICY v2_metadata_catalog ON contour.ingestion_v2_metadata FOR SELECT TO contour_catalog_worker
    USING (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.ingestion_v2_metadata FROM PUBLIC;
GRANT SELECT, INSERT ON contour.ingestion_v2_metadata TO contour_v2_ingress;
GRANT SELECT ON contour.ingestion_v2_metadata TO contour_catalog_worker;
CREATE TRIGGER immutable_v2_metadata BEFORE UPDATE OR DELETE ON contour.ingestion_v2_metadata
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER no_truncate_v2_metadata BEFORE TRUNCATE ON contour.ingestion_v2_metadata
    FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();
-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (16);
COMMIT;
