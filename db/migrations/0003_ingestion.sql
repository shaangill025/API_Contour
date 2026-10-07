-- Durable checked batches. Application admission and digest verification are required.
BEGIN;
SET LOCAL ROLE contour_owner;
CREATE TABLE contour.ingestion_batches (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    request_digest bytea NOT NULL CHECK (pg_catalog.octet_length(request_digest) = 32),
    digest_version smallint NOT NULL CHECK (digest_version = 1),
    receipt_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    accepted_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    record_count integer NOT NULL CHECK (record_count BETWEEN 1 AND 500),
    PRIMARY KEY (tenant_id, collector_id, batch_id),
    FOREIGN KEY (tenant_id, collector_id) REFERENCES contour.collectors
);
CREATE TABLE contour.ingestion_payloads (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    payload_format smallint NOT NULL CHECK (payload_format = 1),
    checked_batch bytea NOT NULL CHECK (pg_catalog.octet_length(checked_batch) BETWEEN 1 AND 1048576),
    PRIMARY KEY (tenant_id, collector_id, batch_id),
    FOREIGN KEY (tenant_id, collector_id, batch_id) REFERENCES contour.ingestion_batches
);
-- Reuse the collector guard/lock and immutable-row machinery, with invoker rights.
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['ingestion_batches','ingestion_payloads'] LOOP
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY', relation);
        EXECUTE pg_catalog.format('CREATE POLICY tenant_scope ON contour.%I TO contour_ingestion
            USING (tenant_id = contour.tenant_context()) WITH CHECK (tenant_id = contour.tenant_context())', relation);
        EXECUTE pg_catalog.format('CREATE TRIGGER inbox_insert_guard BEFORE INSERT ON contour.%I
            FOR EACH ROW EXECUTE FUNCTION contour.authority_guard()', relation);
        EXECUTE pg_catalog.format('CREATE TRIGGER immutable_inbox BEFORE UPDATE OR DELETE ON contour.%I
            FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()', relation);
        EXECUTE pg_catalog.format('GRANT SELECT, INSERT ON contour.%I TO contour_ingestion', relation);
    END LOOP;
END $$;
GRANT EXECUTE ON FUNCTION contour.guard_collector(uuid,uuid) TO contour_ingestion;
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (3);
COMMIT;
