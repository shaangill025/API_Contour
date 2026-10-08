-- Additive storage only. A trusted adapter must verify and derive all identities.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_catalog_worker, contour_catalog_reader;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_catalog_worker, contour_catalog_reader;
ALTER TABLE contour.sources ADD CONSTRAINT catalog_source_workload UNIQUE
    (tenant_id, source_id, collector_id, project_id, service_id, environment_id, deployment_id);
CREATE TABLE contour.operations (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    operation_hash bytea NOT NULL CHECK (octet_length(operation_hash)=32),
    identity_version smallint NOT NULL CHECK (identity_version=1),
    canonical_key bytea NOT NULL CHECK (octet_length(canonical_key) BETWEEN 1 AND 2048),
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, operation_id),
    UNIQUE (tenant_id, identity_version, operation_hash),
    UNIQUE (tenant_id, operation_id, project_id, service_id, environment_id),
    FOREIGN KEY (tenant_id, project_id, service_id) REFERENCES contour.services (tenant_id, project_id, service_id),
    FOREIGN KEY (tenant_id, project_id, environment_id) REFERENCES contour.environments (tenant_id, project_id, environment_id)
);
CREATE TABLE contour.variants (
    tenant_id uuid NOT NULL,
    variant_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    operation_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    policy_revision numeric NOT NULL,
    parser_profile text NOT NULL CHECK (parser_profile COLLATE "C" ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$'),
    canonicalization_version smallint NOT NULL CHECK (canonicalization_version=1),
    structure_hash bytea NOT NULL CHECK (octet_length(structure_hash)=32),
    canonical_structure bytea NOT NULL CHECK (octet_length(canonical_structure) BETWEEN 1 AND 65536),
    structure_wire bytea NOT NULL CHECK (octet_length(structure_wire) BETWEEN 1 AND 1048576),
    PRIMARY KEY (tenant_id, variant_id),
    UNIQUE (tenant_id, operation_id, collector_id, policy_revision, parser_profile,
        canonicalization_version, structure_hash),
    UNIQUE (tenant_id, variant_id, operation_id, collector_id),
    FOREIGN KEY (tenant_id, operation_id) REFERENCES contour.operations,
    FOREIGN KEY (tenant_id, collector_id, policy_revision) REFERENCES contour.policy_revisions
);
CREATE TABLE contour.catalog_processed_batches (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    processor_version smallint NOT NULL CHECK (processor_version=1),
    processed_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, collector_id, batch_id),
    FOREIGN KEY (tenant_id, collector_id, batch_id) REFERENCES contour.ingestion_payloads
);
CREATE FUNCTION contour.valid_catalog_reasons(reasons text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path=pg_catalog AS $$
    SELECT coalesce(cardinality(reasons)<=8
        AND (cardinality(reasons)=0 OR array_ndims(reasons)=1)
        AND cardinality(reasons)=(SELECT count(DISTINCT reason) FROM unnest(reasons) reason)
        AND reasons <@ ARRAY['permission','encrypted','unsupported','sampled','limit',
            'malformed','source_gap','clock_skew']::text[],false)
$$;
REVOKE ALL ON FUNCTION contour.valid_catalog_reasons(text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.valid_catalog_reasons(text[]) TO contour_catalog_worker;
-- Despite the table name, each row is one original record, never a source total.
CREATE TABLE contour.observation_windows (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    batch_id uuid NOT NULL,
    record_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    variant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    observation_count numeric NOT NULL CHECK (observation_count=trunc(observation_count)
        AND observation_count BETWEEN 1 AND 1000000000),
    sample_numerator numeric NOT NULL CHECK (sample_numerator=trunc(sample_numerator) AND sample_numerator>=1),
    sample_denominator numeric NOT NULL CHECK (sample_denominator=trunc(sample_denominator)
        AND sample_denominator BETWEEN sample_numerator AND 1000000),
    visibility text NOT NULL CHECK (visibility IN ('structure','operation','connection')),
    completeness text NOT NULL CHECK (completeness IN ('complete','partial','unavailable')),
    reasons text[] NOT NULL CHECK (contour.valid_catalog_reasons(reasons)),
    route_uncertain boolean NOT NULL,
    status_code integer CHECK (status_code BETWEEN 100 AND 599),
    first_seen text NOT NULL CHECK (octet_length(first_seen) BETWEEN 20 AND 40),
    last_seen text NOT NULL CHECK (octet_length(last_seen) BETWEEN 20 AND 40),
    queued_at text NOT NULL CHECK (octet_length(queued_at) BETWEEN 20 AND 40),
    expires_at text NOT NULL CHECK (octet_length(expires_at) BETWEEN 20 AND 40),
    -- Version-1 JSON string arrays encoded as UTF-8; never values.
    request_header_names bytea NOT NULL CHECK (octet_length(request_header_names) BETWEEN 2 AND 1048576),
    response_header_names bytea NOT NULL CHECK (octet_length(response_header_names) BETWEEN 2 AND 1048576),
    query_parameter_names bytea NOT NULL CHECK (octet_length(query_parameter_names) BETWEEN 2 AND 1048576),
    PRIMARY KEY (tenant_id, collector_id, batch_id, record_id),
    FOREIGN KEY (tenant_id, collector_id, batch_id) REFERENCES contour.catalog_processed_batches,
    FOREIGN KEY (tenant_id, variant_id, operation_id, collector_id)
        REFERENCES contour.variants (tenant_id, variant_id, operation_id, collector_id),
    FOREIGN KEY (tenant_id, operation_id, project_id, service_id, environment_id)
        REFERENCES contour.operations (tenant_id, operation_id, project_id, service_id, environment_id),
    FOREIGN KEY (tenant_id, source_id, collector_id, project_id, service_id, environment_id, deployment_id)
        REFERENCES contour.sources (tenant_id, source_id, collector_id, project_id, service_id, environment_id, deployment_id)
);
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['operations','variants','observation_windows','catalog_processed_batches'] LOOP
        EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',relation);
        EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',relation);
        EXECUTE format('CREATE POLICY catalog_tenant_scope ON contour.%I
            TO contour_catalog_worker, contour_catalog_reader
            USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',relation);
        EXECUTE format('CREATE TRIGGER immutable_catalog BEFORE UPDATE OR DELETE ON contour.%I
            FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',relation);
        EXECUTE format('GRANT SELECT, INSERT ON contour.%I TO contour_catalog_worker',relation);
        IF relation <> 'catalog_processed_batches' THEN
            EXECUTE format('GRANT SELECT ON contour.%I TO contour_catalog_reader',relation);
        END IF;
    END LOOP;
    FOREACH relation IN ARRAY ARRAY['ingestion_batches','ingestion_payloads'] LOOP
        EXECUTE format('CREATE POLICY catalog_inbox_read ON contour.%I FOR SELECT
            TO contour_catalog_worker USING (tenant_id=contour.tenant_context())',relation);
        EXECUTE format('GRANT SELECT ON contour.%I TO contour_catalog_worker',relation);
    END LOOP;
END $$;
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (4);
COMMIT;
