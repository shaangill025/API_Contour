-- Internal sanitized codec storage; checked decoding belongs to the trusted adapter.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_declared_writer, contour_declared_reader;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_declared_writer, contour_declared_reader;
CREATE TABLE contour.declared_versions (
    tenant_id uuid NOT NULL,
    version_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    codec_version smallint NOT NULL CHECK (codec_version=1),
    declared_wire bytea NOT NULL CHECK (octet_length(declared_wire) BETWEEN 1 AND 1048576),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id, version_id),
    FOREIGN KEY (tenant_id, operation_id, project_id, service_id, environment_id)
        REFERENCES contour.operations (tenant_id, operation_id, project_id, service_id, environment_id)
);
ALTER TABLE contour.declared_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.declared_versions FORCE ROW LEVEL SECURITY;
CREATE POLICY declared_tenant_scope ON contour.declared_versions
    TO contour_declared_writer, contour_declared_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE TRIGGER immutable_declared BEFORE UPDATE OR DELETE ON contour.declared_versions
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
GRANT SELECT ON contour.declared_versions TO contour_declared_writer, contour_declared_reader;
-- Only the server supplies the creation time. Explicit column lists are required.
GRANT INSERT (tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
    ON contour.declared_versions TO contour_declared_writer;
-- Imports can create operation identity before any observed traffic exists.
GRANT SELECT ON contour.operations TO contour_declared_writer, contour_declared_reader;
GRANT INSERT ON contour.operations TO contour_declared_writer;
CREATE POLICY declared_operation_read ON contour.operations FOR SELECT
    TO contour_declared_writer, contour_declared_reader USING (tenant_id=contour.tenant_context());
CREATE POLICY declared_operation_insert ON contour.operations FOR INSERT
    TO contour_declared_writer WITH CHECK (tenant_id=contour.tenant_context());
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (5);
COMMIT;
