-- Immutable internal declared/approved comparisons, not public result projection.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_comparison_writer, contour_comparison_reader;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_comparison_writer, contour_comparison_reader;
ALTER TABLE contour.approval_events ADD CONSTRAINT approval_comparison_scope
    UNIQUE (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id);
CREATE TABLE contour.comparisons (
    tenant_id uuid NOT NULL,
    comparison_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    left_kind text NOT NULL CHECK (left_kind IN ('declared','approved')),
    left_version_id uuid NOT NULL,
    left_event_id uuid,
    right_kind text NOT NULL CHECK (right_kind IN ('declared','approved')),
    right_version_id uuid NOT NULL,
    right_event_id uuid,
    evaluator_version smallint NOT NULL CHECK (evaluator_version=1),
    result_codec_version smallint NOT NULL CHECK (result_codec_version=1),
    result_wire bytea NOT NULL CHECK (octet_length(result_wire) BETWEEN 1 AND 1048576),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id,comparison_id),
    CHECK ((left_kind='approved')=(left_event_id IS NOT NULL)),
    CHECK ((right_kind='approved')=(right_event_id IS NOT NULL)),
    FOREIGN KEY (tenant_id,left_version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.declared_versions
            (tenant_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,right_version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.declared_versions
            (tenant_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,left_event_id,left_version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,right_event_id,right_version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id)
);
ALTER TABLE contour.comparisons ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.comparisons FORCE ROW LEVEL SECURITY;
CREATE POLICY comparison_tenant ON contour.comparisons
    TO contour_comparison_writer, contour_comparison_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE TRIGGER immutable_comparison BEFORE UPDATE OR DELETE ON contour.comparisons
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
GRANT SELECT ON contour.comparisons TO contour_comparison_writer, contour_comparison_reader;
GRANT INSERT (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,
    evaluator_version,result_codec_version,result_wire)
    ON contour.comparisons TO contour_comparison_writer;
-- Scoped input metadata permits resolution without capture data or mutable heads.
GRANT SELECT (tenant_id,version_id,operation_id,project_id,service_id,environment_id)
    ON contour.declared_versions TO contour_comparison_writer, contour_comparison_reader;
CREATE POLICY comparison_declared_read ON contour.declared_versions FOR SELECT
    TO contour_comparison_writer, contour_comparison_reader USING (tenant_id=contour.tenant_context());
GRANT SELECT (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id)
    ON contour.approval_events TO contour_comparison_writer, contour_comparison_reader;
CREATE POLICY comparison_approval_read ON contour.approval_events FOR SELECT
    TO contour_comparison_writer, contour_comparison_reader USING (tenant_id=contour.tenant_context());
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (7);
COMMIT;
