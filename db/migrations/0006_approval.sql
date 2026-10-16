-- Internal approved associations. Public reviews and decisions are separate.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_approval_writer, contour_approval_reader;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_approval_writer, contour_approval_reader;
ALTER TABLE contour.declared_versions ADD CONSTRAINT declared_approval_scope
    UNIQUE (tenant_id,version_id,operation_id,project_id,service_id,environment_id);
-- Each immutable event is also its actor audit association. No free-form payload.
CREATE TABLE contour.approval_events (
    tenant_id uuid NOT NULL,
    event_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    version_id uuid NOT NULL,
    expected_event_id uuid,
    actor_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id,event_id),
    UNIQUE (tenant_id,event_id,operation_id,project_id,service_id,environment_id),
    CHECK (event_id IS DISTINCT FROM expected_event_id),
    FOREIGN KEY (tenant_id,version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.declared_versions
            (tenant_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,expected_event_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,operation_id,project_id,service_id,environment_id)
);
-- Stable lock row for first approval as well as replacement; null means no approval.
CREATE TABLE contour.approval_heads (
    tenant_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    current_event_id uuid,
    PRIMARY KEY (tenant_id,operation_id),
    FOREIGN KEY (tenant_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.operations (tenant_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,current_event_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,operation_id,project_id,service_id,environment_id)
);
ALTER TABLE contour.approval_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.approval_events FORCE ROW LEVEL SECURITY;
ALTER TABLE contour.approval_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.approval_heads FORCE ROW LEVEL SECURITY;
CREATE POLICY approval_event_tenant ON contour.approval_events
    TO contour_approval_writer, contour_approval_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE POLICY approval_head_tenant ON contour.approval_heads
    TO contour_approval_writer, contour_approval_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
CREATE TRIGGER immutable_approval_event BEFORE UPDATE OR DELETE ON contour.approval_events
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
GRANT SELECT ON contour.approval_events, contour.approval_heads
    TO contour_approval_writer, contour_approval_reader;
GRANT INSERT (tenant_id,event_id,operation_id,project_id,service_id,environment_id,
    version_id,expected_event_id,actor_id) ON contour.approval_events TO contour_approval_writer;
GRANT INSERT (tenant_id,operation_id,project_id,service_id,environment_id,current_event_id),
    UPDATE (current_event_id) ON contour.approval_heads TO contour_approval_writer;
-- No graph bytes or observation payloads are needed by the association transaction.
GRANT SELECT (tenant_id,version_id,operation_id,project_id,service_id,environment_id)
    ON contour.declared_versions TO contour_approval_writer, contour_approval_reader;
CREATE POLICY approval_declared_read ON contour.declared_versions FOR SELECT
    TO contour_approval_writer, contour_approval_reader USING (tenant_id=contour.tenant_context());
GRANT SELECT ON contour.operations TO contour_approval_writer, contour_approval_reader;
CREATE POLICY approval_operation_read ON contour.operations FOR SELECT
    TO contour_approval_writer, contour_approval_reader USING (tenant_id=contour.tenant_context());
-- transaction failure probe: fixture injects after all DDL and grants.
INSERT INTO contour.schema_migrations(version) VALUES (6);
COMMIT;
