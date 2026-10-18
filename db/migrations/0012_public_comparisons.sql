-- Preserve the selected public import identity independently of graph identity.
BEGIN;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.comparisons ADD COLUMN public_projection smallint
    NOT NULL DEFAULT 1 CHECK (public_projection IN (1,2));
GRANT INSERT (public_projection) ON contour.comparisons TO contour_comparison_writer;
ALTER TABLE contour.public_declared_members ADD CONSTRAINT public_member_comparison_scope
    UNIQUE (tenant_id,contract_id,version_id,operation_id,project_id,service_id,environment_id);
CREATE TABLE contour.public_comparison_inputs (
    tenant_id uuid NOT NULL,
    comparison_id uuid NOT NULL,
    side text NOT NULL CHECK (side IN ('left','right')),
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    input_kind text NOT NULL CHECK (input_kind IN ('declared','approved')),
    public_input_id uuid NOT NULL,
    declared_contract_id uuid NOT NULL,
    version_id uuid NOT NULL,
    approval_event_id uuid,
    PRIMARY KEY (tenant_id,comparison_id,side),
    CHECK ((input_kind='approved')=(approval_event_id IS NOT NULL)),
    CHECK (public_input_id=CASE WHEN input_kind='declared'
        THEN declared_contract_id ELSE approval_event_id END),
    FOREIGN KEY (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,declared_contract_id,version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.public_declared_members
            (tenant_id,contract_id,version_id,operation_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,approval_event_id,version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.approval_events
            (tenant_id,event_id,version_id,operation_id,project_id,service_id,environment_id)
);
ALTER TABLE contour.public_comparison_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.public_comparison_inputs FORCE ROW LEVEL SECURITY;
CREATE POLICY public_comparison_tenant ON contour.public_comparison_inputs
    TO contour_comparison_writer,contour_comparison_reader
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
GRANT SELECT ON contour.public_comparison_inputs TO contour_comparison_writer,contour_comparison_reader;
GRANT INSERT ON contour.public_comparison_inputs TO contour_comparison_writer;
CREATE TRIGGER immutable_public_comparison BEFORE UPDATE OR DELETE ON contour.public_comparison_inputs
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE FUNCTION contour.check_public_comparison_inputs() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,contour AS $$
DECLARE comparison contour.comparisons; actual bigint; invalid boolean;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'comparison tenant context required' USING ERRCODE='42501';
    END IF;
    SELECT * INTO comparison FROM contour.comparisons
        WHERE tenant_id=NEW.tenant_id AND comparison_id=NEW.comparison_id;
    SELECT count(*),coalesce(bool_or(
        input_kind IS DISTINCT FROM CASE side WHEN 'left' THEN comparison.left_kind ELSE comparison.right_kind END
        OR version_id IS DISTINCT FROM CASE side WHEN 'left' THEN comparison.left_version_id ELSE comparison.right_version_id END
        OR approval_event_id IS DISTINCT FROM CASE side WHEN 'left' THEN comparison.left_event_id ELSE comparison.right_event_id END
    ),false) INTO actual,invalid FROM contour.public_comparison_inputs
        WHERE tenant_id=NEW.tenant_id AND comparison_id=NEW.comparison_id;
    IF comparison.comparison_id IS NULL OR invalid
        OR actual <> (CASE comparison.public_projection WHEN 1 THEN 0 ELSE 2 END) THEN
        RAISE EXCEPTION 'incomplete or mismatched public comparison inputs' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION contour.check_public_comparison_inputs() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER complete_public_comparison AFTER INSERT ON contour.comparisons
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.check_public_comparison_inputs();
CREATE CONSTRAINT TRIGGER complete_public_comparison_inputs AFTER INSERT ON contour.public_comparison_inputs
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.check_public_comparison_inputs();
-- transaction failure probe: fixture injects after all DDL, grants and triggers.
INSERT INTO contour.schema_migrations(version) VALUES (12);
COMMIT;
