-- Whole-service import identities; raw uploaded documents are never stored here.
BEGIN;
SET LOCAL ROLE contour_owner;
CREATE TABLE contour.service_import_defaults (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,project_id,service_id),
    FOREIGN KEY (tenant_id,project_id,service_id)
        REFERENCES contour.services(tenant_id,project_id,service_id),
    FOREIGN KEY (tenant_id,project_id,environment_id)
        REFERENCES contour.environments(tenant_id,project_id,environment_id)
);
-- Only provisioning administrators configure defaults. Writer's tenant-column
-- privilege permits SELECT FOR SHARE, never a write, including a no-op write.
CREATE TRIGGER stable_import_default_scope BEFORE UPDATE OF tenant_id,project_id,service_id
    ON contour.service_import_defaults FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
GRANT SELECT ON contour.service_import_defaults TO contour_declared_writer,contour_declared_reader;
GRANT UPDATE (tenant_id) ON contour.service_import_defaults TO contour_declared_writer;
ALTER TABLE contour.service_import_defaults ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.service_import_defaults FORCE ROW LEVEL SECURITY;
CREATE POLICY import_default_read ON contour.service_import_defaults FOR SELECT
    TO contour_declared_writer,contour_declared_reader USING (tenant_id=contour.tenant_context());
CREATE POLICY import_default_lock ON contour.service_import_defaults FOR UPDATE
    TO contour_declared_writer USING (tenant_id=contour.tenant_context())
    WITH CHECK (tenant_id=contour.tenant_context());

CREATE TABLE contour.public_declared_contracts (
    tenant_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    revision bigint NOT NULL CHECK (revision BETWEEN 1 AND 9007199254740991),
    member_count integer NOT NULL CHECK (member_count BETWEEN 0 AND 4096),
    warnings text[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(warnings) <= 200 AND array_position(warnings,NULL) IS NULL
        AND warnings <@ ARRAY['unsupported_construct','removed_value','unresolved_reference','partial_import']::text[]),
    created_at timestamptz NOT NULL DEFAULT pg_catalog.clock_timestamp(),
    PRIMARY KEY (tenant_id,contract_id),
    UNIQUE (tenant_id,project_id,service_id,revision),
    UNIQUE (tenant_id,contract_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,project_id,service_id)
        REFERENCES contour.services(tenant_id,project_id,service_id),
    FOREIGN KEY (tenant_id,project_id,environment_id)
        REFERENCES contour.environments(tenant_id,project_id,environment_id)
);
CREATE TABLE contour.public_declared_members (
    tenant_id uuid NOT NULL,
    contract_id uuid NOT NULL,
    version_id uuid NOT NULL,
    operation_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    PRIMARY KEY (tenant_id,contract_id,version_id),
    FOREIGN KEY (tenant_id,contract_id,project_id,service_id,environment_id)
        REFERENCES contour.public_declared_contracts
            (tenant_id,contract_id,project_id,service_id,environment_id),
    FOREIGN KEY (tenant_id,version_id,operation_id,project_id,service_id,environment_id)
        REFERENCES contour.declared_versions
            (tenant_id,version_id,operation_id,project_id,service_id,environment_id)
);
-- Count checked at transaction completion seals the manifest against later append.
-- Multiple checked graphs for one operation are allowed; exact members are unique.
CREATE FUNCTION contour.check_public_contract_members() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,contour AS $$
DECLARE expected integer; actual bigint;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'contract tenant context required' USING ERRCODE='42501';
    END IF;
    SELECT member_count INTO expected FROM contour.public_declared_contracts
        WHERE tenant_id=NEW.tenant_id AND contract_id=NEW.contract_id;
    SELECT count(*) INTO actual FROM contour.public_declared_members
        WHERE tenant_id=NEW.tenant_id AND contract_id=NEW.contract_id;
    IF expected IS NULL OR actual <> expected THEN
        RAISE EXCEPTION 'incomplete contract membership' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION contour.check_public_contract_members() FROM PUBLIC;
CREATE CONSTRAINT TRIGGER complete_public_contract AFTER INSERT ON contour.public_declared_contracts
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.check_public_contract_members();
CREATE CONSTRAINT TRIGGER complete_public_members AFTER INSERT ON contour.public_declared_members
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.check_public_contract_members();
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['public_declared_contracts','public_declared_members'] LOOP
        EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',relation);
        EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',relation);
        EXECUTE format('CREATE POLICY public_contract_tenant ON contour.%I
            TO contour_declared_writer,contour_declared_reader
            USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',relation);
        EXECUTE format('CREATE TRIGGER immutable_public_contract BEFORE UPDATE OR DELETE
            ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',relation);
        EXECUTE format('GRANT SELECT ON contour.%I TO contour_declared_writer,contour_declared_reader',relation);
    END LOOP;
END $$;
GRANT INSERT (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,warnings)
    ON contour.public_declared_contracts TO contour_declared_writer;
GRANT INSERT ON contour.public_declared_members TO contour_declared_writer;
-- transaction failure probe: fixture injects after all DDL, grants and triggers.
INSERT INTO contour.schema_migrations(version) VALUES (10);
COMMIT;
