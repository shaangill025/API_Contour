BEGIN;
SET LOCAL ROLE contour_owner;
CREATE SCHEMA contour AUTHORIZATION contour_owner;
REVOKE ALL ON SCHEMA contour FROM PUBLIC;
GRANT USAGE ON SCHEMA contour TO contour_runtime;

CREATE TABLE contour.schema_migrations (
    version integer PRIMARY KEY,
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE contour.tenants (
    tenant_id uuid PRIMARY KEY
);
-- transaction failure probe: fixture injects an error here, never production.
CREATE TABLE contour.projects (
    tenant_id uuid NOT NULL REFERENCES contour.tenants(tenant_id),
    project_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, project_id)
);
CREATE TABLE contour.services (
    tenant_id uuid NOT NULL,
    service_id uuid NOT NULL,
    project_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, service_id),
    UNIQUE (tenant_id, project_id, service_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES contour.projects(tenant_id, project_id)
);
CREATE TABLE contour.environments (
    tenant_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    project_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, environment_id),
    UNIQUE (tenant_id, project_id, environment_id),
    FOREIGN KEY (tenant_id, project_id) REFERENCES contour.projects(tenant_id, project_id)
);
CREATE TABLE contour.deployments (
    tenant_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, deployment_id),
    UNIQUE (tenant_id, project_id, service_id, environment_id, deployment_id),
    FOREIGN KEY (tenant_id, project_id, service_id)
        REFERENCES contour.services(tenant_id, project_id, service_id),
    FOREIGN KEY (tenant_id, project_id, environment_id)
        REFERENCES contour.environments(tenant_id, project_id, environment_id)
);
CREATE TABLE contour.collectors (
    tenant_id uuid NOT NULL REFERENCES contour.tenants(tenant_id),
    collector_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, collector_id)
);
CREATE TABLE contour.workload_assignments (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, collector_id, project_id, service_id, environment_id, deployment_id),
    FOREIGN KEY (tenant_id, collector_id) REFERENCES contour.collectors(tenant_id, collector_id),
    FOREIGN KEY (tenant_id, project_id, service_id, environment_id, deployment_id)
        REFERENCES contour.deployments(tenant_id, project_id, service_id, environment_id, deployment_id)
);
CREATE TABLE contour.sources (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    environment_id uuid NOT NULL,
    deployment_id uuid NOT NULL,
    source_nonce uuid NOT NULL,
    PRIMARY KEY (tenant_id, source_id),
    UNIQUE (tenant_id, collector_id, source_nonce),
    FOREIGN KEY (tenant_id, collector_id, project_id, service_id, environment_id, deployment_id)
        REFERENCES contour.workload_assignments
            (tenant_id, collector_id, project_id, service_id, environment_id, deployment_id)
);

CREATE FUNCTION contour.tenant_context() RETURNS uuid
LANGUAGE sql STABLE SET search_path = pg_catalog
AS $$ SELECT nullif(current_setting('apicontour.tenant_id', true), '')::uuid $$;
REVOKE ALL ON FUNCTION contour.tenant_context() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.tenant_context() TO contour_runtime;

DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['tenants', 'projects', 'services', 'environments',
        'deployments', 'collectors', 'workload_assignments', 'sources'] LOOP
        EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY', relation);
        EXECUTE format('CREATE POLICY tenant_scope ON contour.%I TO contour_runtime
            USING (tenant_id = contour.tenant_context())
            WITH CHECK (tenant_id = contour.tenant_context())', relation);
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON contour.%I TO contour_runtime', relation);
    END LOOP;
END $$;
INSERT INTO contour.schema_migrations(version) VALUES (1);
COMMIT;
