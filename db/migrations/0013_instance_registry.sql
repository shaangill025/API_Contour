-- Registry only: these rows do not prove capture origin or lifecycle validity.
BEGIN;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.sources ADD COLUMN binding_mode text NOT NULL DEFAULT 'unbound'
    CHECK (binding_mode IN ('unbound','instance'));
CREATE TABLE contour.workload_instances (
    tenant_id uuid NOT NULL, project_id uuid NOT NULL, service_id uuid NOT NULL,
    environment_id uuid NOT NULL, deployment_id uuid NOT NULL, instance_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, instance_id),
    UNIQUE (tenant_id, project_id, service_id, environment_id, deployment_id, instance_id),
    FOREIGN KEY (tenant_id, project_id, service_id, environment_id, deployment_id)
        REFERENCES contour.deployments (tenant_id, project_id, service_id, environment_id, deployment_id)
);
CREATE TABLE contour.source_instance_bindings (
    tenant_id uuid NOT NULL, source_id uuid NOT NULL, collector_id uuid NOT NULL,
    project_id uuid NOT NULL, service_id uuid NOT NULL, environment_id uuid NOT NULL,
    deployment_id uuid NOT NULL, instance_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, source_id),
    FOREIGN KEY (tenant_id, source_id, collector_id, project_id, service_id, environment_id, deployment_id)
        REFERENCES contour.sources (tenant_id, source_id, collector_id, project_id, service_id, environment_id, deployment_id),
    FOREIGN KEY (tenant_id, project_id, service_id, environment_id, deployment_id, instance_id)
        REFERENCES contour.workload_instances (tenant_id, project_id, service_id, environment_id, deployment_id, instance_id)
);
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['workload_instances','source_instance_bindings'] LOOP
        EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY', relation);
        EXECUTE format('CREATE POLICY instance_tenant_scope ON contour.%I TO contour_admin USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())', relation);
        EXECUTE format('GRANT SELECT, INSERT ON contour.%I TO contour_admin', relation);
        EXECUTE format('CREATE TRIGGER immutable_instance BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()', relation);
    END LOOP;
END $$;
CREATE FUNCTION contour.guard_instance_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM contour.guard_collector(NEW.tenant_id, NEW.collector_id);
    IF NOT EXISTS (SELECT 1 FROM contour.sources s WHERE s.tenant_id=NEW.tenant_id
        AND s.source_id=NEW.source_id AND s.binding_mode='instance') THEN
        RAISE EXCEPTION 'source is not instance-bound' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER instance_binding_guard BEFORE INSERT ON contour.source_instance_bindings
    FOR EACH ROW EXECUTE FUNCTION contour.guard_instance_binding();
CREATE FUNCTION contour.require_instance_binding() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF NEW.binding_mode='instance' AND NOT EXISTS (SELECT 1 FROM contour.source_instance_bindings b
        WHERE b.tenant_id=NEW.tenant_id AND b.source_id=NEW.source_id) THEN
        RAISE EXCEPTION 'instance source requires binding in same transaction' USING ERRCODE='23514';
    END IF;
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER instance_source_requires_binding AFTER INSERT ON contour.sources
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION contour.require_instance_binding();
-- Caller holds the collector lock in a preceding statement, before fresh reads.
CREATE FUNCTION contour.register_instance_source(tenant uuid, source uuid, collector uuid,
    project uuid, service uuid, environment uuid, deployment uuid, nonce uuid, instance uuid)
RETURNS void LANGUAGE plpgsql SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    INSERT INTO contour.sources (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id,source_nonce,binding_mode)
        VALUES (tenant,source,collector,project,service,environment,deployment,nonce,'instance');
    INSERT INTO contour.source_instance_bindings VALUES
        (tenant,source,collector,project,service,environment,deployment,instance);
END $$;
REVOKE ALL ON FUNCTION contour.guard_instance_binding(), contour.require_instance_binding(),
    contour.register_instance_source(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.register_instance_source(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) TO contour_admin;
-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (13);
COMMIT;
