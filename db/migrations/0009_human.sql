-- Operator-provisioned human metadata, not login/session or endpoint authorization.
BEGIN;
SET LOCAL ROLE contour_owner;
GRANT USAGE ON SCHEMA contour TO contour_human_provisioner,contour_human_lookup;
CREATE TABLE contour.human_actors (
    actor_id uuid PRIMARY KEY,
    enabled boolean NOT NULL DEFAULT false
);
CREATE TABLE contour.human_identities (
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 1024
        AND issuer !~ '[[:cntrl:]]'),
    subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255
        AND subject ~ '^[ -~]+$'),
    actor_id uuid NOT NULL REFERENCES contour.human_actors(actor_id),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (issuer,subject)
);
CREATE TABLE contour.human_tenant_memberships (
    tenant_id uuid NOT NULL REFERENCES contour.tenants(tenant_id),
    actor_id uuid NOT NULL REFERENCES contour.human_actors(actor_id),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id,actor_id)
);
CREATE TABLE contour.human_project_memberships (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id,project_id,actor_id),
    FOREIGN KEY (tenant_id,actor_id)
        REFERENCES contour.human_tenant_memberships(tenant_id,actor_id),
    FOREIGN KEY (tenant_id,project_id)
        REFERENCES contour.projects(tenant_id,project_id)
);
CREATE TABLE contour.human_service_roles (
    tenant_id uuid NOT NULL,
    project_id uuid NOT NULL,
    service_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    role text COLLATE "C" NOT NULL CHECK (role IN
        ('viewer','service_owner','policy_administrator','operator','security_reviewer')),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (tenant_id,project_id,service_id,actor_id,role),
    FOREIGN KEY (tenant_id,project_id,actor_id)
        REFERENCES contour.human_project_memberships(tenant_id,project_id,actor_id),
    FOREIGN KEY (tenant_id,project_id,service_id)
        REFERENCES contour.services(tenant_id,project_id,service_id)
);
-- These are trusted operator/authentication metadata roles, NOT tenant-user roles.
-- Identity resolution precedes tenant selection. The lookup role intentionally sees
-- all identity/membership metadata, including disabled records, without any tenant
-- GUC. The future adapter must check every enabled flag and exact scope per request.
-- No business rows, collector identities, tokens, email or graph bytes are granted.
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['human_actors','human_identities',
        'human_tenant_memberships','human_project_memberships','human_service_roles'] LOOP
        EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',relation);
        EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',relation);
        EXECUTE format('CREATE POLICY human_lookup ON contour.%I FOR SELECT
            TO contour_human_lookup USING (true)',relation);
        EXECUTE format('CREATE POLICY human_provision ON contour.%I
            TO contour_human_provisioner USING (true) WITH CHECK (true)',relation);
        EXECUTE format('GRANT SELECT,INSERT ON contour.%I TO contour_human_provisioner',relation);
        EXECUTE format('GRANT UPDATE (enabled) ON contour.%I TO contour_human_provisioner',relation);
        EXECUTE format('GRANT SELECT ON contour.%I TO contour_human_lookup',relation);
        -- Row locks require UPDATE on at least one column. This trigger rejects
        -- every actual actor_id UPDATE, including no-ops, without blocking enabled.
        EXECUTE format('GRANT UPDATE (actor_id) ON contour.%I TO contour_human_lookup',relation);
        EXECUTE format('CREATE POLICY human_lookup_lock ON contour.%I FOR UPDATE
            TO contour_human_lookup USING (true) WITH CHECK (true)',relation);
        EXECUTE format('CREATE TRIGGER human_stable_actor BEFORE UPDATE OF actor_id
            ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',relation);
    END LOOP;
END $$;
-- No DELETE/TRUNCATE or mutable key authority. The lookup actor_id grant is
-- lock-only in behavior because its trigger rejects every write. Disable records instead of
-- deleting/reassigning actors, identities or scope keys. Foreign keys never cascade.
-- transaction failure probe: fixture injects after all DDL, grants and policies.
INSERT INTO contour.schema_migrations(version) VALUES (9);
COMMIT;
