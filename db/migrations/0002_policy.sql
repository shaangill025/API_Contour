-- Requires a superuser or existing BYPASSRLS provisioning executor for backfill.
BEGIN;
SET LOCAL ROLE contour_owner;
CREATE TABLE contour.policy_revisions (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    revision numeric NOT NULL CHECK (revision = pg_catalog.trunc(revision)
        AND revision BETWEEN 1 AND 18446744073709551615),
    signed_envelope bytea NOT NULL CHECK (pg_catalog.octet_length(signed_envelope) BETWEEN 1 AND 1048576),
    PRIMARY KEY (tenant_id, collector_id, revision),
    FOREIGN KEY (tenant_id, collector_id) REFERENCES contour.collectors
);
CREATE TABLE contour.collector_authorization (
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    active_revision numeric,
    enabled boolean NOT NULL DEFAULT false,
    revoked_at timestamptz,
    PRIMARY KEY (tenant_id, collector_id),
    FOREIGN KEY (tenant_id, collector_id) REFERENCES contour.collectors,
    FOREIGN KEY (tenant_id, collector_id, active_revision) REFERENCES contour.policy_revisions,
    CHECK (NOT enabled OR (active_revision IS NOT NULL AND revoked_at IS NULL))
);
CREATE FUNCTION contour.valid_parser_profiles(profiles text[]) RETURNS boolean
LANGUAGE sql IMMUTABLE SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT coalesce(pg_catalog.array_ndims(profiles) = 1 AND pg_catalog.cardinality(profiles) BETWEEN 1 AND 128
        AND pg_catalog.cardinality(profiles) = (SELECT pg_catalog.count(DISTINCT name) FROM pg_catalog.unnest(profiles) name)
        AND (SELECT pg_catalog.bool_and(name IS NOT NULL AND name COLLATE "C" ~ '^[A-Za-z_][A-Za-z0-9_.-]{0,63}$')
            FROM pg_catalog.unnest(profiles) name), false)
$$;
ALTER TABLE contour.sources ADD UNIQUE (tenant_id, source_id, collector_id);
CREATE TABLE contour.source_authorization (
    tenant_id uuid NOT NULL,
    source_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    technique text NOT NULL CHECK (technique IN
        ('gateway','ebpf','browser','android','ios','cloud','messaging','runtime')),
    parser_profiles text[] NOT NULL CHECK (contour.valid_parser_profiles(parser_profiles)),
    PRIMARY KEY (tenant_id, source_id),
    FOREIGN KEY (tenant_id, source_id, collector_id)
        REFERENCES contour.sources (tenant_id, source_id, collector_id)
);
-- Existing identity tables FORCE RLS and exclude owner. Backfill as provisioning
-- administrator without granting BYPASSRLS or disabling a policy.
RESET ROLE;
DO $$ BEGIN
    IF NOT coalesce((SELECT rolsuper OR rolbypassrls FROM pg_catalog.pg_roles
        WHERE rolname = current_user), false) THEN
        RAISE EXCEPTION 'policy backfill requires bypass-capable provisioning executor'
            USING ERRCODE = '42501';
    END IF;
END $$;
INSERT INTO contour.collector_authorization (tenant_id, collector_id)
    SELECT tenant_id, collector_id FROM contour.collectors;
SET LOCAL ROLE contour_owner;

CREATE FUNCTION contour.collector_lock_key(tenant uuid, collector uuid) RETURNS bigint
LANGUAGE sql IMMUTABLE STRICT SECURITY INVOKER SET search_path = pg_catalog AS $$
    SELECT pg_catalog.hashtextextended('apicontour/collector/1:' || tenant::text || ':' || collector::text, 0)
$$;
CREATE FUNCTION contour.lock_collector(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'collector lock requires read committed' USING ERRCODE = '25001';
    END IF;
    IF tenant IS NULL OR collector IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'collector lock context mismatch' USING ERRCODE = '42501';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(contour.collector_lock_key(tenant, collector));
END $$;
CREATE FUNCTION contour.guard_collector(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'authority mutation requires read committed' USING ERRCODE = '25001';
    END IF;
    IF tenant IS NULL OR collector IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'authority mutation context mismatch' USING ERRCODE = '42501';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(contour.collector_lock_key(tenant, collector)) THEN
        RAISE EXCEPTION 'collector authority busy' USING ERRCODE = '40001';
    END IF;
END $$;
CREATE FUNCTION contour.authority_guard() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    IF TG_OP = 'UPDATE' THEN
        IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
            OR NEW.collector_id IS DISTINCT FROM OLD.collector_id THEN
            RAISE EXCEPTION 'authority identity immutable' USING ERRCODE = '23514';
        END IF;
        IF TG_TABLE_NAME = 'source_authorization' THEN
            IF NEW.source_id IS DISTINCT FROM OLD.source_id THEN
                RAISE EXCEPTION 'source identity immutable' USING ERRCODE = '23514';
            END IF;
        ELSE
            IF (OLD.active_revision IS NOT NULL AND (NEW.active_revision IS NULL
                OR NEW.active_revision < OLD.active_revision))
                OR (OLD.revoked_at IS NOT NULL AND NEW IS DISTINCT FROM OLD) THEN
                RAISE EXCEPTION 'authority rollback forbidden' USING ERRCODE = '23514';
            END IF;
        END IF;
    END IF;
    PERFORM contour.guard_collector(NEW.tenant_id, NEW.collector_id);
    RETURN NEW;
END $$;
CREATE FUNCTION contour.immutable_row() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN RAISE EXCEPTION 'immutable authority row' USING ERRCODE = '23514'; END $$;
CREATE FUNCTION contour.initialize_collector() RETURNS trigger
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
    INSERT INTO contour.collector_authorization (tenant_id, collector_id)
        VALUES (NEW.tenant_id, NEW.collector_id);
    RETURN NEW;
END $$;

CREATE TRIGGER policy_insert_guard BEFORE INSERT ON contour.policy_revisions
    FOR EACH ROW EXECUTE FUNCTION contour.authority_guard();
CREATE TRIGGER immutable_policy BEFORE UPDATE OR DELETE ON contour.policy_revisions
    FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER collector_authority_guard BEFORE INSERT OR UPDATE ON contour.collector_authorization
    FOR EACH ROW EXECUTE FUNCTION contour.authority_guard();
CREATE TRIGGER source_authority_guard BEFORE INSERT OR UPDATE ON contour.source_authorization
    FOR EACH ROW EXECUTE FUNCTION contour.authority_guard();
CREATE TRIGGER initialize_authority AFTER INSERT ON contour.collectors
    FOR EACH ROW EXECUTE FUNCTION contour.initialize_collector();
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['collectors','workload_assignments','sources'] LOOP
        EXECUTE pg_catalog.format('CREATE TRIGGER authority_insert_guard BEFORE INSERT ON contour.%I
            FOR EACH ROW EXECUTE FUNCTION contour.authority_guard()', relation);
    END LOOP;
    FOREACH relation IN ARRAY ARRAY['tenants','projects','services','environments',
        'deployments','collectors','workload_assignments','sources'] LOOP
        EXECUTE pg_catalog.format('REVOKE INSERT, UPDATE, DELETE ON contour.%I FROM contour_runtime', relation);
        EXECUTE pg_catalog.format('GRANT INSERT ON contour.%I TO contour_admin', relation);
        EXECUTE pg_catalog.format('CREATE TRIGGER immutable_identity BEFORE UPDATE OR DELETE ON contour.%I
            FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()', relation);
    END LOOP;
    FOREACH relation IN ARRAY ARRAY['policy_revisions','collector_authorization','source_authorization'] LOOP
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY', relation);
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY', relation);
        EXECUTE pg_catalog.format('CREATE POLICY tenant_scope ON contour.%I TO contour_runtime
            USING (tenant_id = contour.tenant_context()) WITH CHECK (tenant_id = contour.tenant_context())', relation);
        EXECUTE pg_catalog.format('GRANT SELECT ON contour.%I TO contour_runtime', relation);
        EXECUTE pg_catalog.format('GRANT INSERT ON contour.%I TO contour_admin', relation);
    END LOOP;
END $$;
GRANT UPDATE (active_revision, enabled, revoked_at) ON contour.collector_authorization TO contour_admin;
GRANT UPDATE (technique, parser_profiles) ON contour.source_authorization TO contour_admin;
-- transaction failure probe: fixture injects after DDL, backfill and grant changes.
REVOKE ALL ON FUNCTION contour.valid_parser_profiles(text[]), contour.collector_lock_key(uuid,uuid),
    contour.lock_collector(uuid,uuid), contour.guard_collector(uuid,uuid),
    contour.authority_guard(), contour.immutable_row(), contour.initialize_collector() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.collector_lock_key(uuid,uuid), contour.lock_collector(uuid,uuid)
    TO contour_runtime;
GRANT EXECUTE ON FUNCTION contour.valid_parser_profiles(text[]), contour.guard_collector(uuid,uuid)
    TO contour_admin;
INSERT INTO contour.schema_migrations(version) VALUES (2);
COMMIT;
