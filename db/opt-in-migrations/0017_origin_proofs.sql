-- Opt-in origin ingress capability, phase 1. This does not admit origin proofs.
-- A trusted application must authenticate its collector independently.
BEGIN;
SET LOCAL ROLE contour_owner;

CREATE TABLE contour.origin_ingress_context (
    transaction_id bigint NOT NULL,
    backend_pid integer NOT NULL,
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    started_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(started_at)),
    PRIMARY KEY (transaction_id, backend_pid)
);
ALTER TABLE contour.origin_ingress_context ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_ingress_context FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_ingress_context_owner ON contour.origin_ingress_context TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_ingress_context FROM PUBLIC, contour_origin_ingress;

-- Deferred cleanup is transactional: rollback removes the insertion, commit
-- deletes it. Temporarily restore the row's tenant even if the caller changed
-- its tenant setting since beginning the operation. Forced RLS remains active.
CREATE FUNCTION contour.cleanup_origin_ingress_context() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE prior text;
BEGIN
    prior := pg_catalog.current_setting('apicontour.tenant_id', true);
    PERFORM pg_catalog.set_config('apicontour.tenant_id', NEW.tenant_id::text, true);
    DELETE FROM contour.origin_ingress_context c
      WHERE c.transaction_id=NEW.transaction_id AND c.backend_pid=NEW.backend_pid
        AND c.tenant_id=NEW.tenant_id AND c.collector_id=NEW.collector_id;
    PERFORM pg_catalog.set_config('apicontour.tenant_id', coalesce(prior,''), true);
    RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER cleanup_origin_ingress_context
    AFTER INSERT ON contour.origin_ingress_context DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION contour.cleanup_origin_ingress_context();

CREATE FUNCTION contour.begin_origin_ingress(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE at_time timestamptz;
BEGIN
    -- This guard refuses any preheld advisory lock, including session locks,
    -- and acquires Q first. The collector gate is then held through transaction end.
    PERFORM contour.begin_origin_operation(tenant);
    PERFORM contour.lock_origin_collector(tenant,collector);
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_ingress_context
        VALUES (pg_catalog.txid_current(),pg_catalog.pg_backend_pid(),tenant,collector,at_time);
END $$;

-- The private row is required in addition to advisory locks; locks and GUCs
-- alone cannot establish authority. A later proof writer must invoke this.
CREATE FUNCTION contour.require_origin_ingress(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM contour.require_origin_locks(tenant,collector,NULL);
    IF collector IS NULL OR NOT EXISTS (
        SELECT 1 FROM contour.origin_ingress_context c
        WHERE c.transaction_id=pg_catalog.txid_current()
          AND c.backend_pid=pg_catalog.pg_backend_pid()
          AND c.tenant_id=tenant AND c.collector_id=collector
    ) THEN
        RAISE EXCEPTION 'origin ingress context required' USING ERRCODE='42501';
    END IF;
END $$;
REVOKE ALL ON FUNCTION contour.cleanup_origin_ingress_context(),
    contour.begin_origin_ingress(uuid,uuid), contour.require_origin_ingress(uuid,uuid) FROM PUBLIC;
GRANT USAGE ON SCHEMA contour TO contour_origin_ingress;
GRANT EXECUTE ON FUNCTION contour.begin_origin_ingress(uuid,uuid), contour.require_origin_ingress(uuid,uuid)
    TO contour_origin_ingress;
-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (17);
COMMIT;
