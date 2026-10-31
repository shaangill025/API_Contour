-- Opt-in origin ingress capability and origin epoch/clock state. This does not admit proofs.
-- A trusted application must authenticate its collector independently.
BEGIN;
SET LOCAL ROLE contour_owner;

-- Facts present at activation have unknown relative ordering, represented by 0.
ALTER TABLE contour.origin_lifecycles ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_credentials ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_observer_grants ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);
ALTER TABLE contour.origin_terminal_events ADD COLUMN fact_epoch bigint NOT NULL DEFAULT 0 CHECK (fact_epoch >= 0);

CREATE TABLE contour.origin_tenant_state (
    tenant_id uuid PRIMARY KEY,
    epoch bigint NOT NULL CHECK (epoch >= 0),
    clock_floor timestamptz CHECK (clock_floor IS NULL OR pg_catalog.isfinite(clock_floor))
);
ALTER TABLE contour.origin_tenant_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.origin_tenant_state FORCE ROW LEVEL SECURITY;
CREATE POLICY origin_tenant_state_owner ON contour.origin_tenant_state TO contour_owner
    USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.origin_tenant_state FROM PUBLIC, contour_origin_ingress;

-- Bound the lazy terminal-event seed to one tenant, including all event kinds.
CREATE INDEX origin_terminal_tenant_time ON contour.origin_terminal_events (tenant_id,event_at);

-- Called only under Q. The history scan occurs once per tenant, at lazy seed.
CREATE FUNCTION contour.ensure_origin_tenant_state(tenant uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    PERFORM contour.require_origin_locks(tenant,NULL,NULL);
    IF NOT EXISTS (SELECT 1 FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant) THEN
        INSERT INTO contour.origin_tenant_state (tenant_id,epoch,clock_floor)
        SELECT tenant,0,max(h.at_time) FROM (
          SELECT l.enrolled_at AS at_time FROM contour.origin_lifecycles l WHERE l.tenant_id=tenant
          UNION ALL SELECT c.enrolled_at FROM contour.origin_credentials c WHERE c.tenant_id=tenant
          UNION ALL SELECT g.granted_at FROM contour.origin_observer_grants g WHERE g.tenant_id=tenant
          UNION ALL SELECT e.event_at FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant
        ) h;
    END IF;
END $$;

-- The existing mutation entrypoints supply server time and hold Q. The trigger
-- overrides any supplied epoch and advances both fields transactionally.
CREATE FUNCTION contour.assign_origin_fact_epoch() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE at_time timestamptz; state_epoch bigint; floor_time timestamptz;
BEGIN
    PERFORM contour.ensure_origin_tenant_state(NEW.tenant_id);
    IF TG_TABLE_NAME IN ('origin_lifecycles','origin_credentials') THEN at_time := NEW.enrolled_at;
    ELSIF TG_TABLE_NAME='origin_observer_grants' THEN at_time := NEW.granted_at;
    ELSE at_time := NEW.event_at; END IF;
    SELECT s.epoch,s.clock_floor INTO state_epoch,floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=NEW.tenant_id FOR UPDATE;
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR (floor_time IS NOT NULL AND at_time < floor_time) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    IF state_epoch = 9223372036854775807 THEN
        RAISE EXCEPTION 'origin epoch exhausted' USING ERRCODE='54000';
    END IF;
    NEW.fact_epoch := state_epoch + 1;
    UPDATE contour.origin_tenant_state SET epoch=NEW.fact_epoch,clock_floor=at_time WHERE tenant_id=NEW.tenant_id;
    RETURN NEW;
END $$;
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'] LOOP
        EXECUTE pg_catalog.format('CREATE TRIGGER origin_z_fact_epoch BEFORE INSERT ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.assign_origin_fact_epoch()',relation);
    END LOOP;
END $$;
-- Preserve the existing lifecycle history check, and extend it by the tenant
-- floor. Proof acceptance can advance this same floor in a later phase.
ALTER FUNCTION contour.origin_history_highwater(uuid,uuid) RENAME TO origin_lifecycle_highwater;
CREATE FUNCTION contour.origin_history_highwater(tenant uuid, lifecycle uuid) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE history_time timestamptz; floor_time timestamptz;
BEGIN
    history_time := contour.origin_lifecycle_highwater(tenant,lifecycle);
    SELECT s.clock_floor INTO floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant;
    RETURN greatest(history_time,floor_time);
END $$;
REVOKE ALL ON FUNCTION contour.ensure_origin_tenant_state(uuid), contour.assign_origin_fact_epoch(),
    contour.origin_lifecycle_highwater(uuid,uuid), contour.origin_history_highwater(uuid,uuid) FROM PUBLIC;

CREATE TABLE contour.origin_ingress_context (
    transaction_id bigint NOT NULL,
    backend_pid integer NOT NULL,
    tenant_id uuid NOT NULL,
    collector_id uuid NOT NULL,
    started_at timestamptz NOT NULL CHECK (pg_catalog.isfinite(started_at)),
    fact_epoch bigint NOT NULL CHECK (fact_epoch >= 0),
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
DECLARE at_time timestamptz; current_epoch bigint; floor_time timestamptz;
BEGIN
    -- This guard refuses any preheld advisory lock, including session locks,
    -- and acquires Q first. The collector gate is then held through transaction end.
    PERFORM contour.begin_origin_operation(tenant);
    PERFORM contour.lock_origin_collector(tenant,collector);
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    PERFORM contour.ensure_origin_tenant_state(tenant);
    SELECT s.epoch,s.clock_floor INTO current_epoch,floor_time FROM contour.origin_tenant_state s WHERE s.tenant_id=tenant;
    IF floor_time IS NOT NULL AND at_time < floor_time THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_ingress_context
        VALUES (pg_catalog.txid_current(),pg_catalog.pg_backend_pid(),tenant,collector,at_time,current_epoch);
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
