-- Opt-in registry only. The trusted provisioner validates platform evidence;
-- rows and caller-supplied leaf digests are not authentication or admission.
BEGIN;
SET LOCAL ROLE contour_owner;

CREATE TABLE contour.origin_lifecycles (
    tenant_id uuid NOT NULL, lifecycle_id uuid NOT NULL,
    project_id uuid NOT NULL, service_id uuid NOT NULL, environment_id uuid NOT NULL,
    deployment_id uuid NOT NULL, instance_id uuid NOT NULL,
    platform_kind text NOT NULL CHECK (platform_kind = 'trusted_platform_v1'),
    platform_evidence_sha256 bytea NOT NULL CHECK (octet_length(platform_evidence_sha256)=32),
    enrolled_at timestamptz NOT NULL CHECK (isfinite(enrolled_at)),
    PRIMARY KEY (tenant_id,lifecycle_id), UNIQUE (tenant_id,instance_id),
    FOREIGN KEY (tenant_id,project_id,service_id,environment_id,deployment_id,instance_id)
        REFERENCES contour.workload_instances (tenant_id,project_id,service_id,environment_id,deployment_id,instance_id)
);
CREATE TABLE contour.origin_credentials (
    tenant_id uuid NOT NULL, credential_id uuid NOT NULL, lifecycle_id uuid NOT NULL,
    leaf_sha256 bytea NOT NULL CHECK (octet_length(leaf_sha256)=32),
    enrolled_at timestamptz NOT NULL CHECK (isfinite(enrolled_at)),
    PRIMARY KEY (tenant_id,credential_id), UNIQUE (leaf_sha256),
    FOREIGN KEY (tenant_id,lifecycle_id) REFERENCES contour.origin_lifecycles
);
CREATE INDEX origin_credentials_lifecycle ON contour.origin_credentials(tenant_id,lifecycle_id);
CREATE TABLE contour.origin_observer_grants (
    tenant_id uuid NOT NULL, grant_id uuid NOT NULL, lifecycle_id uuid NOT NULL,
    source_id uuid NOT NULL, collector_id uuid NOT NULL, project_id uuid NOT NULL,
    service_id uuid NOT NULL, environment_id uuid NOT NULL, deployment_id uuid NOT NULL,
    granted_at timestamptz NOT NULL CHECK (isfinite(granted_at)),
    PRIMARY KEY (tenant_id,grant_id),
    FOREIGN KEY (tenant_id,lifecycle_id) REFERENCES contour.origin_lifecycles,
    FOREIGN KEY (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id)
        REFERENCES contour.sources (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id)
);
CREATE INDEX origin_grant_scope ON contour.origin_observer_grants
    (tenant_id,lifecycle_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id);
CREATE TABLE contour.origin_terminal_events (
    tenant_id uuid NOT NULL, event_kind text NOT NULL,
    lifecycle_id uuid, credential_id uuid, grant_id uuid,
    event_at timestamptz NOT NULL CHECK (isfinite(event_at)),
    CHECK ((event_kind='lifecycle_closed' AND lifecycle_id IS NOT NULL AND credential_id IS NULL AND grant_id IS NULL)
        OR (event_kind='credential_revoked' AND lifecycle_id IS NULL AND credential_id IS NOT NULL AND grant_id IS NULL)
        OR (event_kind='grant_revoked' AND lifecycle_id IS NULL AND credential_id IS NULL AND grant_id IS NOT NULL)),
    FOREIGN KEY (tenant_id,lifecycle_id) REFERENCES contour.origin_lifecycles,
    FOREIGN KEY (tenant_id,credential_id) REFERENCES contour.origin_credentials,
    FOREIGN KEY (tenant_id,grant_id) REFERENCES contour.origin_observer_grants
);
CREATE UNIQUE INDEX origin_close_once ON contour.origin_terminal_events(tenant_id,lifecycle_id) WHERE event_kind='lifecycle_closed';
CREATE UNIQUE INDEX origin_credential_revoke_once ON contour.origin_terminal_events(tenant_id,credential_id) WHERE event_kind='credential_revoked';
CREATE UNIQUE INDEX origin_grant_revoke_once ON contour.origin_terminal_events(tenant_id,grant_id) WHERE event_kind='grant_revoked';

DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'] LOOP
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',relation);
        EXECUTE pg_catalog.format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',relation);
        EXECUTE pg_catalog.format('CREATE POLICY origin_owner_scope ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',relation);
        EXECUTE pg_catalog.format('CREATE POLICY origin_admin_read ON contour.%I FOR SELECT TO contour_admin USING (tenant_id=contour.tenant_context())',relation);
        EXECUTE pg_catalog.format('REVOKE ALL ON contour.%I FROM PUBLIC, contour_runtime',relation);
        EXECUTE pg_catalog.format('GRANT SELECT ON contour.%I TO contour_admin',relation);
        EXECUTE pg_catalog.format('CREATE TRIGGER origin_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',relation);
        EXECUTE pg_catalog.format('CREATE TRIGGER origin_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',relation);
    END LOOP;
END $$;
-- Narrow SELECT policies for the function owner, whose RLS is also forced.
CREATE POLICY origin_owner_instance_read ON contour.workload_instances FOR SELECT TO contour_owner
    USING (tenant_id=contour.tenant_context());
CREATE POLICY origin_owner_source_read ON contour.sources FOR SELECT TO contour_owner
    USING (tenant_id=contour.tenant_context());

-- Two-int advisory namespaces are disjoint from legacy bigint collector locks.
-- A held-lock guard is defense in depth, not proof of a fresh snapshot.
CREATE FUNCTION contour.origin_lock_held(namespace integer, identifier integer) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks l
        WHERE l.pid=pg_catalog.pg_backend_pid() AND l.locktype='advisory' AND l.granted
          AND l.mode='ExclusiveLock' AND l.objsubid=2
          AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
          AND l.classid::bigint=(namespace::bigint & 4294967295)
          AND l.objid::bigint=(identifier::bigint & 4294967295))
$$;
CREATE FUNCTION contour.origin_collector_lock_held(tenant uuid, collector uuid) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
    SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_locks l
        WHERE l.pid=pg_catalog.pg_backend_pid() AND l.locktype='advisory' AND l.granted
          AND l.mode='ExclusiveLock' AND l.objsubid=1
          AND l.database=(SELECT oid FROM pg_catalog.pg_database WHERE datname=pg_catalog.current_database())
          AND l.classid::bigint=((contour.collector_lock_key(tenant,collector) >> 32) & 4294967295)
          AND l.objid::bigint=(contour.collector_lock_key(tenant,collector) & 4294967295))
$$;
CREATE FUNCTION contour.begin_origin_operation(tenant uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'origin operation requires read committed' USING ERRCODE='25001';
    END IF;
    IF tenant IS NULL OR tenant IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'origin context mismatch' USING ERRCODE='42501';
    END IF;
    -- Conservative: reject any pre-held advisory lock, including a session lock.
    -- This avoids C-first composition and permits only one operation per transaction.
    IF EXISTS (SELECT 1 FROM pg_catalog.pg_locks l WHERE l.pid=pg_catalog.pg_backend_pid()
               AND l.locktype='advisory' AND l.granted) THEN
        RAISE EXCEPTION 'origin operation requires no prior advisory lock' USING ERRCODE='40001';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(1330792270,pg_catalog.hashtext(tenant::text)) THEN
        RAISE EXCEPTION 'origin gate busy' USING ERRCODE='40001';
    END IF;
END $$;
CREATE FUNCTION contour.lock_origin_credential(leaf bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF leaf IS NULL OR pg_catalog.octet_length(leaf) <> 32 THEN
        RAISE EXCEPTION 'invalid credential' USING ERRCODE='23514';
    END IF;
    IF NOT pg_catalog.pg_try_advisory_xact_lock(1330792271,pg_catalog.hashtext(pg_catalog.encode(leaf,'hex'))) THEN
        RAISE EXCEPTION 'credential gate busy' USING ERRCODE='40001';
    END IF;
END $$;
CREATE FUNCTION contour.lock_origin_collector(tenant uuid, collector uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF collector IS NULL OR NOT pg_catalog.pg_try_advisory_xact_lock(contour.collector_lock_key(tenant,collector)) THEN
        RAISE EXCEPTION 'collector gate busy' USING ERRCODE='40001';
    END IF;
END $$;
CREATE FUNCTION contour.require_origin_locks(tenant uuid, collector uuid DEFAULT NULL, leaf bytea DEFAULT NULL) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
BEGIN
    IF pg_catalog.current_setting('transaction_isolation') <> 'read committed'
        OR tenant IS NULL OR tenant IS DISTINCT FROM contour.tenant_context()
        OR NOT contour.origin_lock_held(1330792270,pg_catalog.hashtext(tenant::text)) THEN
        RAISE EXCEPTION 'origin gate required' USING ERRCODE='42501';
    END IF;
    IF collector IS NOT NULL AND NOT contour.origin_collector_lock_held(tenant,collector) THEN
        RAISE EXCEPTION 'collector gate required' USING ERRCODE='42501';
    END IF;
    IF leaf IS NOT NULL AND (pg_catalog.octet_length(leaf) <> 32 OR NOT contour.origin_lock_held(1330792271,pg_catalog.hashtext(pg_catalog.encode(leaf,'hex')))) THEN
        RAISE EXCEPTION 'credential gate required' USING ERRCODE='42501';
    END IF;
END $$;
-- Private, argument-free trusted database clock; callers cannot supply time.
CREATE FUNCTION contour.origin_server_time() RETURNS timestamptz
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
    SELECT pg_catalog.clock_timestamp()
$$;
-- Every origin mutation checks all already-committed lifecycle history after
-- holding the tenant gate. A backwards clock step fails rather than fabricating
-- chronology. The indexes on lifecycle/target keys bound the lookup scope.
CREATE FUNCTION contour.origin_history_highwater(tenant uuid, lifecycle uuid) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE highwater timestamptz;
BEGIN
    PERFORM contour.require_origin_locks(tenant,NULL,NULL);
    SELECT max(m.at_time) INTO highwater FROM (
        SELECT l.enrolled_at AS at_time FROM contour.origin_lifecycles l
          WHERE l.tenant_id=tenant AND l.lifecycle_id=lifecycle
        UNION ALL
        SELECT c.enrolled_at FROM contour.origin_credentials c
          WHERE c.tenant_id=tenant AND c.lifecycle_id=lifecycle
        UNION ALL
        SELECT g.granted_at FROM contour.origin_observer_grants g
          WHERE g.tenant_id=tenant AND g.lifecycle_id=lifecycle
        UNION ALL
        SELECT e.event_at FROM contour.origin_terminal_events e
          WHERE e.tenant_id=tenant AND e.lifecycle_id=lifecycle AND e.event_kind='lifecycle_closed'
        UNION ALL
        SELECT e.event_at FROM contour.origin_credentials c JOIN contour.origin_terminal_events e
          ON e.tenant_id=c.tenant_id AND e.credential_id=c.credential_id AND e.event_kind='credential_revoked'
          WHERE c.tenant_id=tenant AND c.lifecycle_id=lifecycle
        UNION ALL
        SELECT e.event_at FROM contour.origin_observer_grants g JOIN contour.origin_terminal_events e
          ON e.tenant_id=g.tenant_id AND e.grant_id=g.grant_id AND e.event_kind='grant_revoked'
          WHERE g.tenant_id=tenant AND g.lifecycle_id=lifecycle
    ) m;
    RETURN highwater;
END $$;
CREATE FUNCTION contour.guard_origin_insert() RETURNS trigger
LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
DECLARE collector uuid;
BEGIN
    IF TG_TABLE_NAME='origin_credentials' THEN
        PERFORM contour.require_origin_locks(NEW.tenant_id,NULL,NEW.leaf_sha256);
    ELSIF TG_TABLE_NAME='origin_observer_grants' THEN
        PERFORM contour.require_origin_locks(NEW.tenant_id,NEW.collector_id,NULL);
    ELSIF TG_TABLE_NAME='origin_terminal_events' THEN
        IF NEW.event_kind='grant_revoked' THEN
            SELECT g.collector_id INTO collector FROM contour.origin_observer_grants g
              WHERE g.tenant_id=NEW.tenant_id AND g.grant_id=NEW.grant_id;
            IF collector IS NULL THEN RAISE EXCEPTION 'grant unavailable' USING ERRCODE='23514'; END IF;
            PERFORM contour.require_origin_locks(NEW.tenant_id,collector,NULL);
        ELSE
            PERFORM contour.require_origin_locks(NEW.tenant_id,NULL,NULL);
        END IF;
    ELSIF TG_TABLE_NAME='origin_lifecycles' THEN
        PERFORM contour.require_origin_locks(NEW.tenant_id,NULL,NULL);
    ELSE
        RAISE EXCEPTION 'unexpected origin registry table' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['origin_lifecycles','origin_credentials','origin_observer_grants','origin_terminal_events'] LOOP
        EXECUTE pg_catalog.format('CREATE TRIGGER origin_insert_guard BEFORE INSERT ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.guard_origin_insert()',relation);
    END LOOP;
END $$;

-- Entrypoints are restricted to trusted provisioners. Caller assertions are not
-- SQL-authenticated platform evidence. Later admission must independently recheck.
CREATE FUNCTION contour.enroll_origin(tenant uuid, lifecycle uuid, project uuid, service uuid,
    environment uuid, deployment uuid, instance uuid, kind text, evidence bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE at_time timestamptz;
BEGIN
    PERFORM contour.begin_origin_operation(tenant);
    IF kind IS DISTINCT FROM 'trusted_platform_v1' OR pg_catalog.octet_length(evidence) IS DISTINCT FROM 32 THEN
        RAISE EXCEPTION 'invalid origin evidence' USING ERRCODE='23514';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM contour.workload_instances i WHERE i.tenant_id=tenant
        AND i.instance_id=instance AND i.project_id=project AND i.service_id=service
        AND i.environment_id=environment AND i.deployment_id=deployment) THEN
        RAISE EXCEPTION 'origin instance unavailable' USING ERRCODE='23514';
    END IF;
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) THEN RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514'; END IF;
    INSERT INTO contour.origin_lifecycles VALUES (tenant,lifecycle,project,service,environment,deployment,instance,kind,evidence,at_time);
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'origin identity unavailable' USING ERRCODE='23505';
END $$;
CREATE FUNCTION contour.enroll_origin_credential(tenant uuid, credential uuid, lifecycle uuid, leaf bytea) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE started timestamptz; at_time timestamptz;
BEGIN
    PERFORM contour.begin_origin_operation(tenant);
    PERFORM contour.lock_origin_credential(leaf);
    SELECT l.enrolled_at INTO started FROM contour.origin_lifecycles l WHERE l.tenant_id=tenant AND l.lifecycle_id=lifecycle
      AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant AND e.lifecycle_id=lifecycle AND e.event_kind='lifecycle_closed');
    IF started IS NULL THEN RAISE EXCEPTION 'origin unavailable' USING ERRCODE='23514'; END IF;
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time < started OR at_time < contour.origin_history_highwater(tenant,lifecycle) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_credentials VALUES (tenant,credential,lifecycle,leaf,at_time);
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'credential unavailable' USING ERRCODE='23505';
END $$;
CREATE FUNCTION contour.grant_origin_observer(tenant uuid, grant_id uuid, lifecycle uuid, source uuid,
    collector uuid, project uuid, service uuid, environment uuid, deployment uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE started timestamptz; at_time timestamptz;
BEGIN
    PERFORM contour.begin_origin_operation(tenant);
    PERFORM contour.lock_origin_collector(tenant,collector);
    SELECT l.enrolled_at INTO started FROM contour.origin_lifecycles l WHERE l.tenant_id=tenant AND l.lifecycle_id=lifecycle
      AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant AND e.lifecycle_id=lifecycle AND e.event_kind='lifecycle_closed');
    IF started IS NULL OR NOT EXISTS (SELECT 1 FROM contour.sources s WHERE s.tenant_id=tenant
       AND s.source_id=source AND s.collector_id=collector AND s.project_id=project AND s.service_id=service
       AND s.environment_id=environment AND s.deployment_id=deployment) THEN
        RAISE EXCEPTION 'origin or observer unavailable' USING ERRCODE='23514';
    END IF;
    IF EXISTS (SELECT 1 FROM contour.origin_observer_grants g WHERE g.tenant_id=tenant AND g.lifecycle_id=lifecycle
       AND g.source_id=source AND g.collector_id=collector AND g.project_id=project AND g.service_id=service
       AND g.environment_id=environment AND g.deployment_id=deployment
       AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events e WHERE e.tenant_id=tenant AND e.grant_id=g.grant_id AND e.event_kind='grant_revoked')) THEN
        RAISE EXCEPTION 'active grant exists' USING ERRCODE='23505';
    END IF;
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time < started OR at_time < contour.origin_history_highwater(tenant,lifecycle) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_observer_grants VALUES (tenant,grant_id,lifecycle,source,collector,project,service,environment,deployment,at_time);
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'grant unavailable' USING ERRCODE='23505';
END $$;
CREATE FUNCTION contour.end_origin(tenant uuid, kind text, target uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE started timestamptz; at_time timestamptz; collector uuid; lifecycle_key uuid;
BEGIN
    PERFORM contour.begin_origin_operation(tenant);
    IF kind='lifecycle_closed' THEN
        lifecycle_key := target;
        SELECT l.enrolled_at INTO started FROM contour.origin_lifecycles l WHERE l.tenant_id=tenant AND l.lifecycle_id=target;
    ELSIF kind='credential_revoked' THEN
        SELECT c.enrolled_at,c.lifecycle_id INTO started,lifecycle_key FROM contour.origin_credentials c WHERE c.tenant_id=tenant AND c.credential_id=target;
    ELSIF kind='grant_revoked' THEN
        SELECT g.collector_id INTO collector FROM contour.origin_observer_grants g WHERE g.tenant_id=tenant AND g.grant_id=target;
        IF collector IS NULL THEN RAISE EXCEPTION 'target unavailable' USING ERRCODE='23514'; END IF;
        PERFORM contour.lock_origin_collector(tenant,collector);
        SELECT g.granted_at,g.lifecycle_id INTO started,lifecycle_key FROM contour.origin_observer_grants g WHERE g.tenant_id=tenant AND g.grant_id=target;
    ELSE
        RAISE EXCEPTION 'invalid terminal event' USING ERRCODE='23514';
    END IF;
    IF started IS NULL THEN RAISE EXCEPTION 'target unavailable' USING ERRCODE='23514'; END IF;
    at_time := contour.origin_server_time();
    IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time < started OR at_time < contour.origin_history_highwater(tenant,lifecycle_key) THEN
        RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514';
    END IF;
    INSERT INTO contour.origin_terminal_events VALUES (tenant,kind,
        CASE WHEN kind='lifecycle_closed' THEN target END,
        CASE WHEN kind='credential_revoked' THEN target END,
        CASE WHEN kind='grant_revoked' THEN target END,at_time);
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'terminal event already recorded' USING ERRCODE='23505';
END $$;
REVOKE ALL ON FUNCTION contour.origin_lock_held(integer,integer), contour.origin_collector_lock_held(uuid,uuid),
    contour.begin_origin_operation(uuid), contour.lock_origin_credential(bytea), contour.lock_origin_collector(uuid,uuid),
    contour.require_origin_locks(uuid,uuid,bytea), contour.origin_server_time(), contour.origin_history_highwater(uuid,uuid), contour.guard_origin_insert(),
    contour.enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea),
    contour.enroll_origin_credential(uuid,uuid,uuid,bytea),
    contour.grant_origin_observer(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid),
    contour.end_origin(uuid,text,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION contour.enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea),
    contour.enroll_origin_credential(uuid,uuid,uuid,bytea),
    contour.grant_origin_observer(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid),
    contour.end_origin(uuid,text,uuid) TO contour_admin;
-- transaction failure probe
INSERT INTO contour.schema_migrations(version) VALUES (15);
COMMIT;
