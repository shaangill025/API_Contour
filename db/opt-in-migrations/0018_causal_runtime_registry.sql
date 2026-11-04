-- Internal synthetic runtime registry only. This records operator assertions;
-- it does not attest artifacts, authorize sessions, or verify policy signatures.
-- Apply only after 1..17 by a trusted superuser; default migrations remain 1..14.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
    OR pg_catalog.current_setting('row_security') <> 'on'
    OR pg_catalog.current_setting('transaction_isolation') <> 'read committed'
 THEN RAISE EXCEPTION 'trusted runtime registry migration required' USING ERRCODE='42501'; END IF;
 IF (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
       IS DISTINCT FROM ARRAY(SELECT generate_series(1,17))
    OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_catalog.pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'runtime registry migration state unavailable' USING ERRCODE='42501'; END IF;
END $$;
-- Drain existing leaf enrollments and keep this lock until backfill and trigger
-- installation commit together. New enrollments cannot pass this boundary.
LOCK TABLE contour.origin_credentials IN ACCESS EXCLUSIVE MODE;
CREATE ROLE contour_causal_provisioner NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;

-- Anonymous global namespace: no tenant or lifecycle information is exposed.
CREATE TABLE contour.causal_leaf_reservations (
 leaf_sha256 bytea PRIMARY KEY CHECK (octet_length(leaf_sha256)=32),
 leaf_class text NOT NULL CHECK (leaf_class IN ('product','export'))
);
ALTER TABLE contour.causal_leaf_reservations ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_leaf_reservations FORCE ROW LEVEL SECURITY;
CREATE POLICY causal_leaf_owner ON contour.causal_leaf_reservations TO contour_owner USING (true) WITH CHECK (true);
REVOKE ALL ON contour.causal_leaf_reservations FROM PUBLIC,contour_runtime,contour_causal_provisioner;
CREATE TRIGGER causal_leaf_immutable BEFORE UPDATE OR DELETE ON contour.causal_leaf_reservations FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_leaf_no_truncate BEFORE TRUNCATE ON contour.causal_leaf_reservations FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();

CREATE TABLE contour.causal_runtime_profiles (
 tenant_id uuid NOT NULL REFERENCES contour.tenants(tenant_id),
 profile_id uuid NOT NULL CHECK (profile_id='00000000-0000-4000-8000-000000000501'::uuid),
 artifact_sha256 bytea NOT NULL CHECK (artifact_sha256=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')),
 point_kind text NOT NULL CHECK (point_kind='node_in'), method text NOT NULL CHECK (method='POST'),
 route text NOT NULL CHECK (route='/run'), technique text NOT NULL CHECK (technique='runtime'),
 parser_profile text NOT NULL CHECK (parser_profile='http_json_v1'),
 registered_at timestamptz NOT NULL CHECK (isfinite(registered_at)),
 PRIMARY KEY (tenant_id,profile_id)
);
CREATE TABLE contour.causal_runtime_bindings (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, collector_id uuid NOT NULL, source_id uuid NOT NULL,
 project_id uuid NOT NULL, service_id uuid NOT NULL, environment_id uuid NOT NULL, deployment_id uuid NOT NULL,
 instance_id uuid NOT NULL, lifecycle_id uuid NOT NULL, profile_id uuid NOT NULL CHECK (profile_id='00000000-0000-4000-8000-000000000501'::uuid),
 artifact_sha256 bytea NOT NULL CHECK (artifact_sha256=decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex')),
 export_leaf_sha256 bytea NOT NULL CHECK (octet_length(export_leaf_sha256)=32),
 enrolled_at timestamptz NOT NULL CHECK (isfinite(enrolled_at)),
 PRIMARY KEY (tenant_id,runtime_id), UNIQUE (export_leaf_sha256), UNIQUE (tenant_id,lifecycle_id),
 FOREIGN KEY (tenant_id,profile_id) REFERENCES contour.causal_runtime_profiles,
 FOREIGN KEY (tenant_id,lifecycle_id) REFERENCES contour.origin_lifecycles,
 FOREIGN KEY (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id) REFERENCES contour.sources (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id),
 FOREIGN KEY (tenant_id,project_id,service_id,environment_id,deployment_id,instance_id) REFERENCES contour.workload_instances (tenant_id,project_id,service_id,environment_id,deployment_id,instance_id)
);
CREATE TABLE contour.causal_runtime_terminal_events (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, event_kind text NOT NULL CHECK (event_kind IN ('runtime_closed','export_revoked')),
 event_at timestamptz NOT NULL CHECK (isfinite(event_at)),
 PRIMARY KEY (tenant_id,runtime_id,event_kind),
 FOREIGN KEY (tenant_id,runtime_id) REFERENCES contour.causal_runtime_bindings
);
DO $$ DECLARE r text; BEGIN
 FOREACH r IN ARRAY ARRAY['causal_runtime_profiles','causal_runtime_bindings','causal_runtime_terminal_events'] LOOP
  EXECUTE pg_catalog.format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',r);
  EXECUTE pg_catalog.format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',r);
  EXECUTE pg_catalog.format('CREATE POLICY causal_owner_scope ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',r);
  EXECUTE pg_catalog.format('REVOKE ALL ON contour.%I FROM PUBLIC,contour_runtime,contour_causal_provisioner',r);
  EXECUTE pg_catalog.format('CREATE TRIGGER causal_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',r);
  EXECUTE pg_catalog.format('CREATE TRIGGER causal_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',r);
 END LOOP;
END $$;

-- Product-origin inserts still use migration15's private Q→leaf protocol. This
-- trigger is additive; it has no PUBLIC or caller-accessible entrypoint.
CREATE FUNCTION contour.reserve_product_leaf() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 PERFORM contour.require_origin_locks(NEW.tenant_id,NULL,NEW.leaf_sha256);
 INSERT INTO contour.causal_leaf_reservations VALUES (NEW.leaf_sha256,'product');
 RETURN NEW;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'leaf unavailable' USING ERRCODE='23505';
END $$;
REVOKE ALL ON FUNCTION contour.reserve_product_leaf() FROM PUBLIC,contour_runtime,contour_causal_provisioner;

-- Owner reads the exact fixed legacy authority only through this new boolean
-- capability. Its definer (admin) already has tenant-scoped legacy read access.
CREATE FUNCTION contour.causal_legacy_authorized(t uuid,c uuid,src uuid,p uuid,s uuid,e uuid,d uuid,i uuid) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
BEGIN
 IF t IS NULL OR t IS DISTINCT FROM contour.tenant_context() OR c IS NULL OR src IS NULL OR p IS NULL OR s IS NULL OR e IS NULL OR d IS NULL OR i IS NULL THEN RETURN false; END IF;
 RETURN EXISTS (SELECT 1 FROM contour.sources x
  JOIN contour.source_instance_bindings b USING (tenant_id,source_id,collector_id,project_id,service_id,environment_id,deployment_id)
  JOIN contour.workload_assignments w USING (tenant_id,collector_id,project_id,service_id,environment_id,deployment_id)
  JOIN contour.source_authorization sa USING (tenant_id,source_id,collector_id)
  JOIN contour.collector_authorization ca USING (tenant_id,collector_id)
  JOIN contour.policy_revisions pr ON pr.tenant_id=ca.tenant_id AND pr.collector_id=ca.collector_id AND pr.revision=ca.active_revision
  WHERE x.tenant_id=t AND x.collector_id=c AND x.source_id=src AND x.project_id=p AND x.service_id=s
   AND x.environment_id=e AND x.deployment_id=d AND x.binding_mode='instance' AND b.instance_id=i
   AND sa.technique='runtime' AND sa.parser_profiles=ARRAY['http_json_v1']
   AND ca.enabled AND ca.revoked_at IS NULL AND ca.active_revision IS NOT NULL);
END $$;
RESET ROLE;
ALTER FUNCTION contour.causal_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) OWNER TO contour_admin;
REVOKE ALL ON FUNCTION contour.causal_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC,contour_runtime,contour_causal_provisioner;
GRANT EXECUTE ON FUNCTION contour.causal_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) TO contour_owner;
-- Backfill executes as the previously verified superuser, never SET ROLE owner:
-- FORCE RLS remains enabled, and the query sees every preexisting tenant.
INSERT INTO contour.causal_leaf_reservations SELECT leaf_sha256,'product' FROM contour.origin_credentials;
DO $$ BEGIN
 IF (SELECT count(*) FROM contour.causal_leaf_reservations) <> (SELECT count(*) FROM contour.origin_credentials)
 OR EXISTS (SELECT 1 FROM contour.origin_credentials c LEFT JOIN contour.causal_leaf_reservations r USING(leaf_sha256) WHERE r.leaf_sha256 IS NULL OR r.leaf_class<>'product')
 THEN RAISE EXCEPTION 'product leaf backfill mismatch'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
CREATE TRIGGER causal_reserve_product_leaf BEFORE INSERT ON contour.origin_credentials FOR EACH ROW EXECUTE FUNCTION contour.reserve_product_leaf();

CREATE FUNCTION contour.register_causal_profile(t uuid,profile uuid,artifact bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_profiles;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF profile IS DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid OR artifact IS DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex') THEN RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_profiles WHERE tenant_id=t AND profile_id=profile;
 IF FOUND THEN
  IF existing.artifact_sha256=artifact AND existing.point_kind='node_in' AND existing.method='POST' AND existing.route='/run'
     AND existing.technique='runtime' AND existing.parser_profile='http_json_v1' THEN RETURN profile; END IF;
  RAISE EXCEPTION 'profile unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_runtime_profiles VALUES (t,profile,artifact,'node_in','POST','/run','runtime','http_json_v1',pg_catalog.clock_timestamp());
 RETURN profile;
END $$;

CREATE FUNCTION contour.enroll_causal_runtime(t uuid,runtime uuid,c uuid,src uuid,p uuid,s uuid,e uuid,d uuid,i uuid,lifecycle uuid,profile uuid,artifact bytea,leaf bytea) RETURNS uuid
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE existing contour.causal_runtime_bindings; at_time timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 PERFORM contour.lock_origin_credential(leaf);
 PERFORM contour.lock_origin_collector(t,c);
 IF runtime IS NULL OR lifecycle IS NULL OR profile IS DISTINCT FROM '00000000-0000-4000-8000-000000000501'::uuid OR artifact IS DISTINCT FROM decode('b0bcc91455463d2dd48c438292abe1063ed7d3430459ead5ec48423c9ba1b510','hex') THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 IF NOT contour.causal_legacy_authorized(t,c,src,p,s,e,d,i) OR NOT EXISTS (
  SELECT 1 FROM contour.causal_runtime_profiles x WHERE x.tenant_id=t AND x.profile_id=profile AND x.artifact_sha256=artifact
   AND x.point_kind='node_in' AND x.method='POST' AND x.route='/run' AND x.technique='runtime' AND x.parser_profile='http_json_v1')
 OR NOT EXISTS (SELECT 1 FROM contour.origin_lifecycles l WHERE l.tenant_id=t AND l.lifecycle_id=lifecycle
   AND l.project_id=p AND l.service_id=s AND l.environment_id=e AND l.deployment_id=d AND l.instance_id=i
   AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.lifecycle_id=lifecycle AND z.event_kind='lifecycle_closed')
   AND EXISTS (SELECT 1 FROM contour.origin_credentials oc WHERE oc.tenant_id=t AND oc.lifecycle_id=lifecycle
     AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND z.credential_id=oc.credential_id AND z.event_kind='credential_revoked')))
 THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time<contour.origin_history_highwater(t,lifecycle) THEN RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514'; END IF;
 SELECT * INTO existing FROM contour.causal_runtime_bindings WHERE tenant_id=t AND runtime_id=runtime;
 IF FOUND THEN
  IF existing.collector_id=c AND existing.source_id=src AND existing.project_id=p AND existing.service_id=s AND existing.environment_id=e
    AND existing.deployment_id=d AND existing.instance_id=i AND existing.lifecycle_id=lifecycle AND existing.profile_id=profile
    AND existing.artifact_sha256=artifact AND existing.export_leaf_sha256=leaf AND existing.enrolled_at<=at_time
    AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations WHERE leaf_sha256=leaf AND leaf_class='export')
    AND NOT EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=t AND z.runtime_id=runtime)
  THEN RETURN runtime; END IF;
  RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
 END IF;
 INSERT INTO contour.causal_leaf_reservations VALUES (leaf,'export');
 INSERT INTO contour.causal_runtime_bindings VALUES (t,runtime,c,src,p,s,e,d,i,lifecycle,profile,artifact,leaf,at_time);
 RETURN runtime;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505';
END $$;

CREATE FUNCTION contour.end_causal_runtime(t uuid,runtime uuid,kind text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE r contour.causal_runtime_bindings; at_time timestamptz;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF kind NOT IN ('runtime_closed','export_revoked') OR kind IS NULL THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO r FROM contour.causal_runtime_bindings WHERE tenant_id=t AND runtime_id=runtime;
 IF NOT FOUND THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23514'; END IF;
 PERFORM contour.lock_origin_credential(r.export_leaf_sha256);
 PERFORM contour.lock_origin_collector(t,r.collector_id);
 IF EXISTS (SELECT 1 FROM contour.causal_runtime_terminal_events z WHERE z.tenant_id=t AND z.runtime_id=runtime) THEN RAISE EXCEPTION 'runtime unavailable' USING ERRCODE='23505'; END IF;
 at_time:=pg_catalog.clock_timestamp();
 IF at_time IS NULL OR NOT pg_catalog.isfinite(at_time) OR at_time<r.enrolled_at OR at_time<contour.origin_history_highwater(t,r.lifecycle_id) THEN RAISE EXCEPTION 'invalid clock' USING ERRCODE='23514'; END IF;
 INSERT INTO contour.causal_runtime_terminal_events VALUES (t,runtime,kind,at_time);
END $$;
REVOKE ALL ON FUNCTION contour.register_causal_profile(uuid,uuid,bytea),contour.enroll_causal_runtime(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bytea,bytea),contour.end_causal_runtime(uuid,uuid,text) FROM PUBLIC,contour_runtime;
GRANT USAGE ON SCHEMA contour TO contour_causal_provisioner;
GRANT EXECUTE ON FUNCTION contour.register_causal_profile(uuid,uuid,bytea),contour.enroll_causal_runtime(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid,bytea,bytea),contour.end_causal_runtime(uuid,uuid,text) TO contour_causal_provisioner;
INSERT INTO contour.schema_migrations(version) VALUES (18);
COMMIT;
