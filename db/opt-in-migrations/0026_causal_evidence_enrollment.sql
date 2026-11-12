-- Trusted issuer assertions only. SQL verifies neither signatures nor mTLS.
-- Issuer must independently verify policy signature, scope and exact authority;
-- ceil issued and floor expiry to microseconds as in migration 19. No receiver API.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,25))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted evidence migration required' USING ERRCODE='42501'; END IF;
END $$;
CREATE ROLE contour_causal_evidence_provisioner NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.causal_leaf_reservations DROP CONSTRAINT causal_leaf_reservations_leaf_class_check;
ALTER TABLE contour.causal_leaf_reservations ADD CONSTRAINT causal_leaf_reservations_leaf_class_check
 CHECK (leaf_class IN ('product','export','gateway_observer','gateway_backend','receiver_backend','receiver_evidence'));
CREATE TYPE contour.gateway_enrollment_claim AS (
 tenant_id uuid, gateway_id uuid, collector_id uuid, source_id uuid, project_id uuid, service_id uuid,
 environment_id uuid, deployment_id uuid, instance_id uuid, provision_nonce bytea,
 observer_leaf bytea, backend_client_leaf bytea, policy_revision numeric, policy_envelope bytea,
 policy_issued timestamptz, policy_expires timestamptz, ttl_microseconds bigint
);
CREATE TABLE contour.causal_gateway_enrollments (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, generation text NOT NULL CHECK (generation COLLATE "C" ~ '^[0-9a-f]{32}$'),
 claim contour.gateway_enrollment_claim NOT NULL, issued_at timestamptz NOT NULL CHECK(isfinite(issued_at)),
 expires_at timestamptz NOT NULL CHECK(isfinite(expires_at) AND expires_at>issued_at AND expires_at-issued_at<=interval '24 hours'),
 metadata bytea NOT NULL CHECK(octet_length(metadata) BETWEEN 1 AND 4096),
 charged_bytes bigint NOT NULL CHECK(charged_bytes=octet_length(metadata)+octet_length((claim).policy_envelope)+256),
 PRIMARY KEY(tenant_id,gateway_id,generation), UNIQUE(generation)
);
CREATE UNIQUE INDEX causal_gateway_nonce ON contour.causal_gateway_enrollments(tenant_id,gateway_id,((claim).provision_nonce));
CREATE TABLE contour.causal_gateway_terminal_reservations (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, generation text NOT NULL,
 charged_bytes integer NOT NULL CHECK(charged_bytes=1024),
 PRIMARY KEY(tenant_id,gateway_id,generation), FOREIGN KEY(tenant_id,gateway_id,generation) REFERENCES contour.causal_gateway_enrollments
);
CREATE TABLE contour.causal_gateway_terminals (
 tenant_id uuid NOT NULL, gateway_id uuid NOT NULL, generation text NOT NULL,
 reason text NOT NULL CHECK(reason IN ('expired','operator_revoked')), effective_at timestamptz NOT NULL CHECK(isfinite(effective_at)),
 canonical_body bytea NOT NULL CHECK(octet_length(canonical_body) BETWEEN 1 AND 768),
 PRIMARY KEY(tenant_id,gateway_id,generation), FOREIGN KEY(tenant_id,gateway_id,generation) REFERENCES contour.causal_gateway_terminal_reservations
);
DO $$ DECLARE n text; BEGIN
 FOREACH n IN ARRAY ARRAY['causal_gateway_enrollments','causal_gateway_terminal_reservations','causal_gateway_terminals'] LOOP
  EXECUTE format('ALTER TABLE contour.%I ENABLE ROW LEVEL SECURITY',n);
  EXECUTE format('ALTER TABLE contour.%I FORCE ROW LEVEL SECURITY',n);
  EXECUTE format('CREATE POLICY evidence_owner ON contour.%I TO contour_owner USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context())',n);
  EXECUTE format('REVOKE ALL ON contour.%I FROM PUBLIC,contour_runtime,contour_causal_evidence_provisioner',n);
  EXECUTE format('CREATE TRIGGER evidence_immutable BEFORE UPDATE OR DELETE ON contour.%I FOR EACH ROW EXECUTE FUNCTION contour.immutable_row()',n);
  EXECUTE format('CREATE TRIGGER evidence_no_truncate BEFORE TRUNCATE ON contour.%I FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row()',n);
 END LOOP;
END $$;

CREATE FUNCTION contour.gateway_legacy_authorized(t uuid,c uuid,src uuid,p uuid,s uuid,e uuid,d uuid,i uuid) RETURNS boolean
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
   AND sa.technique='gateway' AND sa.parser_profiles=ARRAY['http_json_v1']
   AND ca.enabled AND ca.revoked_at IS NULL AND ca.active_revision IS NOT NULL);
END $$;
RESET ROLE;
ALTER FUNCTION contour.gateway_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) OWNER TO contour_admin;
REVOKE ALL ON FUNCTION contour.gateway_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) FROM PUBLIC,contour_runtime,contour_causal_evidence_provisioner;
GRANT EXECUTE ON FUNCTION contour.gateway_legacy_authorized(uuid,uuid,uuid,uuid,uuid,uuid,uuid,uuid) TO contour_owner;
SET LOCAL ROLE contour_owner;

-- Metadata excludes policy bytes, which are charged separately and stored in the claim.
CREATE FUNCTION contour.gateway_enrollment_metadata(x contour.gateway_enrollment_claim, gen text, issued timestamptz, expires timestamptz) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object(
 'tenant_id',x.tenant_id,'gateway_id',x.gateway_id,'collector_id',x.collector_id,'source_id',x.source_id,
 'project_id',x.project_id,'service_id',x.service_id,'environment_id',x.environment_id,'deployment_id',x.deployment_id,'instance_id',x.instance_id,
 'provision_nonce',encode(x.provision_nonce,'hex'),'observer_leaf',encode(x.observer_leaf,'hex'),'backend_client_leaf',encode(x.backend_client_leaf,'hex'),
 'policy_revision',x.policy_revision::text,'policy_issued',to_char(x.policy_issued AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'policy_expires',to_char(x.policy_expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'ttl_microseconds',x.ttl_microseconds::text,'generation',gen,
 'issued_at',to_char(issued AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
 'expires_at',to_char(expires AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'))),'UTF8')
$$;
CREATE FUNCTION contour.gateway_terminal_body(t uuid,g uuid,gen text,at_time timestamptz,why text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to(contour.causal_json_canonical(jsonb_build_object('wire_version',1,'kind','gateway',
 'tenant_id',t,'gateway_id',g,'gateway_generation',gen,'runtime_id',NULL,'session_epoch',NULL,
 'effective_at',to_char(at_time AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),'reason',why)),'UTF8')
$$;
CREATE FUNCTION contour.gateway_claim_current(x contour.gateway_enrollment_claim,at_time timestamptz) RETURNS boolean
LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$
 SELECT coalesce(x.tenant_id=contour.tenant_context() AND isfinite(at_time)
  AND at_time>=x.policy_issued AND at_time<x.policy_expires
  AND contour.causal_policy_exact(x.tenant_id,x.collector_id,x.policy_revision,x.policy_envelope)
  AND contour.gateway_legacy_authorized(x.tenant_id,x.collector_id,x.source_id,x.project_id,x.service_id,x.environment_id,x.deployment_id,x.instance_id),false)
$$;

CREATE FUNCTION contour.enroll_causal_gateway(x contour.gateway_enrollment_claim)
RETURNS TABLE(generation text,issued_at timestamptz,expires_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old contour.causal_gateway_enrollments; leaf bytea; initial_at timestamptz; final_at timestamptz; floor_at timestamptz; used bigint; newgen text; until_at timestamptz; meta bytea; charge bigint; random_a text; random_b text;
BEGIN
 PERFORM contour.begin_origin_operation(x.tenant_id);
 IF x.gateway_id IS NULL OR x.collector_id IS NULL OR x.source_id IS NULL OR x.project_id IS NULL OR x.service_id IS NULL OR x.environment_id IS NULL OR x.deployment_id IS NULL OR x.instance_id IS NULL
 OR x.provision_nonce IS NULL OR octet_length(x.provision_nonce)<>32 OR x.observer_leaf IS NULL OR octet_length(x.observer_leaf)<>32 OR x.backend_client_leaf IS NULL OR octet_length(x.backend_client_leaf)<>32 OR x.observer_leaf=x.backend_client_leaf
 OR x.policy_revision IS NULL OR x.policy_revision<>trunc(x.policy_revision) OR x.policy_revision NOT BETWEEN 1 AND 18446744073709551615 OR x.policy_envelope IS NULL OR octet_length(x.policy_envelope) NOT BETWEEN 1 AND 1048576
 OR x.policy_issued IS NULL OR NOT isfinite(x.policy_issued) OR x.policy_expires IS NULL OR NOT isfinite(x.policy_expires) OR x.policy_issued < timestamptz '0001-01-01 00:00:00+00' OR x.policy_expires >= timestamptz '10000-01-01 00:00:00+00' OR x.policy_expires<=x.policy_issued OR x.ttl_microseconds IS NULL OR x.ttl_microseconds NOT BETWEEN 1 AND 86400000000
 THEN RAISE EXCEPTION 'gateway authority unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM (VALUES(x.observer_leaf),(x.backend_client_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(x.tenant_id,x.collector_id);
 PERFORM contour.ensure_origin_tenant_state(x.tenant_id);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=x.tenant_id FOR UPDATE;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(x.tenant_id,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT used_bytes INTO STRICT used FROM contour.origin_logical_usage WHERE tenant_id=x.tenant_id FOR UPDATE;
 initial_at:=clock_timestamp();
 IF initial_at IS NULL OR NOT isfinite(initial_at) OR initial_at < timestamptz '0001-01-01 00:00:00+00' OR initial_at >= timestamptz '10000-01-01 00:00:00+00' OR (floor_at IS NOT NULL AND initial_at<floor_at) OR NOT contour.gateway_claim_current(x,initial_at)
 THEN RAISE EXCEPTION 'gateway authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_gateway_enrollments e WHERE e.tenant_id=x.tenant_id AND e.gateway_id=x.gateway_id AND (e.claim).provision_nonce=x.provision_nonce;
 IF FOUND THEN
  IF old.claim IS DISTINCT FROM x OR initial_at>=old.expires_at OR EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(old.tenant_id,old.gateway_id,old.generation))
  THEN RAISE EXCEPTION 'gateway enrollment unavailable' USING ERRCODE='23505'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM contour.causal_gateway_enrollments e WHERE e.tenant_id=x.tenant_id AND e.gateway_id=x.gateway_id AND e.expires_at>initial_at AND NOT EXISTS(SELECT 1 FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(e.tenant_id,e.gateway_id,e.generation)))
  THEN RAISE EXCEPTION 'gateway enrollment unavailable' USING ERRCODE='23505'; END IF;
  -- Two UUIDv4 values contribute their 122 random bits each; discard both version and variant nibbles.
  random_a:=replace(gen_random_uuid()::text,'-',''); random_b:=replace(gen_random_uuid()::text,'-','');
  newgen:=substr(random_a,1,12)||substr(random_a,14,3)||substr(random_a,18,1)||substr(random_b,1,12)||substr(random_b,14,3)||substr(random_b,18,1);
  IF newgen COLLATE "C" !~ '^[0-9a-f]{32}$' OR octet_length(contour.gateway_terminal_body(x.tenant_id,x.gateway_id,newgen,initial_at,'operator_revoked'))>768
  THEN RAISE EXCEPTION 'gateway terminal encoding invalid' USING ERRCODE='23514'; END IF;
  until_at:=least(initial_at+x.ttl_microseconds*interval '1 microsecond',x.policy_expires);
  meta:=contour.gateway_enrollment_metadata(x,newgen,initial_at,until_at);
  charge:=octet_length(meta)+octet_length(x.policy_envelope)+256;
  IF 1024+charge>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
  INSERT INTO contour.causal_leaf_reservations VALUES(x.observer_leaf,'gateway_observer'),(x.backend_client_leaf,'gateway_backend');
  INSERT INTO contour.causal_gateway_enrollments VALUES(x.tenant_id,x.gateway_id,newgen,x,initial_at,until_at,meta,charge) RETURNING * INTO old;
  INSERT INTO contour.causal_gateway_terminal_reservations VALUES(x.tenant_id,x.gateway_id,newgen,1024);
  UPDATE contour.origin_logical_usage SET used_bytes=used+charge+1024 WHERE tenant_id=x.tenant_id;
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at) OR final_at>=old.expires_at OR NOT contour.gateway_claim_current(x,final_at)
 THEN RAISE EXCEPTION 'gateway authority unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=x.tenant_id;
 RETURN QUERY SELECT old.generation,old.issued_at,old.expires_at;
EXCEPTION WHEN unique_violation THEN RAISE EXCEPTION 'gateway enrollment unavailable' USING ERRCODE='23505';
END $$;

CREATE FUNCTION contour.close_causal_gateway(t uuid, gateway uuid, gen text, why text) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE old contour.causal_gateway_enrollments; checked contour.causal_gateway_enrollments; prior contour.causal_gateway_terminals; leaf bytea; initial_at timestamptz; final_at timestamptz; floor_at timestamptz; body bytea;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 IF gateway IS NULL OR gen IS NULL OR gen COLLATE "C" !~ '^[0-9a-f]{32}$' OR why IS NULL OR why NOT IN ('expired','operator_revoked')
 THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_gateway_enrollments e WHERE (e.tenant_id,e.gateway_id,e.generation)=(t,gateway,gen);
 IF NOT FOUND THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
 FOR leaf IN SELECT DISTINCT ON (k) v FROM (SELECT v,hashtext(encode(v,'hex')) k FROM (VALUES((old.claim).observer_leaf),((old.claim).backend_client_leaf)) leaves(v)) q ORDER BY k,v
 LOOP PERFORM contour.lock_origin_credential(leaf); END LOOP;
 PERFORM contour.lock_origin_collector(t,(old.claim).collector_id);
 PERFORM contour.ensure_origin_tenant_state(t);
 SELECT clock_floor INTO floor_at FROM contour.origin_tenant_state WHERE tenant_id=t FOR UPDATE;
 PERFORM 1 FROM contour.origin_logical_usage WHERE tenant_id=t AND used_bytes>=1024 FOR UPDATE;
 IF NOT FOUND THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO checked FROM contour.causal_gateway_enrollments e WHERE (e.tenant_id,e.gateway_id,e.generation)=(t,gateway,gen);
 initial_at:=clock_timestamp();
 IF checked IS DISTINCT FROM old OR initial_at IS NULL OR NOT isfinite(initial_at) OR initial_at < timestamptz '0001-01-01 00:00:00+00' OR initial_at >= timestamptz '10000-01-01 00:00:00+00' OR (floor_at IS NOT NULL AND initial_at<floor_at) OR (why='expired' AND initial_at<old.expires_at)
 OR NOT EXISTS(SELECT 1 FROM contour.causal_gateway_terminal_reservations r WHERE (r.tenant_id,r.gateway_id,r.generation,r.charged_bytes)=(t,gateway,gen,1024))
 THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO prior FROM contour.causal_gateway_terminals z WHERE (z.tenant_id,z.gateway_id,z.generation)=(t,gateway,gen);
 IF FOUND THEN
  IF prior.reason<>why OR prior.canonical_body IS DISTINCT FROM contour.gateway_terminal_body(t,gateway,gen,prior.effective_at,prior.reason) THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23505'; END IF;
 ELSE
  body:=contour.gateway_terminal_body(t,gateway,gen,initial_at,why);
  IF octet_length(body) NOT BETWEEN 1 AND 768 THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
  INSERT INTO contour.causal_gateway_terminals VALUES(t,gateway,gen,why,initial_at,body);
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<initial_at OR (floor_at IS NOT NULL AND final_at<floor_at)
 THEN RAISE EXCEPTION 'gateway closure unavailable' USING ERRCODE='23514'; END IF;
 UPDATE contour.origin_tenant_state SET clock_floor=final_at WHERE tenant_id=t;
END $$;

REVOKE ALL ON FUNCTION contour.gateway_enrollment_metadata(contour.gateway_enrollment_claim,text,timestamptz,timestamptz), contour.gateway_terminal_body(uuid,uuid,text,timestamptz,text), contour.gateway_claim_current(contour.gateway_enrollment_claim,timestamptz), contour.enroll_causal_gateway(contour.gateway_enrollment_claim), contour.close_causal_gateway(uuid,uuid,text,text) FROM PUBLIC,contour_runtime,contour_causal_evidence_provisioner;
GRANT USAGE ON SCHEMA contour TO contour_causal_evidence_provisioner;
REVOKE ALL ON TYPE contour.gateway_enrollment_claim FROM PUBLIC,contour_runtime;
GRANT USAGE ON TYPE contour.gateway_enrollment_claim TO contour_causal_evidence_provisioner;
GRANT EXECUTE ON FUNCTION contour.enroll_causal_gateway(contour.gateway_enrollment_claim),contour.close_causal_gateway(uuid,uuid,text,text) TO contour_causal_evidence_provisioner;
INSERT INTO contour.schema_migrations(version) VALUES(26);
COMMIT;
