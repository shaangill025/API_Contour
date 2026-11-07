-- Dormant immutable public-key binding; not proof of private-key possession,
-- TLS identity, launch permission, or authorization of profile 501 for wire use.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,22))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted marker migration required' USING ERRCODE='42501'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.causal_generation_claims ADD CONSTRAINT causal_generation_exact_unique UNIQUE (tenant_id,runtime_id,epoch,nonce,generation);
CREATE TABLE contour.causal_marker_bindings (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, epoch numeric NOT NULL,
 nonce uuid NOT NULL, generation bytea NOT NULL, product_credential_id uuid NOT NULL,
 product_leaf_sha256 bytea NOT NULL CHECK (octet_length(product_leaf_sha256)=32),
 marker_public_key bytea NOT NULL CHECK (octet_length(marker_public_key)=32),
 lifecycle_id uuid NOT NULL, instance_id uuid NOT NULL, profile_id uuid NOT NULL,
 artifact_sha256 bytea NOT NULL CHECK (octet_length(artifact_sha256)=32),
 bound_at timestamptz NOT NULL CHECK (isfinite(bound_at)),
 PRIMARY KEY (tenant_id,runtime_id,epoch),
 FOREIGN KEY (tenant_id,runtime_id,epoch,nonce,generation) REFERENCES contour.causal_generation_claims(tenant_id,runtime_id,epoch,nonce,generation),
 FOREIGN KEY (tenant_id,product_credential_id) REFERENCES contour.origin_credentials(tenant_id,credential_id)
);
ALTER TABLE contour.causal_marker_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_marker_bindings FORCE ROW LEVEL SECURITY;
CREATE POLICY causal_marker_owner ON contour.causal_marker_bindings TO contour_owner
 USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.causal_marker_bindings FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;
CREATE TRIGGER causal_marker_immutable BEFORE UPDATE OR DELETE ON contour.causal_marker_bindings FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_marker_no_truncate BEFORE TRUNCATE ON contour.causal_marker_bindings FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();

-- CMK1, UUIDs in network order, unsigned epoch as exactly 20 ASCII decimal
-- digits, raw fixed-width bytes, and PostgreSQL's 8-byte timestamptz_send.
-- The encoded row is exactly 272 bytes. This is a logical quota charge, not
-- a claim about the physical table size or an external serialization API.
CREATE FUNCTION contour.causal_marker_canonical(x contour.causal_marker_bindings) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path=pg_catalog AS $$
 SELECT convert_to('CMK1','UTF8') || uuid_send(x.tenant_id) || uuid_send(x.runtime_id)
 || convert_to(lpad(trunc(x.epoch)::text,20,'0'),'UTF8') || uuid_send(x.nonce)
 || x.generation || uuid_send(x.product_credential_id) || x.product_leaf_sha256
 || x.marker_public_key || uuid_send(x.lifecycle_id) || uuid_send(x.instance_id)
 || uuid_send(x.profile_id) || x.artifact_sha256 || timestamptz_send(x.bound_at)
$$;
REVOKE ALL ON FUNCTION contour.causal_marker_canonical(contour.causal_marker_bindings) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;

CREATE FUNCTION contour.causal_marker_product_current(t uuid, b contour.causal_runtime_bindings, credential uuid, leaf bytea, at_time timestamptz) RETURNS boolean
LANGUAGE plpgsql VOLATILE SET search_path=pg_catalog AS $$
BEGIN
 PERFORM contour.require_origin_locks(t,b.collector_id,leaf);
 RETURN coalesce(EXISTS (
  SELECT 1 FROM contour.origin_credentials c JOIN contour.origin_lifecycles l ON (l.tenant_id,l.lifecycle_id)=(c.tenant_id,c.lifecycle_id)
  WHERE c.tenant_id=t AND c.credential_id=credential AND c.lifecycle_id=b.lifecycle_id AND l.instance_id=b.instance_id
    AND c.leaf_sha256=leaf AND c.enrolled_at<=at_time AND l.enrolled_at<=at_time
    AND at_time>=contour.origin_history_highwater(t,b.lifecycle_id)
    AND EXISTS (SELECT 1 FROM contour.causal_leaf_reservations r WHERE r.leaf_sha256=leaf AND r.leaf_class='product')
    AND NOT EXISTS (SELECT 1 FROM contour.origin_terminal_events z WHERE z.tenant_id=t AND ((z.credential_id=credential AND z.event_kind='credential_revoked') OR (z.lifecycle_id=b.lifecycle_id AND z.event_kind='lifecycle_closed')))
 ),false);
END $$;
REVOKE ALL ON FUNCTION contour.causal_marker_product_current(uuid,contour.causal_runtime_bindings,uuid,bytea,timestamptz) FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;

CREATE FUNCTION contour.bind_causal_marker_key(t uuid, runtime uuid, ep numeric, n uuid, g bytea, credential uuid, leaf bytea, marker bytea) RETURNS timestamptz
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE b contour.causal_runtime_bindings; checked_b contour.causal_runtime_bindings; c contour.origin_credentials; checked_c contour.origin_credentials;
 s contour.causal_sessions; old contour.causal_marker_bindings; fresh contour.causal_marker_bindings;
 lock_leaf bytea; now_at timestamptz; final_at timestamptz; used bigint;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 SELECT * INTO b FROM contour.causal_runtime_bindings x WHERE x.tenant_id=t AND x.runtime_id=runtime;
 IF NOT FOUND THEN RAISE EXCEPTION 'marker authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO c FROM contour.origin_credentials x WHERE x.tenant_id=t AND x.credential_id=credential;
 IF NOT FOUND OR leaf IS NULL OR c.leaf_sha256 IS DISTINCT FROM leaf OR leaf=b.export_leaf_sha256
 OR marker IS NULL OR octet_length(marker)<>32 OR g IS NULL OR octet_length(g)<>32 OR n IS NULL
 THEN RAISE EXCEPTION 'marker authority unavailable' USING ERRCODE='23514'; END IF;
 -- Advisory locks use signed hashtext keys. Deduplicate collisions, not leaves.
 FOR lock_leaf IN SELECT DISTINCT ON (key) item FROM
  (SELECT item,hashtext(encode(item,'hex')) AS key FROM (VALUES (leaf),(b.export_leaf_sha256)) AS leaves(item)) AS keys
  ORDER BY key,item
 LOOP PERFORM contour.lock_origin_credential(lock_leaf); END LOOP;
 PERFORM contour.lock_origin_collector(t,b.collector_id);
 SELECT * INTO checked_b FROM contour.causal_runtime_bindings x WHERE x.tenant_id=t AND x.runtime_id=runtime;
 SELECT * INTO checked_c FROM contour.origin_credentials x WHERE x.tenant_id=t AND x.credential_id=credential;
 IF checked_b IS DISTINCT FROM b OR checked_c IS DISTINCT FROM c THEN RAISE EXCEPTION 'marker authority changed' USING ERRCODE='23514'; END IF;
 SELECT * INTO s FROM contour.causal_sessions x WHERE x.tenant_id=t AND x.runtime_id=runtime AND x.epoch=ep;
 now_at:=clock_timestamp();
 IF NOT FOUND OR s.nonce IS DISTINCT FROM n OR (s.claim).export_leaf IS DISTINCT FROM b.export_leaf_sha256
 OR NOT contour.causal_session_locked(s.claim,ep,now_at) OR NOT contour.causal_marker_product_current(t,b,credential,leaf,now_at)
 OR NOT EXISTS (SELECT 1 FROM contour.causal_generation_claims x WHERE (x.tenant_id,x.runtime_id,x.epoch,x.nonce,x.generation)=(t,runtime,ep,n,g))
 THEN RAISE EXCEPTION 'marker authority unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_marker_bindings x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,runtime,ep);
 IF FOUND THEN
  IF old.nonce IS DISTINCT FROM n OR old.generation IS DISTINCT FROM g OR old.product_credential_id IS DISTINCT FROM credential
   OR old.product_leaf_sha256 IS DISTINCT FROM leaf OR old.marker_public_key IS DISTINCT FROM marker
   OR old.lifecycle_id IS DISTINCT FROM b.lifecycle_id OR old.instance_id IS DISTINCT FROM b.instance_id
   OR old.profile_id IS DISTINCT FROM b.profile_id OR old.artifact_sha256 IS DISTINCT FROM b.artifact_sha256
  THEN RAISE EXCEPTION 'marker binding conflict' USING ERRCODE='23505'; END IF;
  fresh:=old;
 ELSE
  fresh:=(t,runtime,ep,n,g,credential,leaf,marker,b.lifecycle_id,b.instance_id,b.profile_id,b.artifact_sha256,now_at)::contour.causal_marker_bindings;
  IF octet_length(contour.causal_marker_canonical(fresh))<>272 THEN RAISE EXCEPTION 'invalid marker encoding' USING ERRCODE='23514'; END IF;
  INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
  SELECT x.used_bytes INTO STRICT used FROM contour.origin_logical_usage x WHERE x.tenant_id=t FOR UPDATE;
  IF 272>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
  INSERT INTO contour.causal_marker_bindings SELECT (fresh).*;
  UPDATE contour.origin_logical_usage SET used_bytes=used+272 WHERE tenant_id=t;
 END IF;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<now_at OR final_at<fresh.bound_at
 OR NOT contour.causal_session_locked(s.claim,ep,final_at) OR NOT contour.causal_marker_product_current(t,b,credential,leaf,final_at)
 THEN RAISE EXCEPTION 'marker authority unavailable at final check' USING ERRCODE='23514'; END IF;
 RETURN fresh.bound_at;
END $$;
REVOKE ALL ON FUNCTION contour.bind_causal_marker_key(uuid,uuid,numeric,uuid,bytea,uuid,bytea,bytea) FROM PUBLIC,contour_runtime,contour_causal_issuer;
GRANT EXECUTE ON FUNCTION contour.bind_causal_marker_key(uuid,uuid,numeric,uuid,bytea,uuid,bytea,bytea) TO contour_causal_provisioner;
INSERT INTO contour.schema_migrations(version) VALUES(23);
COMMIT;
