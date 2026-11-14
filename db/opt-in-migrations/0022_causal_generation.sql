-- Opt-in immutable generation claim. Charge 92 logical bytes: domain/version
-- 4, tenant UUID 16, runtime UUID 16, epoch u64 8, nonce UUID 16, generation 32.
BEGIN;
DO $$ BEGIN
 IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname=current_user AND rolsuper)
 OR current_setting('row_security') <> 'on' OR current_setting('transaction_isolation') <> 'read committed'
 OR (SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations) IS DISTINCT FROM ARRAY(SELECT generate_series(1,21))
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_locks WHERE pid=pg_backend_pid() AND locktype='advisory' AND granted)
 THEN RAISE EXCEPTION 'trusted generation migration required' USING ERRCODE='42501'; END IF;
END $$;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.causal_sessions ADD CONSTRAINT causal_session_epoch_nonce_unique UNIQUE (tenant_id,runtime_id,epoch,nonce);
CREATE TABLE contour.causal_generation_claims (
 tenant_id uuid NOT NULL, runtime_id uuid NOT NULL, epoch numeric NOT NULL,
 nonce uuid NOT NULL, generation bytea NOT NULL CHECK (octet_length(generation)=32 AND generation<>decode(repeat('00',32),'hex')),
 PRIMARY KEY (tenant_id,runtime_id,epoch),
 FOREIGN KEY (tenant_id,runtime_id,epoch,nonce) REFERENCES contour.causal_sessions(tenant_id,runtime_id,epoch,nonce)
);
ALTER TABLE contour.causal_generation_claims ENABLE ROW LEVEL SECURITY;
ALTER TABLE contour.causal_generation_claims FORCE ROW LEVEL SECURITY;
CREATE POLICY causal_generation_owner ON contour.causal_generation_claims TO contour_owner
 USING (tenant_id=contour.tenant_context()) WITH CHECK (tenant_id=contour.tenant_context());
REVOKE ALL ON contour.causal_generation_claims FROM PUBLIC,contour_runtime,contour_causal_provisioner,contour_causal_issuer;
CREATE TRIGGER causal_generation_immutable BEFORE UPDATE OR DELETE ON contour.causal_generation_claims FOR EACH ROW EXECUTE FUNCTION contour.immutable_row();
CREATE TRIGGER causal_generation_no_truncate BEFORE TRUNCATE ON contour.causal_generation_claims FOR EACH STATEMENT EXECUTE FUNCTION contour.immutable_row();
CREATE FUNCTION contour.claim_causal_generation(t uuid, runtime uuid, ep numeric, n uuid, g bytea) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog AS $$
DECLARE binding contour.causal_runtime_bindings; s contour.causal_sessions; old contour.causal_generation_claims; now_at timestamptz; final_at timestamptz; used bigint;
BEGIN
 PERFORM contour.begin_origin_operation(t);
 SELECT * INTO binding FROM contour.causal_runtime_bindings b WHERE b.tenant_id=t AND b.runtime_id=runtime;
 IF NOT FOUND THEN RAISE EXCEPTION 'session unavailable' USING ERRCODE='23514'; END IF;
 PERFORM contour.lock_origin_credential(binding.export_leaf_sha256);
 PERFORM contour.lock_origin_collector(t,binding.collector_id);
 SELECT * INTO s FROM contour.causal_sessions x WHERE x.tenant_id=t AND x.runtime_id=runtime AND x.epoch=ep;
 now_at:=clock_timestamp();
 IF NOT FOUND OR n IS NULL OR g IS NULL OR octet_length(g)<>32 OR g=decode(repeat('00',32),'hex') OR s.nonce IS DISTINCT FROM n OR (s.claim).export_leaf IS DISTINCT FROM binding.export_leaf_sha256 OR NOT contour.causal_session_locked(s.claim,ep,now_at)
 THEN RAISE EXCEPTION 'session unavailable' USING ERRCODE='23514'; END IF;
 SELECT * INTO old FROM contour.causal_generation_claims x WHERE (x.tenant_id,x.runtime_id,x.epoch)=(t,runtime,ep);
 IF FOUND THEN
  IF old.nonce IS DISTINCT FROM n OR old.generation IS DISTINCT FROM g THEN RAISE EXCEPTION 'generation conflict' USING ERRCODE='23505'; END IF;
  final_at:=clock_timestamp();
  IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<now_at OR NOT contour.causal_session_locked(s.claim,ep,final_at) THEN RAISE EXCEPTION 'session unavailable at final check' USING ERRCODE='23514'; END IF;
  RETURN true;
 END IF;
 INSERT INTO contour.origin_logical_usage(tenant_id,used_bytes) VALUES(t,0) ON CONFLICT(tenant_id) DO NOTHING;
 SELECT x.used_bytes INTO STRICT used FROM contour.origin_logical_usage x WHERE x.tenant_id=t FOR UPDATE;
 IF 92>1073741824-used THEN RAISE EXCEPTION 'origin logical quota exhausted' USING ERRCODE='54000',CONSTRAINT='origin_logical_quota_exhausted'; END IF;
 INSERT INTO contour.causal_generation_claims VALUES(t,runtime,ep,n,g);
 UPDATE contour.origin_logical_usage SET used_bytes=used+92 WHERE tenant_id=t;
 final_at:=clock_timestamp();
 IF final_at IS NULL OR NOT isfinite(final_at) OR final_at<now_at OR NOT contour.causal_session_locked(s.claim,ep,final_at) THEN RAISE EXCEPTION 'session unavailable at final check' USING ERRCODE='23514'; END IF;
 RETURN true;
END $$;
REVOKE ALL ON FUNCTION contour.claim_causal_generation(uuid,uuid,numeric,uuid,bytea) FROM PUBLIC,contour_runtime,contour_causal_provisioner;
GRANT EXECUTE ON FUNCTION contour.claim_causal_generation(uuid,uuid,numeric,uuid,bytea) TO contour_causal_issuer;
INSERT INTO contour.schema_migrations(version) VALUES(22);
COMMIT;
