-- Disposable 1..23 database; caller supplies current generation_* and a live
-- credential belonging to the registered runtime's lifecycle as marker_credential.
-- Each binder call is its own transaction. This file is not a runtime receipt.
SELECT set_config('apicontour.tenant_id',current_setting('test.generation_tenant'),false);
CREATE TEMP TABLE marker_fixture AS
 SELECT c.credential_id,c.leaf_sha256,
        (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=c.tenant_id) AS used
 FROM contour.origin_credentials c JOIN contour.causal_runtime_bindings b
 ON (b.tenant_id,b.lifecycle_id)=(c.tenant_id,c.lifecycle_id)
 WHERE b.tenant_id=current_setting('test.generation_tenant')::uuid
 AND b.runtime_id=current_setting('test.generation_runtime')::uuid
 AND c.credential_id=current_setting('test.marker_credential')::uuid;
DO $$ BEGIN IF (SELECT count(*) FROM marker_fixture)<>1 THEN RAISE EXCEPTION 'fixture unavailable'; END IF; END $$;
SELECT set_config('test.marker_leaf',(SELECT encode(leaf_sha256,'hex') FROM marker_fixture),false);
SET ROLE contour_causal_provisioner;
SELECT set_config('test.marker_bound',contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('42',32),'hex'))::text,false);
DO $$ DECLARE x timestamptz; BEGIN
 x:=contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('42',32),'hex'));
 IF x IS DISTINCT FROM current_setting('test.marker_bound')::timestamptz THEN RAISE EXCEPTION 'duplicate bound_at changed'; END IF;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('43',32),'hex')); RAISE EXCEPTION 'conflict accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a2',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('42',32),'hex')); RAISE EXCEPTION 'different generation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM count(*) FROM contour.causal_marker_bindings; RAISE EXCEPTION 'direct read accepted'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
-- The wire layout is frozen independently of the live row's values.
SET ROLE contour_owner;
DO $$ DECLARE v contour.causal_marker_bindings; expected bytea; BEGIN
 v:=('00000000-0000-4000-8000-000000000001'::uuid,'00000000-0000-4000-8000-000000000002'::uuid,18446744073709551615::numeric,'00000000-0000-4000-8000-000000000003'::uuid,decode(repeat('11',32),'hex'),'00000000-0000-4000-8000-000000000004'::uuid,decode(repeat('22',32),'hex'),decode(repeat('33',32),'hex'),'00000000-0000-4000-8000-000000000005'::uuid,'00000000-0000-4000-8000-000000000006'::uuid,'00000000-0000-4000-8000-000000000007'::uuid,decode(repeat('44',32),'hex'),'2000-01-01 00:00:00+00'::timestamptz)::contour.causal_marker_bindings;
 expected:=decode('434d4b31' || '00000000000040008000000000000001' || '00000000000040008000000000000002' || '3138343436373434303733373039353531363135' || '00000000000040008000000000000003' || repeat('11',32) || '00000000000040008000000000000004' || repeat('22',32) || repeat('33',32) || '00000000000040008000000000000005' || '00000000000040008000000000000006' || '00000000000040008000000000000007' || repeat('44',32) || '0000000000000000','hex');
 IF contour.causal_marker_canonical(v) IS DISTINCT FROM expected OR octet_length(expected)<>272 THEN RAISE EXCEPTION 'known canonical vector mismatch'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=current_setting('test.generation_tenant')::uuid)<>(SELECT used+272 FROM marker_fixture) THEN RAISE EXCEPTION 'marker quota mismatch'; END IF; END $$;
-- Exact duplicates do not spend quota even when the tenant is at its cap.
SELECT set_config('test.marker_restore',(used+272)::text,false) FROM marker_fixture;
SET ROLE contour_owner;
BEGIN;
SELECT contour.begin_origin_operation(current_setting('test.generation_tenant')::uuid);
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id=current_setting('test.generation_tenant')::uuid;
COMMIT;
RESET ROLE;
SET ROLE contour_causal_provisioner;
DO $$ DECLARE x timestamptz; BEGIN
 x:=contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('42',32),'hex'));
 IF x IS DISTINCT FROM current_setting('test.marker_bound')::timestamptz THEN RAISE EXCEPTION 'quota duplicate changed'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=current_setting('test.generation_tenant')::uuid)<>1073741824 THEN RAISE EXCEPTION 'duplicate charged'; END IF; END $$;
SET ROLE contour_owner;
BEGIN;
SELECT contour.begin_origin_operation(current_setting('test.generation_tenant')::uuid);
UPDATE contour.origin_logical_usage SET used_bytes=current_setting('test.marker_restore')::bigint WHERE tenant_id=current_setting('test.generation_tenant')::uuid;
COMMIT;
RESET ROLE;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 BEGIN PERFORM contour.bind_causal_marker_key(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex'),current_setting('test.marker_credential')::uuid,decode(current_setting('test.marker_leaf'),'hex'),decode(repeat('42',32),'hex')); RAISE EXCEPTION 'issuer bound marker'; EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
RESET ROLE;
SET ROLE contour_owner;
DO $$ DECLARE row_value contour.causal_marker_bindings; encoded bytea; BEGIN
 SELECT * INTO STRICT row_value FROM contour.causal_marker_bindings WHERE tenant_id=current_setting('test.generation_tenant')::uuid AND runtime_id=current_setting('test.generation_runtime')::uuid AND epoch=current_setting('test.generation_epoch')::numeric;
 encoded:=contour.causal_marker_canonical(row_value);
 IF octet_length(encoded)<>272 OR substring(encoded FROM 1 FOR 4)<>convert_to('CMK1','UTF8') OR substring(encoded FROM 37 FOR 20)<>convert_to(lpad(trunc(row_value.epoch)::text,20,'0'),'UTF8') THEN RAISE EXCEPTION 'canonical layout mismatch'; END IF;
 BEGIN UPDATE contour.causal_marker_bindings SET marker_public_key=marker_public_key; RAISE EXCEPTION 'update accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN DELETE FROM contour.causal_marker_bindings; RAISE EXCEPTION 'delete accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 BEGIN TRUNCATE contour.causal_marker_bindings; RAISE EXCEPTION 'truncate accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
RESET ROLE;
