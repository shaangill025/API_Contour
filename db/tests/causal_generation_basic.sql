-- Disposable 1..22 fixture with a live current session. Caller supplies the
-- four test.generation_* settings; each issuer operation is its own transaction.
SELECT set_config('apicontour.tenant_id',current_setting('test.generation_tenant'),false);
CREATE TEMP TABLE generation_before AS SELECT coalesce((SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=current_setting('test.generation_tenant')::uuid),0) AS used;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 IF NOT contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex')) THEN RAISE EXCEPTION 'first claim failed'; END IF;
END $$;
DO $$ BEGIN
 IF NOT contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex')) THEN RAISE EXCEPTION 'retry failed'; END IF;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a2',32),'hex')); RAISE EXCEPTION 'different generation accepted'; EXCEPTION WHEN unique_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,'00000000-0000-4000-8000-000000000001',decode(repeat('a1',32),'hex')); RAISE EXCEPTION 'wrong nonce accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ BEGIN
 BEGIN PERFORM contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('00',32),'hex')); RAISE EXCEPTION 'zero generation accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
DO $$ BEGIN BEGIN PERFORM count(*) FROM contour.causal_generation_claims; RAISE EXCEPTION 'direct read allowed'; EXCEPTION WHEN insufficient_privilege THEN NULL; END; END $$;
RESET ROLE;
DO $$ BEGIN IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=current_setting('test.generation_tenant')::uuid)<>(SELECT used+92 FROM generation_before) THEN RAISE EXCEPTION 'claim charge mismatch'; END IF; END $$;
-- Exact retries still pass at the shared hard quota and do not charge again.
SELECT set_config('test.generation_restore',(used+92)::text,false) FROM generation_before;
SET ROLE contour_owner;
BEGIN; SELECT contour.begin_origin_operation(current_setting('test.generation_tenant')::uuid);
UPDATE contour.origin_logical_usage SET used_bytes=1073741824 WHERE tenant_id=current_setting('test.generation_tenant')::uuid;
COMMIT;
RESET ROLE;
SET ROLE contour_causal_issuer;
DO $$ BEGIN
 IF NOT contour.claim_causal_generation(current_setting('test.generation_tenant')::uuid,current_setting('test.generation_runtime')::uuid,current_setting('test.generation_epoch')::numeric,current_setting('test.generation_nonce')::uuid,decode(repeat('a1',32),'hex')) THEN RAISE EXCEPTION 'full quota retry denied'; END IF;
END $$;
RESET ROLE;
DO $$ BEGIN IF (SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id=current_setting('test.generation_tenant')::uuid)<>1073741824 THEN RAISE EXCEPTION 'retry charged quota'; END IF; END $$;
SET ROLE contour_owner;
BEGIN; SELECT contour.begin_origin_operation(current_setting('test.generation_tenant')::uuid);
UPDATE contour.origin_logical_usage SET used_bytes=current_setting('test.generation_restore')::bigint WHERE tenant_id=current_setting('test.generation_tenant')::uuid;
COMMIT;
DO $$ BEGIN BEGIN UPDATE contour.causal_generation_claims SET generation=generation; RAISE EXCEPTION 'update allowed'; EXCEPTION WHEN check_violation THEN NULL; END; END $$;
DO $$ BEGIN BEGIN DELETE FROM contour.causal_generation_claims; RAISE EXCEPTION 'delete allowed'; EXCEPTION WHEN check_violation THEN NULL; END; END $$;
DO $$ BEGIN BEGIN TRUNCATE contour.causal_generation_claims; RAISE EXCEPTION 'truncate allowed'; EXCEPTION WHEN check_violation THEN NULL; END; END $$;
RESET ROLE;
