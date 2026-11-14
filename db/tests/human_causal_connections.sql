-- SQL32 privilege and context checks in a disposable migrated database.
-- End-to-end fixtures and concurrent revocation checks must run separately.
DO $$
BEGIN
 IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_human_causal_reader'
   AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication))
 OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='contour_human_causal_reader')
 OR pg_has_role('contour_catalog_reader','contour_human_causal_reader','MEMBER')
 OR pg_has_role('contour_runtime','contour_human_causal_reader','MEMBER')
 OR has_table_privilege('contour_catalog_reader','contour.causal_resolved_edges','SELECT')
 OR has_table_privilege('contour_runtime','contour.causal_resolved_edges','SELECT')
 OR EXISTS (SELECT 1 FROM pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
  WHERE p.oid IN ('contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer)'::regprocedure,
   'contour.human_causal_snapshot(uuid,uuid,uuid,uuid,uuid,uuid,text,text,integer)'::regprocedure)
   AND a.grantee=0 AND a.privilege_type='EXECUTE')
 OR NOT has_function_privilege('contour_catalog_reader','contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer)','EXECUTE')
 OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
  WHERE p.oid='contour.human_causal_connections(uuid,uuid,uuid,uuid,uuid,uuid,text,text,uuid,text,text,integer)'::regprocedure
   AND p.prosecdef AND r.rolname='contour_human_causal_reader' AND p.proconfig @> ARRAY['search_path=pg_catalog','TimeZone=UTC'])
 OR NOT EXISTS (SELECT 1 FROM pg_proc p JOIN pg_roles r ON r.oid=p.proowner
  WHERE p.oid='contour.human_causal_snapshot(uuid,uuid,uuid,uuid,uuid,uuid,text,text,integer)'::regprocedure
   AND NOT p.prosecdef AND r.rolname='contour_human_causal_reader' AND p.proconfig @> ARRAY['search_path=pg_catalog','TimeZone=UTC'])
 THEN RAISE EXCEPTION 'human causal reader privilege mismatch'; END IF;
END $$;
BEGIN;
SELECT set_config('apicontour.tenant_id','00000000-0000-4000-8000-000000000001',true);
SET LOCAL ROLE contour_catalog_reader;
DO $$ BEGIN
 BEGIN
  PERFORM contour.human_causal_connections('00000000-0000-4000-8000-000000000002',
   '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001',
   '00000000-0000-4000-8000-000000000001','00000000-0000-4000-8000-000000000001',
   '00000000-0000-4000-8000-000000000001','issuer','subject',NULL,NULL,NULL,1);
  RAISE EXCEPTION 'mismatched tenant accepted';
 EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
