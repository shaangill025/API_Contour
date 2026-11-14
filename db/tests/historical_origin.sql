-- Execute after migration 25 as a privileged fixture administrator.
-- These checks establish the SQL boundary; semantic data cases require the
-- separately owned ingestion/observation qualification fixture.
BEGIN;
DO $$
DECLARE signature regprocedure := 'contour.human_observation_origin(uuid,uuid,uuid,uuid,uuid,uuid)'::regprocedure;
BEGIN
 IF NOT pg_catalog.has_function_privilege('contour_catalog_reader',signature,'EXECUTE')
 OR EXISTS (SELECT 1 FROM pg_catalog.pg_proc p, LATERAL pg_catalog.aclexplode(coalesce(p.proacl,pg_catalog.acldefault('f',p.proowner))) a WHERE p.oid=signature AND a.grantee=0 AND a.privilege_type='EXECUTE')
 OR pg_catalog.has_function_privilege('contour_origin_ingress',signature,'EXECUTE')
 OR pg_catalog.has_table_privilege('contour_catalog_reader','contour.origin_proofs','SELECT')
 OR pg_catalog.has_table_privilege('contour_catalog_reader','contour.ingestion_v2_metadata','SELECT') THEN
   RAISE EXCEPTION 'historical origin privilege boundary';
 END IF;
END $$;
SET LOCAL ROLE contour_catalog_reader;
SELECT pg_catalog.set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ BEGIN
 BEGIN
  PERFORM * FROM contour.human_observation_origin('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000003','00000000-0000-0000-0000-000000000004','00000000-0000-0000-0000-000000000005');
  RAISE EXCEPTION 'cross tenant accepted';
 EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END $$;
ROLLBACK;
