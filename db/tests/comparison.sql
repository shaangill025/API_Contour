-- Run as actual restricted logins, not SET ROLE from the administrator.
\connect contour_fixture contour_comparison_writer_test
SELECT fixture.assert(session_user='contour_comparison_writer_test','real comparison writer');
DO $$ DECLARE role_name text; relation text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_comparison_writer','contour_comparison_reader'] LOOP
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role_name::regrole),
            'comparison groups inherit nothing');
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted nonlogin comparison group');
        PERFORM fixture.assert(has_table_privilege(role_name,'contour.comparisons','SELECT')
            AND NOT has_table_privilege(role_name,'contour.comparisons','UPDATE,DELETE,TRUNCATE'),
            'immutable comparison privileges');
        PERFORM fixture.assert(has_column_privilege(role_name,'contour.comparisons','result_wire','INSERT')
            =(role_name='contour_comparison_writer')
            AND NOT has_column_privilege(role_name,'contour.comparisons','created_at','INSERT'),
            'protected server timestamp');
        PERFORM fixture.assert(NOT has_column_privilege(role_name,'contour.declared_versions','declared_wire','SELECT')
            AND NOT has_column_privilege(role_name,'contour.approval_events','actor_id','SELECT'),
            'input metadata only');
        FOREACH relation IN ARRAY ARRAY['approval_heads','ingestion_payloads','observation_windows','policy_revisions'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'no mutable heads or capture data');
        END LOOP;
    END LOOP;
    PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid='contour.comparisons'::regclass
        AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),'forced owner RLS');
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin','contour_ingestion',
        'contour_catalog_worker','contour_catalog_reader','contour_declared_writer','contour_declared_reader',
        'contour_approval_writer','contour_approval_reader'] LOOP
        PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.comparisons',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'existing roles unchanged');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.comparisons),'absent context hides comparisons');
SELECT fixture.expect_state($q$INSERT INTO contour.comparisons
    (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,left_kind,left_version_id,
    right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000081',
        '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
        'declared','00000000-0000-0000-0000-000000000051',
        'declared','00000000-0000-0000-0000-000000000053',1,1,decode('00','hex'))$q$,'42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000081',operation_id,project_id,service_id,environment_id,
        'approved',version_id,event_id,'declared','00000000-0000-0000-0000-000000000053',1,1,decode('0009c3a9f09f9880','hex')
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000061';
INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,right_kind,right_version_id,right_event_id,evaluator_version,result_codec_version,result_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000082',operation_id,project_id,service_id,environment_id,
        right_kind,right_version_id,left_kind,left_version_id,left_event_id,evaluator_version,result_codec_version,result_wire
    FROM contour.comparisons;
SELECT fixture.assert((SELECT count(*)=2 AND bool_and(created_at BETWEEN transaction_timestamp() AND clock_timestamp())
    AND bool_and(encode(result_wire,'hex')='0009c3a9f09f9880') FROM contour.comparisons),'server time and exact opaque bytes');
SELECT fixture.assert((SELECT left_kind='declared' AND left_version_id='00000000-0000-0000-0000-000000000053'
    AND right_kind='approved' AND right_event_id='00000000-0000-0000-0000-000000000061'
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000082'),'ordered kinds and original event');
INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000084',operation_id,project_id,service_id,environment_id,
        'declared',left_version_id,right_kind,right_version_id,1,1,result_wire
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,evaluator_version,result_codec_version,result_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000085',operation_id,project_id,service_id,environment_id,
        left_kind,left_version_id,left_event_id,'approved',right_version_id,'00000000-0000-0000-0000-000000000063',1,1,result_wire
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
DO $$ DECLARE row contour.comparisons; wire bytea; side text; col text; candidate jsonb; patch jsonb; expected text; BEGIN
    SELECT * INTO row FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
    -- JSON record construction changes one synthetic field; INSERT still names allowed columns.
    FOR patch,expected IN SELECT * FROM (VALUES
        ('{"left_kind":"observed","left_event_id":null}'::jsonb,'23514'),
        ('{"right_kind":"observed"}'::jsonb,'23514'),
        ('{"left_kind":"declared"}'::jsonb,'23514'),
        ('{"left_event_id":null}'::jsonb,'23514'),
        ('{"right_kind":"approved"}'::jsonb,'23514'),
        ('{"right_event_id":"00000000-0000-0000-0000-000000000063"}'::jsonb,'23514'),
        ('{"project_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"service_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"environment_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"operation_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"tenant_id":"bbbbbbbb-0000-0000-0000-000000000000"}'::jsonb,'42501'),
        ('{"comparison_id":"00000000-0000-0000-0000-000000000081"}'::jsonb,'23505')
    ) AS cases(change,state) LOOP
        candidate=to_jsonb(row)||jsonb_build_object('comparison_id','00000000-0000-0000-0000-000000000083')||patch;
        PERFORM fixture.expect_state(format('INSERT INTO contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,
            evaluator_version,result_codec_version,result_wire)
            SELECT tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,
            evaluator_version,result_codec_version,result_wire FROM jsonb_populate_record(NULL::contour.comparisons,%L::jsonb)',candidate),expected);
    END LOOP;
    -- A record-valued insert names allowed columns, excluding server created_at.
    FOREACH side IN ARRAY ARRAY['left','right'] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
            SELECT tenant_id,%L,operation_id,project_id,service_id,environment_id,''declared'',%s,''declared'',%s,1,1,result_wire
            FROM contour.comparisons WHERE comparison_id=%L',
            '00000000-0000-0000-0000-000000000083',
            CASE WHEN side='left' THEN quote_literal('00000000-0000-0000-0000-000000000052')||'::uuid' ELSE 'left_version_id' END,
            CASE WHEN side='right' THEN quote_literal('00000000-0000-0000-0000-000000000052')||'::uuid' ELSE 'right_version_id' END,
            row.comparison_id),'23503');
        -- Event63 is same operation but refers to version53, never version51.
        PERFORM fixture.expect_state(format('INSERT INTO contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,right_event_id,
            evaluator_version,result_codec_version,result_wire)
            SELECT tenant_id,%L,operation_id,project_id,service_id,environment_id,%L,left_version_id,%s,
                %L,left_version_id,%s,1,1,result_wire FROM contour.comparisons WHERE comparison_id=%L',
            '00000000-0000-0000-0000-000000000083',
            CASE WHEN side='left' THEN 'approved' ELSE 'declared' END,
            CASE WHEN side='left' THEN quote_literal('00000000-0000-0000-0000-000000000063')||'::uuid' ELSE 'NULL' END,
            CASE WHEN side='right' THEN 'approved' ELSE 'declared' END,
            CASE WHEN side='right' THEN quote_literal('00000000-0000-0000-0000-000000000063')||'::uuid' ELSE 'NULL' END,
            row.comparison_id),'23503');
    END LOOP;
    FOREACH wire IN ARRAY ARRAY[decode('','hex'),decode(repeat('aa',1048577),'hex')] LOOP
        BEGIN
            INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
                left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
                VALUES(row.tenant_id,pg_catalog.gen_random_uuid(),row.operation_id,row.project_id,row.service_id,row.environment_id,
                    row.left_kind,row.left_version_id,row.left_event_id,row.right_kind,row.right_version_id,1,1,wire);
            RAISE EXCEPTION 'invalid result bound accepted';
        EXCEPTION WHEN check_violation THEN NULL; END;
    END LOOP;
    FOREACH wire IN ARRAY ARRAY[decode('00','hex'),decode(repeat('aa',1048576),'hex')] LOOP
        INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
            VALUES(row.tenant_id,pg_catalog.gen_random_uuid(),row.operation_id,row.project_id,row.service_id,row.environment_id,
                row.left_kind,row.left_version_id,row.left_event_id,row.right_kind,row.right_version_id,1,1,wire);
        PERFORM fixture.assert(EXISTS(SELECT 1 FROM contour.comparisons WHERE result_wire=wire),'inclusive result byte bounds');
    END LOOP;
    FOREACH col IN ARRAY ARRAY['evaluator_version','result_codec_version'] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.comparisons
            (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
            SELECT tenant_id,%L,operation_id,project_id,service_id,environment_id,left_kind,left_version_id,left_event_id,
            right_kind,right_version_id,%s,%s,result_wire FROM contour.comparisons WHERE comparison_id=%L',
            '00000000-0000-0000-0000-000000000083',CASE WHEN col='evaluator_version' THEN '2' ELSE '1' END,
            CASE WHEN col='result_codec_version' THEN '2' ELSE '1' END,row.comparison_id),'23514');
    END LOOP;
END $$;
SELECT fixture.expect_state('UPDATE contour.comparisons SET result_wire=result_wire','42501');
SELECT fixture.expect_state('DELETE FROM contour.comparisons','42501');
SELECT fixture.expect_state('TRUNCATE contour.comparisons','42501');
SELECT fixture.expect_state('INSERT INTO contour.comparisons(created_at) VALUES(now())','42501');
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.comparisons),'commit clears comparison context');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.comparisons (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000083',operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
ROLLBACK;
-- Fixture administrator advances the head only after comparisons were committed.
\connect contour_fixture postgres
UPDATE contour.approval_heads SET current_event_id='00000000-0000-0000-0000-000000000063'
    WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SELECT fixture.assert((SELECT current_event_id='00000000-0000-0000-0000-000000000063'
    FROM contour.approval_heads WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'),'head advanced after comparison persistence');
\connect contour_fixture contour_comparison_reader_test
SELECT fixture.assert(session_user='contour_comparison_reader_test','real comparison reader');
SELECT fixture.expect_state('INSERT INTO contour.comparisons DEFAULT VALUES','42501');
SELECT fixture.expect_state('UPDATE contour.comparisons SET result_wire=result_wire','42501');
SELECT fixture.expect_state('DELETE FROM contour.comparisons','42501');
SELECT fixture.expect_state('SELECT * FROM contour.approval_heads','42501');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.comparisons),'reader absent context');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.comparisons),'reader other tenant');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=6 FROM contour.comparisons)
    AND NOT EXISTS(SELECT 1 FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000083'),
    'immutable rows survive and rolled-back comparison does not');
SELECT fixture.assert((SELECT c.left_event_id=e.event_id AND c.left_version_id=e.version_id
    FROM contour.comparisons c JOIN contour.approval_events e ON c.tenant_id=e.tenant_id AND c.left_event_id=e.event_id
    WHERE c.comparison_id='00000000-0000-0000-0000-000000000081'),'original approved input reloads');
ROLLBACK;
