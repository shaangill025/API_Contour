-- Real restricted logins; identifiers below are synthetic fixture values.
\connect contour_fixture contour_approval_writer_test
SELECT fixture.assert(session_user='contour_approval_writer_test','real approval writer');
DO $$ DECLARE role_name text; relation text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_approval_writer','contour_approval_reader'] LOOP
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role_name::regrole),
            'approval groups inherit nothing');
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted nonlogin group');
        FOREACH relation IN ARRAY ARRAY['approval_events','approval_heads'] LOOP
            PERFORM fixture.assert(has_table_privilege(role_name,'contour.'||relation,'SELECT')
                AND NOT has_table_privilege(role_name,'contour.'||relation,'DELETE,TRUNCATE'),
                'approval restricted reads');
            PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid=('contour.'||relation)::regclass
                AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),'forced RLS');
        END LOOP;
        PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.approval_events','UPDATE')
            AND NOT has_column_privilege(role_name,'contour.approval_events','created_at','INSERT'),
            'immutable audit and protected server timestamp');
        PERFORM fixture.assert(has_column_privilege(role_name,'contour.approval_heads','current_event_id','UPDATE')
            =(role_name='contour_approval_writer')
            AND NOT has_column_privilege(role_name,'contour.approval_heads','operation_id','UPDATE'),
            'only head association mutable');
        PERFORM fixture.assert(NOT has_column_privilege(role_name,'contour.declared_versions','declared_wire','SELECT')
            AND NOT has_table_privilege(role_name,'contour.declared_versions','INSERT,UPDATE,DELETE,TRUNCATE'),
            'no declared bytes or mutations');
        FOREACH relation IN ARRAY ARRAY['ingestion_payloads','observation_windows','policy_revisions','collectors'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'no unrelated permissions');
        END LOOP;
    END LOOP;
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin','contour_ingestion',
        'contour_catalog_worker','contour_catalog_reader','contour_declared_writer','contour_declared_reader'] LOOP
        FOREACH relation IN ARRAY ARRAY['approval_events','approval_heads'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'existing roles unchanged');
        END LOOP;
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.approval_events)
    AND NOT EXISTS(SELECT 1 FROM contour.approval_heads),'missing context hides associations');
SELECT fixture.expect_state($q$INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000061',
        '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000071')$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.approval_heads
    (tenant_id,operation_id,project_id,service_id,environment_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000051',
        '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001')$q$,'42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.approval_heads (tenant_id,operation_id,project_id,service_id,environment_id)
    SELECT tenant_id,operation_id,project_id,service_id,environment_id FROM contour.operations
    WHERE operation_id='00000000-0000-0000-0000-000000000051';
SELECT fixture.assert((SELECT count(*)=1 AND bool_and(current_event_id IS NULL) FROM contour.approval_heads),'initial null head');
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000061',operation_id,project_id,service_id,
        environment_id,version_id,NULL,'00000000-0000-0000-0000-000000000071'
    FROM contour.declared_versions WHERE version_id='00000000-0000-0000-0000-000000000051';
UPDATE contour.approval_heads SET current_event_id='00000000-0000-0000-0000-000000000061';
SELECT fixture.assert((SELECT count(*)=1 AND bool_and(e.created_at BETWEEN transaction_timestamp()
    AND clock_timestamp()) FROM contour.approval_heads h JOIN contour.approval_events e
    ON h.tenant_id=e.tenant_id AND h.current_event_id=e.event_id),'exact event and server timestamp');
DO $$ DECLARE col text; row contour.approval_events; BEGIN
    SELECT * INTO row FROM contour.approval_events;
    FOREACH col IN ARRAY ARRAY['operation_id','project_id','service_id','environment_id','version_id'] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.approval_events
            (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
            SELECT tenant_id,%L,%s,%s,%s,%s,%s,actor_id FROM contour.approval_events',
            '00000000-0000-0000-0000-000000000062',
            CASE WHEN col='operation_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'operation_id' END,
            CASE WHEN col='project_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'project_id' END,
            CASE WHEN col='service_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'service_id' END,
            CASE WHEN col='environment_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'environment_id' END,
            CASE WHEN col='version_id' THEN quote_literal('00000000-0000-0000-0000-000000000002')||'::uuid' ELSE 'version_id' END),'23503');
    END LOOP;
    FOREACH col IN ARRAY ARRAY['project_id','service_id','environment_id'] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.approval_heads
            (tenant_id,operation_id,project_id,service_id,environment_id)
            SELECT tenant_id,operation_id,%s,%s,%s FROM contour.operations
            WHERE operation_id=%L',
            CASE WHEN col='project_id' THEN quote_literal('00000000-0000-0000-0000-000000000001')||'::uuid' ELSE 'project_id' END,
            CASE WHEN col='service_id' THEN quote_literal('00000000-0000-0000-0000-000000000001')||'::uuid' ELSE 'service_id' END,
            CASE WHEN col='environment_id' THEN quote_literal('00000000-0000-0000-0000-000000000001')||'::uuid' ELSE 'environment_id' END,
            '00000000-0000-0000-0000-000000000002'),'23503');
    END LOOP;
    PERFORM fixture.expect_state($q$INSERT INTO contour.approval_events
        (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
        SELECT tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id
        FROM contour.approval_events$q$,'23505');
    PERFORM fixture.expect_state($q$INSERT INTO contour.approval_heads
        (tenant_id,operation_id,project_id,service_id,environment_id)
        SELECT tenant_id,operation_id,project_id,service_id,environment_id FROM contour.approval_heads$q$,'23505');
    PERFORM fixture.expect_state('UPDATE contour.approval_heads SET current_event_id='''
        ||'00000000-0000-0000-0000-000000000099''','23503');
    PERFORM fixture.expect_state('UPDATE contour.approval_heads SET operation_id=operation_id','42501');
    PERFORM fixture.expect_state('UPDATE contour.approval_events SET actor_id=actor_id','42501');
    PERFORM fixture.expect_state('DELETE FROM contour.approval_events','42501');
    PERFORM fixture.expect_state('DELETE FROM contour.approval_heads','42501');
    PERFORM fixture.expect_state('TRUNCATE contour.approval_events','42501');
    PERFORM fixture.expect_state('TRUNCATE contour.approval_heads','42501');
    PERFORM fixture.expect_state($q$INSERT INTO contour.approval_events
        (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id,created_at)
        SELECT tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id,now()
        FROM contour.approval_events$q$,'42501');
    PERFORM fixture.expect_state($q$INSERT INTO contour.approval_events
        (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
        SELECT 'bbbbbbbb-0000-0000-0000-000000000000',event_id,operation_id,project_id,service_id,
            environment_id,version_id,actor_id FROM contour.approval_events$q$,'42501');
END $$;
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.approval_events),'commit clears context');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000062',operation_id,project_id,service_id,
        environment_id,version_id,event_id,actor_id FROM contour.approval_events;
UPDATE contour.approval_heads SET current_event_id='00000000-0000-0000-0000-000000000062';
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=1 FROM contour.approval_events)
    AND (SELECT current_event_id='00000000-0000-0000-0000-000000000061' FROM contour.approval_heads),
    'head event and actor audit roll back together');
ROLLBACK;
-- Both target events/versions exist, but belong to different operations.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000063',operation_id,project_id,service_id,
        environment_id,version_id,'00000000-0000-0000-0000-000000000071'
    FROM contour.declared_versions WHERE version_id='00000000-0000-0000-0000-000000000052';
SELECT fixture.assert((SELECT count(*)=2 FROM contour.approval_events),'two valid distinct operations');
SELECT fixture.expect_state($q$UPDATE contour.approval_heads
    SET current_event_id='00000000-0000-0000-0000-000000000063'$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000064',operation_id,project_id,service_id,
        environment_id,version_id,'00000000-0000-0000-0000-000000000063',actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000061'$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000064',operation_id,project_id,service_id,
        environment_id,'00000000-0000-0000-0000-000000000052',actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000061'$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000064',operation_id,project_id,service_id,
        environment_id,version_id,'00000000-0000-0000-0000-000000000064',actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000061'$q$,'23514');
ROLLBACK;
\connect contour_fixture contour_approval_reader_test
SELECT fixture.assert(session_user='contour_approval_reader_test','real approval reader');
SELECT fixture.expect_state('INSERT INTO contour.approval_events DEFAULT VALUES','42501');
SELECT fixture.expect_state('INSERT INTO contour.approval_heads DEFAULT VALUES','42501');
SELECT fixture.expect_state('UPDATE contour.approval_heads SET current_event_id=current_event_id','42501');
SELECT fixture.expect_state('SELECT declared_wire FROM contour.declared_versions','42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.approval_events)
    AND NOT EXISTS(SELECT 1 FROM contour.approval_heads),'other tenant hides associations');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=1 AND bool_and(actor_id='00000000-0000-0000-0000-000000000071')
    FROM contour.approval_events),'reader sees persisted actor audit');
ROLLBACK;
