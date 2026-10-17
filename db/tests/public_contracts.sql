-- Restricted sessions; SQL stores associations, not checked graph semantics.
\connect contour_fixture postgres
INSERT INTO contour.service_import_defaults VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
     '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$INSERT INTO contour.service_import_defaults VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000ffffff',
     '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23503');
SELECT fixture.expect_state($q$UPDATE contour.service_import_defaults
    SET environment_id='00000000-0000-0000-0000-000000ffffff'$q$,'23503');
\connect contour_fixture contour_declared_writer_test
SELECT fixture.assert(session_user='contour_declared_writer_test','real import writer login');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.service_import_defaults),'no context hides defaults');
SELECT fixture.expect_state('INSERT INTO contour.service_import_defaults DEFAULT VALUES','42501');
SELECT fixture.expect_state('UPDATE contour.service_import_defaults SET environment_id=environment_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.service_import_defaults','42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT * FROM contour.service_import_defaults FOR SHARE;
SELECT fixture.expect_state('UPDATE contour.service_import_defaults SET tenant_id=tenant_id','23514');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.service_import_defaults
    WHERE service_id='00000000-0000-0000-0000-000000ffffff'),'no implicit default for missing service');
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,warnings)
    VALUES (contour.tenant_context(),'00000000-0000-0000-0000-0000000000e1',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001',1,2,ARRAY['removed_value']);
INSERT INTO contour.public_declared_members
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000e1',version_id,operation_id,
        project_id,service_id,environment_id FROM contour.declared_versions
    WHERE version_id IN ('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000053');
SET CONSTRAINTS ALL IMMEDIATE;
SELECT fixture.assert((SELECT count(*)=2 AND count(DISTINCT operation_id)=1
    FROM contour.public_declared_members),'multiple exact graphs for one operation retained');
SELECT fixture.assert((SELECT created_at BETWEEN transaction_timestamp() AND clock_timestamp()
    FROM contour.public_declared_contracts),'server-owned timestamp');
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ DECLARE h contour.public_declared_contracts; m contour.public_declared_members; patch jsonb; candidate jsonb; unused uuid; BEGIN
    SELECT * INTO h FROM contour.public_declared_contracts;
    SELECT * INTO m FROM contour.public_declared_members ORDER BY version_id LIMIT 1;
    SELECT version_id INTO unused FROM contour.declared_versions WHERE version_id NOT IN
        ('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000053') LIMIT 1;
    PERFORM fixture.assert(unused IS NOT NULL,'independent valid unlinked version exists');
    FOREACH patch IN ARRAY ARRAY[
        '{"revision":0}'::jsonb,'{"revision":9007199254740992}'::jsonb,
        '{"member_count":-1}'::jsonb,'{"member_count":4097}'::jsonb,
        '{"warnings":["arbitrary-upload-text"]}'::jsonb,'{"warnings":[null]}'::jsonb,
        jsonb_build_object('warnings',array_fill('removed_value'::text,ARRAY[201]))] LOOP
        candidate=to_jsonb(h)||jsonb_build_object('contract_id','00000000-0000-0000-0000-0000000000e2',
            'revision',2,'member_count',0)||patch;
        PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_contracts
            (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,warnings)
            SELECT tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,warnings
            FROM jsonb_populate_record(NULL::contour.public_declared_contracts,%L::jsonb)',candidate),'23514');
    END LOOP;
    PERFORM fixture.expect_state('INSERT INTO contour.public_declared_members SELECT * FROM contour.public_declared_members','23505');
    FOREACH patch IN ARRAY ARRAY[
        '{"version_id":"00000000-0000-0000-0000-000000ffffff"}'::jsonb,
        jsonb_build_object('operation_id','00000000-0000-0000-0000-000000ffffff','version_id',unused),
        '{"contract_id":"00000000-0000-0000-0000-000000ffffff"}'::jsonb,
        jsonb_build_object('environment_id','00000000-0000-0000-0000-000000ffffff','version_id',unused)] LOOP
        candidate=to_jsonb(m)||patch;
        -- Distinct member keys keep uniqueness errors from masking scope FKs.
        PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_members
            SELECT * FROM jsonb_populate_record(NULL::contour.public_declared_members,%L::jsonb)',candidate),'23503');
    END LOOP;
    PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_contracts
        (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count)
        VALUES(%L,%L,%L,%L,%L,1,0)',h.tenant_id,'00000000-0000-0000-0000-0000000000e2',
        h.project_id,h.service_id,h.environment_id),'23505');
    -- Missing and excess membership must fail before transaction completion.
    BEGIN
        INSERT INTO contour.public_declared_contracts
            (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count)
            VALUES(h.tenant_id,'00000000-0000-0000-0000-0000000000e2',h.project_id,h.service_id,h.environment_id,2,1);
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'incomplete import accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_contracts WHERE revision=2),
        'incomplete import leaves no header');
    BEGIN
        INSERT INTO contour.public_declared_contracts
            (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count)
            VALUES(h.tenant_id,'00000000-0000-0000-0000-0000000000e2',h.project_id,h.service_id,h.environment_id,2,0);
        INSERT INTO contour.public_declared_members VALUES(h.tenant_id,'00000000-0000-0000-0000-0000000000e2',
            m.version_id,m.operation_id,m.project_id,m.service_id,m.environment_id);
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'excess import membership accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_members
        WHERE contract_id='00000000-0000-0000-0000-0000000000e2'),'partial membership rolled back');
    BEGIN
        INSERT INTO contour.public_declared_members
            SELECT tenant_id,h.contract_id,version_id,operation_id,project_id,service_id,environment_id
            FROM contour.declared_versions WHERE version_id NOT IN
                ('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000053') LIMIT 1;
        SET CONSTRAINTS ALL IMMEDIATE;
        RAISE EXCEPTION 'post-commit append accepted';
    EXCEPTION WHEN check_violation THEN NULL; END;
    PERFORM fixture.assert((SELECT count(*)=2 FROM contour.public_declared_members),'committed manifest stays sealed');
END $$;
SELECT fixture.expect_state('UPDATE contour.public_declared_contracts SET revision=revision','42501');
SELECT fixture.expect_state('DELETE FROM contour.public_declared_contracts','42501');
SELECT fixture.expect_state('UPDATE contour.public_declared_members SET version_id=version_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.public_declared_members','42501');
SELECT fixture.assert(NOT has_column_privilege(current_user,'contour.public_declared_contracts','created_at','INSERT'),
    'creation time cannot be supplied');
COMMIT;
\connect contour_fixture postgres
INSERT INTO contour.environments VALUES ('aaaaaaaa-0000-0000-0000-000000000000',
    '00000000-0000-0000-0000-0000000000e9','00000000-0000-0000-0000-000000000001');
\connect contour_fixture contour_declared_writer_test
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count)
    VALUES(contour.tenant_context(),'00000000-0000-0000-0000-0000000000e2',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-0000000000e9',2,1);
-- The new header has a valid, different environment. Each case violates only
-- one association FK; counts remain deferred and this entire setup rolls back.
DO $$ DECLARE m contour.public_declared_members; candidate jsonb; BEGIN
    SELECT * INTO m FROM contour.public_declared_members ORDER BY version_id LIMIT 1;
    candidate=to_jsonb(m)||jsonb_build_object('contract_id','00000000-0000-0000-0000-0000000000e2');
    PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_members
        SELECT * FROM jsonb_populate_record(NULL::contour.public_declared_members,%L::jsonb)',candidate),'23503');
    candidate=candidate||jsonb_build_object('environment_id','00000000-0000-0000-0000-0000000000e9');
    PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_members
        SELECT * FROM jsonb_populate_record(NULL::contour.public_declared_members,%L::jsonb)',candidate),'23503');
END $$;
ROLLBACK;
\connect contour_fixture postgres
UPDATE contour.service_import_defaults SET environment_id='00000000-0000-0000-0000-0000000000e9';
SELECT fixture.assert((SELECT environment_id='00000000-0000-0000-0000-000000000001'
    FROM contour.public_declared_contracts),'default change preserves historical environment');
SELECT fixture.expect_state('UPDATE contour.public_declared_contracts SET revision=revision','23514');
SELECT fixture.expect_state('DELETE FROM contour.public_declared_contracts','23514');
SELECT fixture.expect_state('UPDATE contour.public_declared_members SET version_id=version_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.public_declared_members','23514');
\connect contour_fixture contour_declared_reader_test
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_contracts)
    AND NOT EXISTS(SELECT 1 FROM contour.public_declared_members),'reader absent context hides imports');
SELECT fixture.expect_state('INSERT INTO contour.public_declared_contracts DEFAULT VALUES','42501');
SELECT fixture.expect_state('INSERT INTO contour.public_declared_members DEFAULT VALUES','42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_contracts)
    AND NOT EXISTS(SELECT 1 FROM contour.public_declared_members)
    AND NOT EXISTS(SELECT 1 FROM contour.service_import_defaults),'tenant isolation');
ROLLBACK;
