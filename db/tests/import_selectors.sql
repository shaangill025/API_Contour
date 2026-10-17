\connect contour_fixture contour_declared_writer_test
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT projection_version=1 FROM contour.public_declared_contracts),
    'existing manifests stay explicitly legacy');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_members
    WHERE body_selector IS NOT NULL OR media_type IS NOT NULL),'legacy selectors are not invented');
SELECT * FROM contour.service_import_defaults FOR UPDATE;
INSERT INTO contour.declared_versions
    (tenant_id,version_id,operation_id,project_id,service_id,environment_id,codec_version,declared_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f1',operation_id,
        project_id,service_id,environment_id,codec_version,declared_wire
    FROM contour.declared_versions WHERE version_id='00000000-0000-0000-0000-000000000051';
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f2',project_id,service_id,environment_id,2,2,2
    FROM contour.public_declared_contracts WHERE revision=1;
INSERT INTO contour.public_declared_members
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f2',version_id,operation_id,
        project_id,service_id,environment_id,
        CASE WHEN version_id='00000000-0000-0000-0000-000000000051' THEN 'response:200' ELSE 'response:default' END,
        'application/json'
    FROM contour.declared_versions WHERE version_id IN
        ('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-0000000000f1');
SET CONSTRAINTS ALL IMMEDIATE;
SELECT fixture.assert((SELECT count(*)=2 AND count(DISTINCT body_selector)=2
    AND count(DISTINCT v.declared_wire)=1 FROM contour.public_declared_members m
    JOIN contour.declared_versions v USING(tenant_id,version_id)
    WHERE m.contract_id='00000000-0000-0000-0000-0000000000f2'),
    'identical graphs retain two exact selector associations');
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ DECLARE h contour.public_declared_contracts; m contour.public_declared_members;
    patch jsonb; candidate jsonb; selector text; media text; projection integer; BEGIN
    SELECT * INTO h FROM contour.public_declared_contracts WHERE revision=2;
    SELECT * INTO m FROM contour.public_declared_members WHERE contract_id=h.contract_id ORDER BY version_id LIMIT 1;
    FOREACH patch IN ARRAY ARRAY[
        '{"body_selector":"response:099"}'::jsonb,'{"body_selector":"response:600"}'::jsonb,
        '{"body_selector":"response:2xx"}'::jsonb,'{"body_selector":"uploaded-text"}'::jsonb,
        '{"media_type":"application/json; secret=value"}'::jsonb,'{"media_type":"/json"}'::jsonb,
        '{"media_type":"application/json/extra"}'::jsonb,
        jsonb_build_object('media_type',repeat('a',124)||'/json')] LOOP
        candidate=to_jsonb(m)||jsonb_build_object('version_id','00000000-0000-0000-0000-000000000053')||patch;
        PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_members
            SELECT * FROM jsonb_populate_record(NULL::contour.public_declared_members,%L::jsonb)',candidate),'23514');
    END LOOP;
    -- A distinct version with the same operation must not bypass selector uniqueness.
    candidate=to_jsonb(m)||jsonb_build_object('version_id','00000000-0000-0000-0000-000000000053');
    PERFORM fixture.expect_state(format('INSERT INTO contour.public_declared_members
        SELECT * FROM jsonb_populate_record(NULL::contour.public_declared_members,%L::jsonb)',candidate),'23505');
    -- Each failure has an otherwise complete one-member manifest. Count checks
    -- cannot mask the versioned-selector completeness requirement.
    FOR projection IN 1..2 LOOP
        FOR selector,media IN SELECT * FROM (VALUES
            (NULL::text,NULL::text),('request',NULL),(NULL,'text/plain'),('request','text/plain')) AS cases(s,m) LOOP
            IF (projection=1 AND selector IS NULL AND media IS NULL)
                OR (projection=2 AND selector IS NOT NULL AND media IS NOT NULL) THEN CONTINUE; END IF;
            BEGIN
                INSERT INTO contour.public_declared_contracts
                    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version)
                    VALUES(h.tenant_id,'00000000-0000-0000-0000-0000000000f3',h.project_id,h.service_id,h.environment_id,3,1,projection);
                INSERT INTO contour.public_declared_members VALUES(m.tenant_id,'00000000-0000-0000-0000-0000000000f3',
                    m.version_id,m.operation_id,m.project_id,m.service_id,m.environment_id,selector,media);
                SET CONSTRAINTS ALL IMMEDIATE;
                RAISE EXCEPTION 'invalid projection selector membership accepted';
            EXCEPTION WHEN check_violation THEN NULL; END;
        END LOOP;
    END LOOP;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_contracts WHERE revision=3),
        'invalid selector manifests roll back completely');
END $$;
SELECT fixture.expect_state('UPDATE contour.public_declared_contracts SET projection_version=projection_version','42501');
SELECT fixture.expect_state('UPDATE contour.public_declared_members SET body_selector=body_selector','42501');
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f4',project_id,service_id,environment_id,4,3,2
    FROM contour.public_declared_contracts WHERE revision=1;
INSERT INTO contour.public_declared_members
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f4',version_id,operation_id,
        project_id,service_id,environment_id,
        CASE WHEN version_id='00000000-0000-0000-0000-0000000000f1' THEN 'response:2XX' ELSE 'request' END,
        CASE WHEN version_id='00000000-0000-0000-0000-000000000051' THEN 'application/json' ELSE 'text/plain' END
    FROM contour.declared_versions WHERE version_id IN
        ('00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000053','00000000-0000-0000-0000-0000000000f1');
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version,warnings)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000f5',project_id,service_id,environment_id,5,0,2,ARRAY['partial_import']
    FROM contour.public_declared_contracts WHERE revision=1;
SET CONSTRAINTS ALL IMMEDIATE;
SELECT fixture.assert((SELECT count(*)=3 FROM contour.public_declared_members
    WHERE contract_id='00000000-0000-0000-0000-0000000000f4'),
    'request class and distinct media selectors retained');
SELECT fixture.assert((SELECT member_count=0 AND warnings=ARRAY['partial_import'] FROM contour.public_declared_contracts
    WHERE contract_id='00000000-0000-0000-0000-0000000000f5'),
    'empty partial projection retains header scope and warnings');
COMMIT;
\connect contour_fixture postgres
SELECT fixture.expect_state('UPDATE contour.public_declared_contracts SET projection_version=projection_version','23514');
SELECT fixture.expect_state('UPDATE contour.public_declared_members SET media_type=media_type','23514');
\connect contour_fixture contour_declared_reader_test
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_members),'selector rows hidden without context');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_declared_members),'selector tenant isolation');
ROLLBACK;
