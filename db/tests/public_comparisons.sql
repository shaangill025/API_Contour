\connect contour_fixture contour_declared_writer_test
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
-- Two whole imports legitimately contain the same internal version.
INSERT INTO contour.public_declared_contracts
    (tenant_id,contract_id,project_id,service_id,environment_id,revision,member_count,projection_version)
    SELECT tenant_id,id::uuid,project_id,service_id,environment_id,revision_number,1,2
    FROM contour.public_declared_contracts CROSS JOIN (VALUES
        ('00000000-0000-0000-0000-0000000000d1',6),
        ('00000000-0000-0000-0000-0000000000d2',7)) AS imports(id,revision_number)
    WHERE revision=1;
INSERT INTO contour.public_declared_members
    SELECT tenant_id,id::uuid,version_id,operation_id,project_id,service_id,environment_id,'response:200','application/json'
    FROM contour.declared_versions CROSS JOIN (VALUES
        ('00000000-0000-0000-0000-0000000000d1'),
        ('00000000-0000-0000-0000-0000000000d2')) AS imports(id)
    WHERE version_id='00000000-0000-0000-0000-000000000051';
COMMIT;
\connect contour_fixture contour_approval_writer_test
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000d7',operation_id,project_id,service_id,environment_id,
        version_id,event_id,actor_id FROM contour.approval_events
    WHERE event_id='00000000-0000-0000-0000-000000000061';
COMMIT;
\connect contour_fixture contour_comparison_writer_test
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_comparison_inputs),'absent context hides public inputs');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.comparisons
    (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire,public_projection)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000d3',operation_id,project_id,service_id,environment_id,
        'declared',left_version_id,'declared',left_version_id,1,1,result_wire,2
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
INSERT INTO contour.public_comparison_inputs
    SELECT tenant_id,comparison_id,side,operation_id,project_id,service_id,environment_id,
        'declared',id::uuid,id::uuid,left_version_id,NULL::uuid
    FROM contour.comparisons CROSS JOIN (VALUES
        ('left','00000000-0000-0000-0000-0000000000d1'),
        ('right','00000000-0000-0000-0000-0000000000d2')) AS inputs(side,id)
    WHERE comparison_id='00000000-0000-0000-0000-0000000000d3';
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=2 AND count(DISTINCT public_input_id)=2
    AND count(DISTINCT version_id)=1 FROM contour.public_comparison_inputs),
    'committed comparison retains both selected imports sharing one version');
DO $$ DECLARE c contour.comparisons; i contour.public_comparison_inputs; n integer; patch jsonb; state text; BEGIN
    SELECT * INTO c FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-0000000000d3';
    SELECT * INTO i FROM contour.public_comparison_inputs WHERE side='left';
    -- Missing inputs and otherwise valid but mismatched pairs fail at completion.
    FOR n IN 0..4 LOOP
        BEGIN
            INSERT INTO contour.comparisons
                (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
                left_kind,left_version_id,right_kind,right_version_id,right_event_id,evaluator_version,result_codec_version,result_wire,public_projection)
                VALUES(c.tenant_id,'00000000-0000-0000-0000-0000000000d4',c.operation_id,c.project_id,c.service_id,c.environment_id,
                    c.left_kind,c.left_version_id,CASE WHEN n=4 THEN 'approved' ELSE c.right_kind END,
                    CASE WHEN n=2 THEN '00000000-0000-0000-0000-000000000053'::uuid ELSE c.right_version_id END,
                    CASE WHEN n=4 THEN '00000000-0000-0000-0000-000000000061'::uuid ELSE NULL END,
                    1,1,c.result_wire,2);
            IF n>=1 THEN
                INSERT INTO contour.public_comparison_inputs SELECT * FROM jsonb_populate_record(
                    NULL::contour.public_comparison_inputs,to_jsonb(i)||'{"comparison_id":"00000000-0000-0000-0000-0000000000d4"}'::jsonb);
            END IF;
            IF n>=2 THEN
                INSERT INTO contour.public_comparison_inputs SELECT * FROM jsonb_populate_record(
                    NULL::contour.public_comparison_inputs,to_jsonb(i)||
                    '{"comparison_id":"00000000-0000-0000-0000-0000000000d4","side":"right"}'::jsonb||
                    CASE WHEN n=4 THEN '{"input_kind":"approved","approval_event_id":"00000000-0000-0000-0000-0000000000d7","public_input_id":"00000000-0000-0000-0000-0000000000d7"}'::jsonb
                    WHEN n=3 THEN '{"input_kind":"approved","approval_event_id":"00000000-0000-0000-0000-000000000061","public_input_id":"00000000-0000-0000-0000-000000000061"}'::jsonb
                    ELSE '{}'::jsonb END);
            END IF;
            SET CONSTRAINTS ALL IMMEDIATE;
            RAISE EXCEPTION 'partial public comparison accepted';
        EXCEPTION WHEN check_violation THEN NULL; END;
    END LOOP;
    PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM contour.comparisons
        WHERE comparison_id='00000000-0000-0000-0000-0000000000d4'),'partial comparison fully rolled back');
    -- A legacy comparison cannot be retrofitted after its commit.
    SET CONSTRAINTS ALL IMMEDIATE;
    PERFORM fixture.expect_state(format('INSERT INTO contour.public_comparison_inputs SELECT * FROM jsonb_populate_record(
        NULL::contour.public_comparison_inputs,%L::jsonb)',to_jsonb(i)||
        '{"comparison_id":"00000000-0000-0000-0000-000000000084"}'::jsonb),'23514');
    -- Use the right slot of a new comparison so existing PKs cannot mask guards.
    INSERT INTO contour.comparisons
        (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
        left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire,public_projection)
        SELECT tenant_id,'00000000-0000-0000-0000-0000000000d5',operation_id,project_id,service_id,environment_id,
            left_kind,left_version_id,left_event_id,right_kind,right_version_id,1,1,result_wire,1
        FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
    -- Keep deferred completeness from masking immediate CHECK/FK failures.
    SET CONSTRAINTS ALL DEFERRED;
    FOR patch,state IN SELECT * FROM (VALUES
        ('{"side":"other"}'::jsonb,'23514'),
        ('{"public_input_id":"00000000-0000-0000-0000-0000000000d2"}'::jsonb,'23514'),
        ('{"environment_id":"00000000-0000-0000-0000-000000ffffff"}'::jsonb,'23503'),
        ('{"version_id":"00000000-0000-0000-0000-000000000053"}'::jsonb,'23503'),
        ('{"input_kind":"approved","approval_event_id":"00000000-0000-0000-0000-000000000063","public_input_id":"00000000-0000-0000-0000-000000000063"}'::jsonb,'23503'),
        ('{"tenant_id":"bbbbbbbb-0000-0000-0000-000000000000"}'::jsonb,'42501')
    ) AS cases(p,s) LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.public_comparison_inputs SELECT * FROM jsonb_populate_record(
            NULL::contour.public_comparison_inputs,%L::jsonb)',to_jsonb(i)||
            '{"comparison_id":"00000000-0000-0000-0000-0000000000d5","side":"right"}'::jsonb||patch),state);
    END LOOP;
END $$;
INSERT INTO contour.comparisons
    (tenant_id,comparison_id,operation_id,project_id,service_id,environment_id,
    left_kind,left_version_id,left_event_id,right_kind,right_version_id,evaluator_version,result_codec_version,result_wire,public_projection)
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000d6',operation_id,project_id,service_id,environment_id,
        'approved',left_version_id,'00000000-0000-0000-0000-000000000061','declared',left_version_id,1,1,result_wire,2
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-0000000000d3';
INSERT INTO contour.public_comparison_inputs
    SELECT tenant_id,'00000000-0000-0000-0000-0000000000d6',side,operation_id,project_id,service_id,environment_id,
        CASE side WHEN 'left' THEN 'approved' ELSE input_kind END,
        CASE side WHEN 'left' THEN '00000000-0000-0000-0000-000000000061'::uuid ELSE public_input_id END,
        declared_contract_id,version_id,
        CASE side WHEN 'left' THEN '00000000-0000-0000-0000-000000000061'::uuid ELSE NULL END
    FROM contour.public_comparison_inputs WHERE comparison_id='00000000-0000-0000-0000-0000000000d3';
SET CONSTRAINTS ALL IMMEDIATE;
SELECT fixture.assert((SELECT public_input_id=approval_event_id AND input_kind='approved'
    FROM contour.public_comparison_inputs WHERE comparison_id='00000000-0000-0000-0000-0000000000d6' AND side='left'),
    'approved public identity is exact immutable event with retained source import');
SELECT fixture.expect_state('UPDATE contour.public_comparison_inputs SET public_input_id=public_input_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.public_comparison_inputs','42501');
SELECT fixture.expect_state('UPDATE contour.comparisons SET public_projection=2','42501');
COMMIT;
\connect contour_fixture postgres
SELECT fixture.expect_state('UPDATE contour.public_comparison_inputs SET public_input_id=public_input_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.public_comparison_inputs','23514');
SELECT fixture.expect_state('UPDATE contour.comparisons SET public_projection=2','23514');
\connect contour_fixture contour_comparison_reader_test
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_comparison_inputs),'reader without context sees no inputs');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.public_comparison_inputs),'cross tenant inputs hidden');
SELECT fixture.expect_state('INSERT INTO contour.public_comparison_inputs DEFAULT VALUES','42501');
ROLLBACK;
