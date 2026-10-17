-- Requires the committed comparison fixture and real restricted review logins.
\connect contour_fixture postgres
-- Valid immutable events isolate candidate and predecessor mismatches.
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000065',operation_id,project_id,service_id,
        environment_id,'00000000-0000-0000-0000-000000000051',expected_event_id,actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000063';
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000066',operation_id,project_id,service_id,
        environment_id,version_id,actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000063';
-- A valid different-operation event necessarily has a different candidate: the
-- declared-version scoped FK prevents a scope-only mismatch for the same version.
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000067',operation_id,project_id,service_id,
        environment_id,version_id,'00000000-0000-0000-0000-000000000071'
    FROM contour.declared_versions WHERE version_id='00000000-0000-0000-0000-000000000052';
SELECT fixture.expect_state($q$INSERT INTO contour.approval_events
    (tenant_id,event_id,operation_id,project_id,service_id,environment_id,version_id,actor_id)
    SELECT e.tenant_id,'00000000-0000-0000-0000-000000000068',v.operation_id,v.project_id,v.service_id,
        v.environment_id,e.version_id,e.actor_id FROM contour.approval_events e CROSS JOIN contour.declared_versions v
    WHERE e.event_id='00000000-0000-0000-0000-000000000066'
        AND v.version_id='00000000-0000-0000-0000-000000000052'$q$,'23503');
\connect contour_fixture contour_review_writer_test
SELECT fixture.assert(session_user='contour_review_writer_test','real review writer');
DO $$ DECLARE role_name text; relation text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_review_writer','contour_review_reader'] LOOP
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role_name::regrole),
            'review groups inherit nothing');
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted nonlogin review groups');
        FOREACH relation IN ARRAY ARRAY['review_requests','review_decisions'] LOOP
            PERFORM fixture.assert(has_table_privilege(role_name,'contour.'||relation,'SELECT')
                AND NOT has_table_privilege(role_name,'contour.'||relation,'UPDATE,DELETE,TRUNCATE'),
                'append-only review privileges');
            PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid=('contour.'||relation)::regclass
                AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),
                'forced owner review RLS');
        END LOOP;
        PERFORM fixture.assert(NOT has_column_privilege(role_name,'contour.review_requests','created_at','INSERT')
            AND NOT has_column_privilege(role_name,'contour.review_requests','revision','INSERT')
            AND NOT has_column_privilege(role_name,'contour.review_decisions','decided_at','INSERT')
            AND NOT has_column_privilege(role_name,'contour.review_decisions','revision','INSERT'),
            'protected server timestamps and revisions');
        FOREACH relation IN ARRAY ARRAY['approval_heads','declared_versions','ingestion_payloads',
            'observation_windows','policy_revisions'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'no heads graph or capture access');
        END LOOP;
    END LOOP;
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin','contour_ingestion',
        'contour_catalog_worker','contour_catalog_reader','contour_declared_writer','contour_declared_reader',
        'contour_approval_writer','contour_approval_reader','contour_comparison_writer','contour_comparison_reader'] LOOP
        PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.review_requests',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE') AND NOT has_table_privilege(role_name,'contour.review_decisions',
            'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'existing role privileges unchanged');
    END LOOP;
END $$;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.review_requests),'missing tenant context');
SELECT fixture.expect_state($q$INSERT INTO contour.review_requests
    (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
        comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000099',
        '00000000-0000-0000-0000-000000000051','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000081','00000000-0000-0000-0000-000000000053',
        '00000000-0000-0000-0000-000000000061','00000000-0000-0000-0000-000000000071')$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000099',
        'reject',1,'00000000-0000-0000-0000-000000000071')$q$,'42501');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
-- Baseline is the left input; the declared candidate must be the right input.
INSERT INTO contour.review_requests (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
    comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000091',operation_id,project_id,service_id,environment_id,
        comparison_id,right_version_id,left_event_id,'00000000-0000-0000-0000-000000000071'
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
INSERT INTO contour.review_requests (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
    comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000092',operation_id,project_id,service_id,environment_id,
        comparison_id,right_version_id,left_event_id,'00000000-0000-0000-0000-000000000072'
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000081';
INSERT INTO contour.review_requests (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
    comparison_id,candidate_version_id,creator_actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000093',operation_id,project_id,service_id,environment_id,
        comparison_id,right_version_id,'00000000-0000-0000-0000-000000000071'
    FROM contour.comparisons WHERE comparison_id='00000000-0000-0000-0000-000000000084';
SELECT fixture.assert((SELECT count(*)=3 AND bool_and(revision=1)
    AND bool_and(created_at BETWEEN transaction_timestamp() AND clock_timestamp()) FROM contour.review_requests),
    'pending reviews revision one with server creation time');
DO $$ DECLARE row contour.review_requests; patch jsonb; expected text; candidate jsonb; BEGIN
    SELECT * INTO row FROM contour.review_requests WHERE review_id='00000000-0000-0000-0000-000000000091';
    FOR patch,expected IN SELECT * FROM (VALUES
        ('{"candidate_version_id":"00000000-0000-0000-0000-000000000051"}'::jsonb,'23503'),
        ('{"comparison_id":"00000000-0000-0000-0000-000000000082"}'::jsonb,'23503'),
        ('{"comparison_id":"00000000-0000-0000-0000-000000000085"}'::jsonb,'23503'),
        ('{"candidate_version_id":"00000000-0000-0000-0000-000000000052"}'::jsonb,'23503'),
        ('{"expected_event_id":"00000000-0000-0000-0000-000000000063"}'::jsonb,'23503'),
        ('{"expected_event_id":null}'::jsonb,'23503'),
        ('{"comparison_id":"00000000-0000-0000-0000-000000000084"}'::jsonb,'23503'),
        ('{"operation_id":"00000000-0000-0000-0000-000000000052"}'::jsonb,'23503'),
        ('{"project_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"service_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"environment_id":"00000000-0000-0000-0000-000000000002"}'::jsonb,'23503'),
        ('{"tenant_id":"bbbbbbbb-0000-0000-0000-000000000000"}'::jsonb,'42501')
    ) cases(change,state) LOOP
        candidate=to_jsonb(row)||jsonb_build_object('review_id','00000000-0000-0000-0000-000000000094')||patch;
        PERFORM fixture.expect_state(format('INSERT INTO contour.review_requests
            (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
            comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
            SELECT tenant_id,review_id,operation_id,project_id,service_id,environment_id,
            comparison_id,candidate_version_id,expected_event_id,creator_actor_id
            FROM jsonb_populate_record(NULL::contour.review_requests,%L::jsonb)',candidate),expected);
    END LOOP;
END $$;
-- Exact event63 is candidate53 replacing event61 with actor71.
-- Each valid event changes one association component from event63, except scope:
-- the existing version FK makes a scope-only valid event impossible.
DO $$ DECLARE event uuid; BEGIN
    FOREACH event IN ARRAY ARRAY['00000000-0000-0000-0000-000000000065'::uuid,
        '00000000-0000-0000-0000-000000000066'::uuid,'00000000-0000-0000-0000-000000000067'::uuid] LOOP
        PERFORM fixture.expect_state(format('INSERT INTO contour.review_decisions
            (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
            VALUES (%L,%L,''approve'',1,%L,%L)',
            'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000091',
            '00000000-0000-0000-0000-000000000071',event),'23503');
    END LOOP;
END $$;
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000091',
        'approve',1,'00000000-0000-0000-0000-000000000072','00000000-0000-0000-0000-000000000063')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000091',
        'approve',1,'00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000061')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000093',
        'approve',1,'00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000063')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'reject',1,'00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000063')$q$,'23514');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000099',
        'reject',1,'00000000-0000-0000-0000-000000000071')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'reject',1,'00000000-0000-0000-0000-000000000071')$q$,'42501');
INSERT INTO contour.review_decisions (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000091',
        'approve',1,'00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000063');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id,approval_event_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'approve',1,'00000000-0000-0000-0000-000000000071','00000000-0000-0000-0000-000000000063')$q$,'23505');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'reject',2,'00000000-0000-0000-0000-000000000071')$q$,'23514');
INSERT INTO contour.review_decisions (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'reject',1,'00000000-0000-0000-0000-000000000072');
SELECT fixture.expect_state($q$INSERT INTO contour.review_decisions
    (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000092',
        'reject',1,'00000000-0000-0000-0000-000000000071')$q$,'23505');
SELECT fixture.assert((SELECT count(*)=2 AND bool_and(revision=2) AND bool_and(expected_revision=1)
    AND bool_and(decided_at BETWEEN transaction_timestamp() AND clock_timestamp()) FROM contour.review_decisions),
    'only terminal revision two and server decision time');
SELECT fixture.assert((SELECT review_id='00000000-0000-0000-0000-000000000091'
    FROM contour.review_requests WHERE review_id='00000000-0000-0000-0000-000000000091' FOR UPDATE),
    'writer can lock immutable request for decision CAS');
SELECT fixture.expect_state('UPDATE contour.review_requests SET review_id=review_id','23514');
SELECT fixture.expect_state('UPDATE contour.review_requests SET creator_actor_id=creator_actor_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.review_requests','42501');
SELECT fixture.expect_state('TRUNCATE contour.review_requests','42501');
SELECT fixture.expect_state('UPDATE contour.review_decisions SET actor_id=actor_id','42501');
SELECT fixture.expect_state('DELETE FROM contour.review_decisions','42501');
SELECT fixture.expect_state('TRUNCATE contour.review_decisions','42501');
SELECT fixture.expect_state('INSERT INTO contour.review_requests(created_at) VALUES(now())','42501');
SELECT fixture.expect_state('INSERT INTO contour.review_decisions(revision) VALUES(3)','42501');
COMMIT;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.review_requests),'commit clears context');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.review_decisions (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000093',
        'reject',1,'00000000-0000-0000-0000-000000000071');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.review_requests (tenant_id,review_id,operation_id,project_id,service_id,environment_id,
    comparison_id,candidate_version_id,expected_event_id,creator_actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000094',operation_id,project_id,service_id,environment_id,
        comparison_id,candidate_version_id,expected_event_id,creator_actor_id
    FROM contour.review_requests WHERE review_id='00000000-0000-0000-0000-000000000091';
INSERT INTO contour.review_decisions (tenant_id,review_id,decision,expected_revision,actor_id)
    VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000094',
        'reject',1,'00000000-0000-0000-0000-000000000071');
ROLLBACK;
\connect contour_fixture contour_review_reader_test
SELECT fixture.assert(session_user='contour_review_reader_test','real review reader');
SELECT fixture.expect_state('INSERT INTO contour.review_requests DEFAULT VALUES','42501');
SELECT fixture.expect_state('INSERT INTO contour.review_decisions DEFAULT VALUES','42501');
SELECT fixture.expect_state('SELECT * FROM contour.approval_heads','42501');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.review_requests),'reader absent context');
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.review_requests)
    AND NOT EXISTS(SELECT 1 FROM contour.review_decisions),'other tenant hidden');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=3 FROM contour.review_requests)
    AND (SELECT count(*)=2 FROM contour.review_decisions)
    AND NOT EXISTS(SELECT 1 FROM contour.review_decisions WHERE review_id='00000000-0000-0000-0000-000000000093'),
    'rollback leaves pending request without decision audit');
SELECT fixture.assert((SELECT r.revision=1 AND d.revision=2 AND d.actor_id='00000000-0000-0000-0000-000000000072'
    AND d.approval_event_id IS NULL FROM contour.review_requests r JOIN contour.review_decisions d
    USING (tenant_id,review_id) WHERE review_id='00000000-0000-0000-0000-000000000092'),
    'rejected review retains independent creator and deciding actor');
ROLLBACK;
\connect contour_fixture postgres
SELECT fixture.expect_state('UPDATE contour.review_requests SET creator_actor_id=creator_actor_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.review_requests','23514');
SELECT fixture.expect_state('UPDATE contour.review_decisions SET actor_id=actor_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.review_decisions','23514');
SELECT fixture.assert((SELECT current_event_id='00000000-0000-0000-0000-000000000063'
    FROM contour.approval_heads WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'),
    'review rejection and rollback do not change approval head');
