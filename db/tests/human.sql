-- Requires migration 0009 and real restricted metadata logins. No auth claims.
\connect contour_fixture postgres
INSERT INTO contour.tenants VALUES
    ('cccccccc-0000-0000-0000-000000000000'),('dddddddd-0000-0000-0000-000000000000');
INSERT INTO contour.projects VALUES
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c001'),
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c002'),
    ('dddddddd-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000d001');
INSERT INTO contour.services VALUES
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c011','00000000-0000-0000-0000-00000000c001'),
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c012','00000000-0000-0000-0000-00000000c002'),
    ('dddddddd-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000d011','00000000-0000-0000-0000-00000000d001');
\connect contour_fixture contour_human_provisioner_test
SELECT fixture.assert(session_user='contour_human_provisioner_test','real human provisioner login');
DO $$ DECLARE relation text; role_name text; BEGIN
    FOREACH role_name IN ARRAY ARRAY['contour_human_provisioner','contour_human_lookup'] LOOP
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_auth_members WHERE member=role_name::regrole),
            'human metadata groups inherit no roles');
        PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=role_name
            AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin)),
            'restricted nonlogin human metadata groups');
        FOREACH relation IN ARRAY ARRAY['human_actors','human_identities','human_tenant_memberships',
            'human_project_memberships','human_service_roles'] LOOP
            PERFORM fixture.assert(EXISTS(SELECT 1 FROM pg_class WHERE oid=('contour.'||relation)::regclass
                AND relowner='contour_owner'::regrole AND relrowsecurity AND relforcerowsecurity),
                'forced owner human metadata RLS');
            PERFORM fixture.assert(has_table_privilege(role_name,'contour.'||relation,'SELECT')
                AND NOT has_table_privilege(role_name,'contour.'||relation,'DELETE,TRUNCATE'),
                'metadata readable without deletion authority');
            PERFORM fixture.assert(has_table_privilege(role_name,'contour.'||relation,'INSERT')
                =(role_name='contour_human_provisioner')
                AND has_column_privilege(role_name,'contour.'||relation,'enabled','UPDATE')
                =(role_name='contour_human_provisioner'), 'provisioning and enabling isolated');
            PERFORM fixture.assert(NOT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=('contour.'||relation)::regclass
                AND a.attnum>0 AND NOT a.attisdropped AND a.attname<>CASE WHEN role_name='contour_human_lookup' THEN 'actor_id' ELSE 'enabled' END
                AND has_column_privilege(role_name,a.attrelid,a.attname,'UPDATE')),
                'identity and scope keys cannot be reassigned');
        END LOOP;
        FOREACH relation IN ARRAY ARRAY['tenants','projects','services','collectors','sources',
            'declared_versions','approval_events','approval_heads','comparisons','review_requests',
            'review_decisions','ingestion_payloads','policy_revisions'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'metadata role has no business authority');
        END LOOP;
    END LOOP;
    FOREACH role_name IN ARRAY ARRAY['contour_runtime','contour_admin','contour_ingestion',
        'contour_catalog_worker','contour_catalog_reader','contour_declared_writer','contour_declared_reader',
        'contour_approval_writer','contour_approval_reader','contour_comparison_writer','contour_comparison_reader',
        'contour_review_writer','contour_review_reader'] LOOP
        FOREACH relation IN ARRAY ARRAY['human_actors','human_identities','human_tenant_memberships',
            'human_project_memberships','human_service_roles'] LOOP
            PERFORM fixture.assert(NOT has_table_privilege(role_name,'contour.'||relation,
                'SELECT,INSERT,UPDATE,DELETE,TRUNCATE'),'existing role human privileges unchanged');
        END LOOP;
    END LOOP;
END $$;
INSERT INTO contour.human_actors(actor_id) VALUES
    ('00000000-0000-0000-0000-000000000071'),('00000000-0000-0000-0000-00000000c072');
SELECT fixture.assert((SELECT bool_and(NOT enabled) FROM contour.human_actors),'new actors disabled by default');
SELECT fixture.expect_state($q$INSERT INTO contour.human_actors(actor_id)
    VALUES('00000000-0000-0000-0000-000000000071')$q$,'23505');
BEGIN;
INSERT INTO contour.human_actors(actor_id) VALUES('00000000-0000-0000-0000-00000000c073');
ROLLBACK;
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.human_actors
    WHERE actor_id='00000000-0000-0000-0000-00000000c073'),'rolled back actor not enrolled');
INSERT INTO contour.human_identities(issuer,subject,actor_id) VALUES
    ('https://issuer.example','Alice','00000000-0000-0000-0000-000000000071'),
    ('https://issuer.example','alice','00000000-0000-0000-0000-00000000c072'),
    ('https://Issuer.example','Alice','00000000-0000-0000-0000-00000000c072'),
    ('https://other.example','Alice','00000000-0000-0000-0000-00000000c072'),
    ('https://issuer.example',' spaced subject ','00000000-0000-0000-0000-000000000071');
SELECT fixture.assert((SELECT count(*)=5 AND bool_and(NOT enabled) FROM contour.human_identities),
    'exact case-sensitive issuer subject pairs and default-disabled identities');
SELECT fixture.expect_state($q$INSERT INTO contour.human_identities(issuer,subject,actor_id)
    VALUES('https://issuer.example','Alice','00000000-0000-0000-0000-00000000c072')$q$,'23505');
SELECT fixture.expect_state($q$INSERT INTO contour.human_identities(issuer,subject,actor_id)
    VALUES('https://missing.example','Alice','00000000-0000-0000-0000-00000000ffff')$q$,'23503');
DO $$ DECLARE column_name text; value text; BEGIN
    FOREACH column_name IN ARRAY ARRAY['issuer','subject'] LOOP
        FOREACH value IN ARRAY ARRAY['',E'line\nbreak',repeat('a',CASE WHEN column_name='issuer' THEN 1025 ELSE 256 END)] LOOP
            PERFORM fixture.expect_state(format('INSERT INTO contour.human_identities(issuer,subject,actor_id)
                VALUES(%L,%L,%L)',CASE WHEN column_name='issuer' THEN value ELSE 'https://bounded.example' END,
                CASE WHEN column_name='subject' THEN value ELSE 'bounded' END,
                '00000000-0000-0000-0000-000000000071'),'23514');
        END LOOP;
    END LOOP;
END $$;
SELECT fixture.expect_state($q$INSERT INTO contour.human_identities(issuer,subject,actor_id)
    VALUES('https://issuer.example','é','00000000-0000-0000-0000-000000000071')$q$,'23514');
INSERT INTO contour.human_identities(issuer,subject,actor_id)
    VALUES(repeat('a',1024),repeat('b',255),'00000000-0000-0000-0000-000000000071');
INSERT INTO contour.human_tenant_memberships(tenant_id,actor_id) VALUES
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000071'),
    ('dddddddd-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000071');
INSERT INTO contour.human_project_memberships(tenant_id,project_id,actor_id) VALUES
    ('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c001','00000000-0000-0000-0000-000000000071'),
    ('dddddddd-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000d001','00000000-0000-0000-0000-000000000071');
INSERT INTO contour.human_service_roles(tenant_id,project_id,service_id,actor_id,role)
    SELECT 'cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c001',
        '00000000-0000-0000-0000-00000000c011','00000000-0000-0000-0000-000000000071',role
    FROM unnest(ARRAY['viewer','service_owner','policy_administrator','operator','security_reviewer']) role;
INSERT INTO contour.human_service_roles(tenant_id,project_id,service_id,actor_id,role)
    VALUES('dddddddd-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000d001',
        '00000000-0000-0000-0000-00000000d011','00000000-0000-0000-0000-000000000071','viewer');
-- Each invalid child isolates a missing membership or wrong existing scope.
SELECT fixture.expect_state($q$INSERT INTO contour.human_tenant_memberships(tenant_id,actor_id)
    VALUES('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000ffff')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.human_tenant_memberships(tenant_id,actor_id)
    VALUES('eeeeeeee-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000071')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.human_project_memberships(tenant_id,project_id,actor_id)
    VALUES('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000c001',
        '00000000-0000-0000-0000-00000000c072')$q$,'23503');
SELECT fixture.expect_state($q$INSERT INTO contour.human_project_memberships(tenant_id,project_id,actor_id)
    VALUES('cccccccc-0000-0000-0000-000000000000','00000000-0000-0000-0000-00000000d001',
        '00000000-0000-0000-0000-000000000071')$q$,'23503');
DO $$ DECLARE row contour.human_service_roles; patch jsonb; candidate jsonb; expected text; BEGIN
    SELECT * INTO row FROM contour.human_service_roles WHERE tenant_id='cccccccc-0000-0000-0000-000000000000' AND role='viewer';
    FOR patch,expected IN SELECT * FROM (VALUES
        ('{"role":"owner"}'::jsonb,'23514'),
        ('{"role":"*"}'::jsonb,'23514'),
        ('{"role":"Viewer"}'::jsonb,'23514'),
        ('{"actor_id":"00000000-0000-0000-0000-00000000c072"}'::jsonb,'23503'),
        ('{"service_id":"00000000-0000-0000-0000-00000000c012"}'::jsonb,'23503'),
        ('{"project_id":"00000000-0000-0000-0000-00000000c002","service_id":"00000000-0000-0000-0000-00000000c012"}'::jsonb,'23503'),
        ('{"tenant_id":"dddddddd-0000-0000-0000-000000000000"}'::jsonb,'23503'),
        ('{}'::jsonb,'23505')
    ) cases(change,state) LOOP
        candidate=to_jsonb(row)||patch;
        PERFORM fixture.expect_state(format('INSERT INTO contour.human_service_roles
            SELECT * FROM jsonb_populate_record(NULL::contour.human_service_roles,%L::jsonb)',candidate),expected);
    END LOOP;
END $$;
SELECT fixture.assert((SELECT bool_and(NOT enabled) FROM contour.human_tenant_memberships)
    AND (SELECT bool_and(NOT enabled) FROM contour.human_project_memberships)
    AND (SELECT bool_and(NOT enabled) FROM contour.human_service_roles),'memberships and roles default disabled');
-- Operator can toggle only enabled flags, never identity or scope keys.
UPDATE contour.human_actors SET enabled=true;
UPDATE contour.human_identities SET enabled=true;
UPDATE contour.human_tenant_memberships SET enabled=true;
UPDATE contour.human_project_memberships SET enabled=true;
UPDATE contour.human_service_roles SET enabled=true;
UPDATE contour.human_actors SET enabled=false WHERE actor_id='00000000-0000-0000-0000-000000000071';
UPDATE contour.human_identities SET enabled=false WHERE issuer='https://issuer.example' AND subject='Alice';
UPDATE contour.human_tenant_memberships SET enabled=false WHERE tenant_id='cccccccc-0000-0000-0000-000000000000';
UPDATE contour.human_project_memberships SET enabled=false WHERE tenant_id='cccccccc-0000-0000-0000-000000000000';
UPDATE contour.human_service_roles SET enabled=false WHERE tenant_id='cccccccc-0000-0000-0000-000000000000' AND role='service_owner';
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['human_actors','human_identities','human_tenant_memberships',
        'human_project_memberships','human_service_roles'] LOOP
        PERFORM fixture.expect_state('DELETE FROM contour.'||relation,'42501');
        PERFORM fixture.expect_state('TRUNCATE contour.'||relation,'42501');
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET actor_id=actor_id','42501');
    END LOOP;
END $$;
SELECT fixture.expect_state('UPDATE contour.human_identities SET issuer=issuer','42501');
SELECT fixture.expect_state('UPDATE contour.human_identities SET subject=subject','42501');
SELECT fixture.expect_state('UPDATE contour.human_service_roles SET role=role','42501');
SELECT fixture.expect_state('SET ROLE contour_owner','42501');
SELECT fixture.expect_state('SET ROLE contour_runtime','42501');
SELECT fixture.expect_state('ALTER TABLE contour.human_actors DISABLE ROW LEVEL SECURITY','42501');
SELECT fixture.expect_state('SELECT * FROM contour.approval_heads','42501');
\connect contour_fixture contour_human_lookup_test
SELECT fixture.assert(session_user='contour_human_lookup_test','real pretenant human lookup login');
SELECT fixture.assert(nullif(current_setting('apicontour.tenant_id',true),'') IS NULL,'lookup starts before tenant context');
SELECT fixture.assert((SELECT count(*)=2 FROM contour.human_tenant_memberships),
    'trusted pretenant lookup intentionally reads metadata across tenants');
SELECT fixture.assert((SELECT NOT enabled FROM contour.human_actors WHERE actor_id='00000000-0000-0000-0000-000000000071')
    AND (SELECT NOT enabled FROM contour.human_identities WHERE issuer='https://issuer.example' AND subject='Alice')
    AND (SELECT NOT enabled FROM contour.human_tenant_memberships WHERE tenant_id='cccccccc-0000-0000-0000-000000000000')
    AND (SELECT NOT enabled FROM contour.human_project_memberships WHERE tenant_id='cccccccc-0000-0000-0000-000000000000')
    AND (SELECT NOT enabled FROM contour.human_service_roles WHERE tenant_id='cccccccc-0000-0000-0000-000000000000' AND role='service_owner'),
    'disabled flags persist independently, adapter authorization remains separate');
SELECT fixture.assert((SELECT count(*)=5 FROM contour.human_service_roles WHERE tenant_id='cccccccc-0000-0000-0000-000000000000')
    AND (SELECT count(*)=1 AND bool_and(role='viewer') FROM contour.human_service_roles WHERE tenant_id='dddddddd-0000-0000-0000-000000000000'),
    'additive role records retain exact service scope without wildcard expansion');
DO $$ DECLARE relation text; BEGIN
    FOREACH relation IN ARRAY ARRAY['human_actors','human_identities','human_tenant_memberships',
        'human_project_memberships','human_service_roles'] LOOP
        PERFORM fixture.expect_state('INSERT INTO contour.'||relation||' DEFAULT VALUES','42501');
        -- The narrow actor column grant permits locks, never actual mutation.
        EXECUTE 'SELECT actor_id FROM contour.'||relation||' FOR SHARE';
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET actor_id=actor_id','23514');
        PERFORM fixture.expect_state('UPDATE contour.'||relation||' SET enabled=true','42501');
        PERFORM fixture.expect_state('DELETE FROM contour.'||relation,'42501');
        PERFORM fixture.expect_state('TRUNCATE contour.'||relation,'42501');
    END LOOP;
END $$;
SELECT fixture.expect_state('SELECT * FROM contour.review_decisions','42501');
SELECT fixture.expect_state('SELECT * FROM contour.collectors','42501');
SELECT fixture.expect_state('SET ROLE contour_human_provisioner','42501');
-- Setting a tenant does not turn this trusted metadata role into a tenant-user role.
BEGIN;
SELECT set_config('apicontour.tenant_id','cccccccc-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=2 FROM contour.human_tenant_memberships),'lookup policy is explicitly pretenant');
ROLLBACK;
\connect contour_fixture postgres
SELECT fixture.assert((SELECT count(*)=1 AND bool_and(actor_id='00000000-0000-0000-0000-000000000071')
    FROM contour.review_decisions WHERE review_id='00000000-0000-0000-0000-000000000091'),
    'disabling human metadata preserves immutable actor decision history');
-- Default NO ACTION references block cascading removal even for privileged DELETE.
SELECT fixture.expect_state($q$DELETE FROM contour.human_actors
    WHERE actor_id='00000000-0000-0000-0000-000000000071'$q$,'23503');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid IN
    ('contour.human_identities'::regclass,'contour.human_tenant_memberships'::regclass,
    'contour.human_project_memberships'::regclass,'contour.human_service_roles'::regclass)
    AND contype='f' AND confdeltype<>'a'),'human metadata foreign keys never cascade');
