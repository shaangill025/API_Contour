-- psql must connect as contour_test, not a superuser session with SET ROLE.
SELECT fixture.assert(session_user = 'contour_test' AND current_user = 'contour_test', 'real login');
SELECT fixture.assert(NOT pg_has_role(current_user, 'contour_owner', 'MEMBER'), 'no owner membership');
SELECT fixture.assert(pg_has_role(current_user, 'contour_runtime', 'MEMBER'), 'runtime inheritance');
SELECT fixture.assert(NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication),
    'runtime restricted') FROM pg_roles WHERE rolname = 'contour_runtime';
SELECT fixture.assert(NOT (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication),
    'login restricted') FROM pg_roles WHERE rolname = current_user;
SELECT fixture.assert(NOT has_schema_privilege(current_user, 'contour', 'CREATE'), 'no schema create');
SELECT fixture.assert(NOT has_database_privilege(current_user, current_database(), 'CREATE'), 'no database create');

DO $$ DECLARE relation text; privilege text; flags record; total bigint; BEGIN
    FOREACH relation IN ARRAY ARRAY['tenants', 'projects', 'services', 'environments',
        'deployments', 'collectors', 'workload_assignments', 'sources'] LOOP
        SELECT c.relrowsecurity, c.relforcerowsecurity, r.rolname INTO STRICT flags
            FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            JOIN pg_roles r ON r.oid = c.relowner WHERE n.nspname = 'contour' AND c.relname = relation;
        PERFORM fixture.assert(flags.relrowsecurity AND flags.relforcerowsecurity
            AND flags.rolname = 'contour_owner', 'forced RLS and owner');
        PERFORM fixture.assert(NOT has_table_privilege(current_user, 'contour.' || relation, 'TRUNCATE'), 'no truncate');
        FOREACH privilege IN ARRAY ARRAY['SELECT', 'INSERT', 'UPDATE', 'DELETE'] LOOP
            PERFORM fixture.assert(has_table_privilege(current_user, 'contour.' || relation, privilege),
                'required runtime grant');
        END LOOP;
        EXECUTE format('SELECT count(*) FROM contour.%I', relation) INTO total;
        PERFORM fixture.assert(total = 0, 'no-context visibility');
    END LOOP;
END $$;
SELECT fixture.expect_state($q$INSERT INTO contour.projects VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004')$q$, '42501');
SELECT fixture.expect_state('SELECT * FROM contour.schema_migrations', '42501');
SELECT fixture.expect_state('SET ROLE contour_owner', '42501');
SELECT fixture.expect_state('SET ROLE postgres', '42501');
SELECT fixture.expect_state('SET SESSION AUTHORIZATION postgres', '42501');
SELECT fixture.expect_state('GRANT contour_owner TO contour_test', '42501');
SELECT fixture.expect_state('CREATE ROLE contour_escape', '42501');
SELECT fixture.expect_state('ALTER ROLE contour_runtime BYPASSRLS', '42501');
SELECT fixture.expect_state('CREATE TABLE contour.escape (id integer)', '42501');
SELECT fixture.expect_state('CREATE TABLE public.escape (id integer)', '42501');
SELECT fixture.expect_state('DROP POLICY tenant_scope ON contour.sources', '42501');
SELECT fixture.expect_state('ALTER FUNCTION contour.tenant_context() OWNER TO contour_test', '42501');
SELECT fixture.expect_state('TRUNCATE contour.sources', '42501');
SELECT fixture.expect_state('ALTER TABLE contour.sources DISABLE ROW LEVEL SECURITY', '42501');

BEGIN;
SELECT set_config('apicontour.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000000', true);
SELECT fixture.assert((SELECT count(*) FROM contour.tenants) = 1, 'tenant A scope');
SELECT fixture.assert((SELECT count(*) FROM contour.sources) = 2, 'tenant A sources');
WITH changed AS (UPDATE contour.projects SET project_id = project_id
    WHERE tenant_id = 'bbbbbbbb-0000-0000-0000-000000000000' RETURNING 1)
SELECT fixture.assert((SELECT count(*) FROM changed) = 0, 'tenant B update hidden');
WITH changed AS (DELETE FROM contour.projects
    WHERE tenant_id = 'bbbbbbbb-0000-0000-0000-000000000000' RETURNING 1)
SELECT fixture.assert((SELECT count(*) FROM changed) = 0, 'tenant B delete hidden');
SET LOCAL row_security = off;
SELECT fixture.expect_state('SELECT * FROM contour.sources', '42501');
SET LOCAL row_security = on;
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.projects
    WHERE project_id = '00000000-0000-0000-0000-000000000003'), 'tenant B-only project hidden');
SELECT fixture.expect_state($q$INSERT INTO contour.projects VALUES
    ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004')$q$, '42501');
SELECT fixture.expect_state($q$UPDATE contour.projects SET tenant_id = 'bbbbbbbb-0000-0000-0000-000000000000'
    WHERE project_id = '00000000-0000-0000-0000-000000000001'$q$, '42501');
SELECT fixture.expect_state($q$INSERT INTO contour.services VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000003')$q$, '23503');
SELECT fixture.expect_state($q$INSERT INTO contour.workload_assignments VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$, '23503');
SELECT fixture.expect_state($q$INSERT INTO contour.sources VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002',
    '00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000098')$q$, '23503');
SELECT fixture.expect_state($q$UPDATE contour.sources SET collector_id = '00000000-0000-0000-0000-000000000002',
    source_nonce = '00000000-0000-0000-0000-000000000098'
    WHERE source_id = '00000000-0000-0000-0000-000000000001'$q$, '23503');
SELECT fixture.expect_state($q$INSERT INTO contour.sources VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
    '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000099')$q$, '23505');
COMMIT;
SELECT fixture.assert(contour.tenant_context() IS NULL, 'commit clears transaction tenant');
SELECT fixture.assert((SELECT count(*) FROM contour.sources) = 0, 'commit restores deny');

BEGIN;
SELECT set_config('apicontour.tenant_id', 'bbbbbbbb-0000-0000-0000-000000000000', true);
SELECT fixture.assert((SELECT count(*) FROM contour.projects) = 3, 'tenant B scope reused IDs');
SELECT fixture.assert((SELECT count(*) FROM contour.sources) = 2, 'tenant B sources');
ROLLBACK;
SELECT fixture.assert(contour.tenant_context() IS NULL, 'rollback clears transaction tenant');
SELECT fixture.assert((SELECT count(*) FROM contour.projects) = 0, 'rollback restores deny');

BEGIN;
SELECT set_config('apicontour.tenant_id', '', true);
SELECT fixture.assert((SELECT count(*) FROM contour.tenants) = 0, 'empty context denies');
ROLLBACK;
SELECT 'identity assertions passed' AS result;

BEGIN;
SELECT set_config('apicontour.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000000', true);
WITH changed AS (INSERT INTO contour.projects VALUES
    ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000004') RETURNING 1)
SELECT fixture.assert((SELECT count(*) FROM changed) = 1, 'runtime insert succeeds');
WITH changed AS (UPDATE contour.projects SET project_id = '00000000-0000-0000-0000-000000000005'
    WHERE project_id = '00000000-0000-0000-0000-000000000004' RETURNING 1)
SELECT fixture.assert((SELECT count(*) FROM changed) = 1, 'runtime update succeeds');
WITH changed AS (DELETE FROM contour.projects
    WHERE project_id = '00000000-0000-0000-0000-000000000005' RETURNING 1)
SELECT fixture.assert((SELECT count(*) FROM changed) = 1, 'runtime delete succeeds');
ROLLBACK;
SELECT fixture.assert(contour.tenant_context() IS NULL, 'positive writes clear context');

BEGIN;
SELECT set_config('apicontour.tenant_id', 'invalid-fixture-context', true);
SELECT fixture.expect_state('SELECT * FROM contour.sources', '22P02');
ROLLBACK;
-- SET LOCAL restores any session baseline; the application must never set one.
SELECT set_config('apicontour.tenant_id', 'bbbbbbbb-0000-0000-0000-000000000000', false);
BEGIN;
SELECT set_config('apicontour.tenant_id', 'aaaaaaaa-0000-0000-0000-000000000000', true);
SELECT fixture.assert((SELECT count(*) FROM contour.projects) = 2, 'local override');
COMMIT;
SELECT fixture.assert((SELECT count(*) FROM contour.projects) = 3, 'session baseline restored');
RESET apicontour.tenant_id;
SELECT fixture.assert((SELECT count(*) FROM contour.projects) = 0, 'baseline reset denies');
