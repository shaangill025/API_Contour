-- Fixture only: provisioning/seed uses administrator; assertions use a real login.
CREATE ROLE contour_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE
    NOCREATEDB NOREPLICATION;
GRANT contour_runtime TO contour_test;
CREATE SCHEMA fixture;
REVOKE ALL ON SCHEMA fixture FROM PUBLIC;
GRANT USAGE ON SCHEMA fixture TO contour_test;
CREATE FUNCTION fixture.assert(ok boolean, label text) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN IF ok IS DISTINCT FROM true THEN RAISE EXCEPTION 'assertion failed: %', label; END IF; END $$;
CREATE FUNCTION fixture.expect_state(command text, expected text) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER SET search_path = pg_catalog AS $$
DECLARE actual text := '00000'; BEGIN
    BEGIN EXECUTE command; EXCEPTION WHEN OTHERS THEN actual := SQLSTATE; END;
    IF actual <> expected THEN RAISE EXCEPTION 'expected SQLSTATE %, got %', expected, actual; END IF;
END $$;
REVOKE ALL ON FUNCTION fixture.assert(boolean, text), fixture.expect_state(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean, text), fixture.expect_state(text, text) TO contour_test;

-- All values are synthetic UUIDs; identifiers are deliberately reused across tenants.
DO $$ DECLARE tenant uuid; item uuid; BEGIN
    FOREACH tenant IN ARRAY ARRAY['aaaaaaaa-0000-0000-0000-000000000000'::uuid,
        'bbbbbbbb-0000-0000-0000-000000000000'::uuid] LOOP
        INSERT INTO contour.tenants VALUES (tenant);
        FOREACH item IN ARRAY ARRAY['00000000-0000-0000-0000-000000000001'::uuid,
            '00000000-0000-0000-0000-000000000002'::uuid] LOOP
            INSERT INTO contour.projects VALUES (tenant, item);
            INSERT INTO contour.services VALUES (tenant, item, item);
            INSERT INTO contour.environments VALUES (tenant, item, item);
            INSERT INTO contour.deployments VALUES (tenant, item, item, item, item);
            INSERT INTO contour.collectors VALUES (tenant, item);
            INSERT INTO contour.workload_assignments VALUES (tenant, item, item, item, item, item);
            INSERT INTO contour.sources VALUES (tenant, item, item, item, item, item, item,
                '00000000-0000-0000-0000-000000000099');
        END LOOP;
    END LOOP;
END $$;
INSERT INTO contour.projects VALUES ('bbbbbbbb-0000-0000-0000-000000000000',
    '00000000-0000-0000-0000-000000000003');
