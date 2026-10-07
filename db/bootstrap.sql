-- Run with a provisioning administrator, never the application login.
BEGIN;
CREATE ROLE contour_owner NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEROLE
    NOCREATEDB NOREPLICATION;
CREATE ROLE contour_runtime NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$ BEGIN
    EXECUTE format('GRANT CREATE ON DATABASE %I TO contour_owner', current_database());
    EXECUTE format('GRANT CONNECT ON DATABASE %I TO contour_runtime', current_database());
END $$;
COMMIT;
