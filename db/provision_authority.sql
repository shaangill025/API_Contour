-- Provisioning administrator only; migration grants remain transactional.
BEGIN;
CREATE ROLE contour_admin NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE
    NOCREATEDB NOREPLICATION;
CREATE ROLE contour_ingestion NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE
    NOCREATEDB NOREPLICATION;
GRANT contour_runtime TO contour_admin, contour_ingestion;
COMMIT;
