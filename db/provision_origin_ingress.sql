-- Provisioning administrator only; independent of all application roles.
BEGIN;
CREATE ROLE contour_origin_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
COMMIT;
