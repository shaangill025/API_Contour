-- Provisioning administrator only. No inherited application roles.
BEGIN;
CREATE ROLE contour_v2_ingress NOLOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
COMMIT;
