-- Each immutable original observation receives an independent opaque identity.
BEGIN;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.observation_windows
    ADD COLUMN observation_id uuid NOT NULL DEFAULT pg_catalog.gen_random_uuid(),
    ADD CONSTRAINT observation_windows_observation_id_key UNIQUE (observation_id),
    ADD CONSTRAINT observation_windows_scoped_observation_key UNIQUE (tenant_id, operation_id, observation_id);
-- transaction failure probe: fixture injects after all DDL.
INSERT INTO contour.schema_migrations(version) VALUES (14);
COMMIT;
