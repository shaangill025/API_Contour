-- Preserve body/status/media identity without guessing it for legacy manifests.
BEGIN;
SET LOCAL ROLE contour_owner;
ALTER TABLE contour.public_declared_contracts ADD COLUMN projection_version smallint
    NOT NULL DEFAULT 1 CHECK (projection_version IN (1,2));
ALTER TABLE contour.public_declared_members
    ADD COLUMN body_selector text CHECK (body_selector='request'
        OR body_selector='response:default'
        OR body_selector ~ '^response:[1-5]([0-9][0-9]|XX)$'),
    ADD COLUMN media_type text CHECK (octet_length(media_type) <= 128
        AND media_type ~ '^[A-Za-z0-9!#$%&''*+.^_`|~-]+/[A-Za-z0-9!#$%&''*+.^_`|~-]+$'),
    ADD CONSTRAINT unique_public_body_selector UNIQUE
        (tenant_id,contract_id,operation_id,body_selector,media_type);
GRANT INSERT (projection_version) ON contour.public_declared_contracts TO contour_declared_writer;

CREATE OR REPLACE FUNCTION contour.check_public_contract_members() RETURNS trigger
LANGUAGE plpgsql SET search_path=pg_catalog,contour AS $$
DECLARE expected integer; actual bigint; projection smallint; invalid boolean;
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM contour.tenant_context() THEN
        RAISE EXCEPTION 'contract tenant context required' USING ERRCODE='42501';
    END IF;
    SELECT member_count,projection_version INTO expected,projection
        FROM contour.public_declared_contracts
        WHERE tenant_id=NEW.tenant_id AND contract_id=NEW.contract_id;
    SELECT count(*),coalesce(bool_or(CASE projection
        WHEN 1 THEN body_selector IS NOT NULL OR media_type IS NOT NULL
        WHEN 2 THEN body_selector IS NULL OR media_type IS NULL
        ELSE true END),false) INTO actual,invalid
        FROM contour.public_declared_members
        WHERE tenant_id=NEW.tenant_id AND contract_id=NEW.contract_id;
    IF expected IS NULL OR actual <> expected OR invalid THEN
        RAISE EXCEPTION 'incomplete contract membership' USING ERRCODE='23514';
    END IF;
    RETURN NEW;
END $$;
-- Existing function privileges, immutable triggers, exact-scope FKs and RLS remain.
-- transaction failure probe: fixture injects after DDL, function and grant changes.
INSERT INTO contour.schema_migrations(version) VALUES (11);
COMMIT;
