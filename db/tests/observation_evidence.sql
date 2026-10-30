-- Run after upgrading a database populated by catalog.sql.
\connect contour_fixture contour_catalog_worker_test
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT count(*)=2 AND count(DISTINCT observation_id)=2 FROM contour.observation_windows),
    'existing observation has an identity after upgrade');
CREATE TEMP TABLE original_evidence AS SELECT * FROM contour.observation_windows
    WHERE record_id='00000000-0000-0000-0000-000000000001';
-- Replay of the original source key must not replace its persisted identity.
INSERT INTO contour.observation_windows SELECT * FROM original_evidence ON CONFLICT DO NOTHING;
SELECT fixture.assert((SELECT count(*)=1 AND min(observation_id::text)=(SELECT observation_id::text FROM original_evidence)
    FROM contour.observation_windows WHERE record_id='00000000-0000-0000-0000-000000000001'), 'duplicate delivery preserves original identity');
-- New source records get independent IDs even when they share a variant.
INSERT INTO contour.observation_windows (tenant_id,collector_id,batch_id,record_id,operation_id,variant_id,
    source_id,project_id,service_id,environment_id,deployment_id,observation_count,sample_numerator,
    sample_denominator,visibility,completeness,reasons,route_uncertain,status_code,first_seen,last_seen,
    queued_at,expires_at,request_header_names,response_header_names,query_parameter_names)
SELECT tenant_id,collector_id,batch_id,'00000000-0000-0000-0000-000000000098',operation_id,variant_id,
    source_id,project_id,service_id,environment_id,deployment_id,observation_count,sample_numerator,
    sample_denominator,visibility,completeness,reasons,route_uncertain,status_code,first_seen,last_seen,
    queued_at,expires_at,request_header_names,response_header_names,query_parameter_names FROM original_evidence;
SELECT fixture.assert((SELECT count(*)=3 AND count(DISTINCT observation_id)=3 AND count(DISTINCT variant_id)=1
    FROM contour.observation_windows), 'new record identity is distinct from variant identity');
-- The second operation has the same workload and a valid matching variant.
-- Reusing the ID here conflicts only with global, not tenant/operation uniqueness.
INSERT INTO contour.operations SELECT tenant_id,'00000000-0000-0000-0000-000000000098',
    decode(repeat('98',32),'hex'),identity_version,canonical_key,project_id,service_id,environment_id
    FROM contour.operations WHERE operation_id='00000000-0000-0000-0000-000000000001';
INSERT INTO contour.variants SELECT tenant_id,'00000000-0000-0000-0000-000000000098',
    '00000000-0000-0000-0000-000000000098',collector_id,policy_revision,parser_profile,
    canonicalization_version,structure_hash,canonical_structure,structure_wire
    FROM contour.variants WHERE variant_id='00000000-0000-0000-0000-000000000001';
DO $$ DECLARE row contour.observation_windows; violated text; BEGIN
    SELECT * INTO row FROM original_evidence;
    row.record_id := '00000000-0000-0000-0000-000000000093';
    row.operation_id := '00000000-0000-0000-0000-000000000098';
    row.variant_id := '00000000-0000-0000-0000-000000000098';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'global identity reused across operations';
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS violated = CONSTRAINT_NAME;
        IF violated <> 'observation_windows_observation_id_key' THEN
            RAISE EXCEPTION 'unexpected uniqueness constraint: %', violated;
        END IF;
    END;
END $$;
DO $$ DECLARE row contour.observation_windows; BEGIN
    SELECT * INTO row FROM original_evidence;
    row.record_id := '00000000-0000-0000-0000-000000000097';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'identity rebound to another record';
    EXCEPTION WHEN unique_violation THEN NULL; END;
    row.observation_id := pg_catalog.gen_random_uuid();
    row.operation_id := '00000000-0000-0000-0000-000000000002';
    BEGIN INSERT INTO contour.observation_windows SELECT row.*;
        RAISE EXCEPTION 'identity accepted with mismatched operation';
    EXCEPTION WHEN foreign_key_violation THEN NULL; END;
END $$;
SELECT fixture.expect_state('UPDATE contour.observation_windows SET observation_id=gen_random_uuid()','42501');
SELECT fixture.expect_state('UPDATE contour.observation_windows SET observation_count=2','42501');
COMMIT;
\connect contour_fixture contour_catalog_reader_test
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.observation_windows), 'other tenant cannot read identities');
ROLLBACK;
