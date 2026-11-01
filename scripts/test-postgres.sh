#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
image='postgres@sha256:0ea6700a3b4f0ae6ce746519073558aed4d88a79d8d07622a9a644946c7319c4'
name="contour-identity-${$}-${RANDOM}"
container_id=''
cleanup() {
    if [[ -n "$container_id" ]]; then docker rm -f "$container_id" >/dev/null; fi
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# No pulls, host mounts or TCP. Password is inert fixture data; host auth rejects.
docker image inspect "$image" >/dev/null
container_id=$(docker run -d --name "$name" --label apicontour.fixture=identity \
    --network none --memory 512m --cpus 1 --pids-limit 128 \
    --tmpfs /var/lib/postgresql/data:rw,nosuid,noexec,size=256m \
    -e POSTGRES_DB=contour_fixture -e POSTGRES_PASSWORD=isolated-fixture-only \
    -e POSTGRES_HOST_AUTH_METHOD=reject \
    -e 'POSTGRES_INITDB_ARGS=--auth-local=trust --auth-host=reject' \
    "$image" -c listen_addresses= -c unix_socket_directories=/var/run/postgresql)

ready=false
for ((attempt = 0; attempt < 120; attempt++)); do
    # PID 1 becomes postgres only after entrypoint initialization has finished.
    if docker exec "$container_id" sh -c 'test "$(cat /proc/1/comm)" = postgres && pg_isready -h /var/run/postgresql -U postgres -d contour_fixture' >/dev/null 2>&1; then
        ready=true; break
    fi
    sleep 0.5
done
if [[ "$ready" != true ]]; then echo 'PostgreSQL fixture readiness timed out' >&2; exit 1; fi

admin_sql() {
    docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
        -h /var/run/postgresql -U postgres -d contour_fixture
}
admin_sql < "$root/db/bootstrap.sql"
# Exercise a genuine failure after schema/table DDL, then assert atomic rollback.
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0001_identity.sql" | admin_sql; then
    echo 'Injected migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'contour') THEN
        RAISE EXCEPTION 'failed migration left partial schema';
    END IF;
END $$;
SQL
admin_sql < "$root/db/migrations/0001_identity.sql"
admin_sql <<'SQL'
DO $$ BEGIN
    IF (SELECT count(*) FROM contour.schema_migrations WHERE version = 1) <> 1 THEN
        RAISE EXCEPTION 'migration ledger mismatch';
    END IF;
END $$;
SQL
admin_sql < "$root/db/tests/setup.sql"
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_test -d contour_fixture < "$root/db/tests/identity.sql"
echo 'PostgreSQL identity fixture passed'
admin_sql < "$root/db/provision_authority.sql"
admin_sql <<'SQL'
CREATE ROLE contour_provision_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_owner, contour_runtime TO contour_provision_test;
SQL
# A membership-only provisioning login cannot see every forced-RLS collector.
if restricted_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -v VERBOSITY=verbose -h /var/run/postgresql -U contour_provision_test \
    -d contour_fixture < "$root/db/migrations/0002_policy.sql" 2>&1); then
    echo 'Restricted provisioning migration unexpectedly succeeded' >&2; exit 1
fi
if [[ "$restricted_output" != *"42501"* ]]; then
    echo "$restricted_output" >&2
    echo 'Restricted provisioning failed for an unexpected reason' >&2; exit 1
fi
admin_sql <<'SQL'
DO $$ BEGIN
    IF to_regclass('contour.policy_revisions') IS NOT NULL
        OR to_regclass('contour.collector_authorization') IS NOT NULL
        OR to_regclass('contour.source_authorization') IS NOT NULL
        OR EXISTS (SELECT 1 FROM contour.schema_migrations WHERE version=2)
        OR NOT has_table_privilege('contour_runtime','contour.sources','UPDATE')
        OR (SELECT count(*) FROM contour.collectors) <> 4 THEN
        RAISE EXCEPTION 'restricted provisioning failure left partial upgrade';
    END IF;
END $$;
SQL
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0002_policy.sql" | admin_sql; then
    echo 'Injected policy migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
DO $$ BEGIN
    IF to_regclass('contour.policy_revisions') IS NOT NULL
        OR to_regclass('contour.collector_authorization') IS NOT NULL
        OR to_regclass('contour.source_authorization') IS NOT NULL
        OR EXISTS (SELECT 1 FROM contour.schema_migrations WHERE version = 2)
        OR NOT has_table_privilege('contour_runtime','contour.sources','UPDATE')
        OR EXISTS (SELECT 1 FROM pg_class c CROSS JOIN LATERAL aclexplode(c.relacl) a
            WHERE c.oid='contour.collectors'::regclass
            AND a.grantee='contour_admin'::regrole AND a.privilege_type='INSERT') THEN
        RAISE EXCEPTION 'failed policy migration did not restore old state';
    END IF;
END $$;
SQL
admin_sql < "$root/db/migrations/0002_policy.sql"
admin_sql <<'SQL'
DO $$ BEGIN
    IF (SELECT count(*) FROM contour.collectors) <> 4
        OR (SELECT count(*) FROM contour.collector_authorization) <> 4
        OR EXISTS (SELECT 1 FROM contour.collector_authorization
            WHERE enabled OR active_revision IS NOT NULL OR revoked_at IS NOT NULL)
        OR EXISTS (SELECT 1 FROM contour.source_authorization) THEN
        RAISE EXCEPTION 'policy backfill mismatch';
    END IF;
END $$;
CREATE ROLE contour_admin_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_ingest_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS
    NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_admin TO contour_admin_test;
GRANT contour_ingestion TO contour_ingest_test;
GRANT USAGE ON SCHEMA fixture TO contour_admin_test, contour_ingest_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_admin_test, contour_ingest_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_test -d contour_fixture < "$root/db/tests/policy.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.policy_revisions SET signed_envelope=signed_envelope','23514');
SELECT fixture.expect_state('DELETE FROM contour.policy_revisions','23514');
SELECT fixture.expect_state('UPDATE contour.sources SET source_nonce=source_nonce','23514');
SELECT fixture.expect_state('DELETE FROM contour.collectors','23514');
SQL
python3 "$root/scripts/test-policy-concurrency.py" "$container_id"
echo 'PostgreSQL policy authority fixture passed'
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0003_ingestion.sql" | admin_sql; then
    echo 'Injected inbox migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
DO $$ BEGIN
    IF to_regclass('contour.ingestion_batches') IS NOT NULL
        OR to_regclass('contour.ingestion_payloads') IS NOT NULL
        OR EXISTS (SELECT 1 FROM contour.schema_migrations WHERE version=3)
        OR has_function_privilege('contour_ingestion','contour.guard_collector(uuid,uuid)','EXECUTE') THEN
        RAISE EXCEPTION 'failed inbox migration left DDL, grants or ledger';
    END IF;
END $$;
SQL
admin_sql < "$root/db/migrations/0003_ingestion.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3]::integer[], 'three migration ledger entries');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_ingest_test -d contour_fixture < "$root/db/tests/inbox.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.ingestion_batches SET request_digest=request_digest','23514');
SELECT fixture.expect_state('DELETE FROM contour.ingestion_batches','23514');
SELECT fixture.expect_state('UPDATE contour.ingestion_payloads SET checked_batch=checked_batch','23514');
SELECT fixture.expect_state('DELETE FROM contour.ingestion_payloads','23514');
SQL
echo 'PostgreSQL durable inbox fixture passed'
admin_sql < "$root/db/provision_catalog.sql"
# Migration 4 needs owner membership only, not superuser/BYPASSRLS.
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0004_catalog.sql" | docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture; then
    echo 'Injected catalog migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.operations') IS NULL
    AND to_regclass('contour.variants') IS NULL
    AND to_regclass('contour.observation_windows') IS NULL
    AND to_regclass('contour.catalog_processed_batches') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=4)
    AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='catalog_source_workload')
    AND NOT has_table_privilege('contour_catalog_worker','contour.ingestion_payloads','SELECT')
    AND NOT has_schema_privilege('contour_catalog_worker','contour','USAGE'), 'catalog upgrade atomic rollback');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0004_catalog.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4]::integer[], 'four migration ledger entries');
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002');
INSERT INTO contour.policy_revisions VALUES (contour.tenant_context(),
    '00000000-0000-0000-0000-000000000002',3,'catalog-inert-policy');
COMMIT;
CREATE ROLE contour_catalog_worker_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_catalog_reader_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_catalog_worker TO contour_catalog_worker_test;
GRANT contour_catalog_reader TO contour_catalog_reader_test;
GRANT USAGE ON SCHEMA fixture TO contour_catalog_worker_test, contour_catalog_reader_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_catalog_worker_test, contour_catalog_reader_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_catalog_worker_test -d contour_fixture < "$root/db/tests/catalog.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.operations SET canonical_key=canonical_key','23514');
SELECT fixture.expect_state('DELETE FROM contour.variants','23514');
SELECT fixture.expect_state('UPDATE contour.observation_windows SET observation_count=observation_count','23514');
SELECT fixture.expect_state('DELETE FROM contour.catalog_processed_batches','23514');
SQL
python3 "$root/scripts/test-catalog-concurrency.py" "$container_id"
echo 'PostgreSQL catalog storage fixture passed'
admin_sql < "$root/db/provision_declared.sql"
# As with catalog storage, owner membership is sufficient; no BYPASSRLS needed.
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0005_declared.sql" | docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture; then
    echo 'Injected declared migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.declared_versions') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=5)
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polrelid='contour.operations'::regclass
        AND polname IN ('declared_operation_read','declared_operation_insert'))
    AND NOT has_table_privilege('contour_declared_writer','contour.operations','SELECT,INSERT')
    AND NOT has_table_privilege('contour_declared_reader','contour.operations','SELECT')
    AND NOT has_schema_privilege('contour_declared_writer','contour','USAGE')
    AND NOT has_schema_privilege('contour_declared_reader','contour','USAGE')
    AND NOT has_function_privilege('contour_declared_writer','contour.tenant_context()','EXECUTE')
    AND NOT has_function_privilege('contour_declared_reader','contour.tenant_context()','EXECUTE'),
    'declared upgrade rolls back DDL policies grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0005_declared.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5]::integer[], 'five migration ledger entries');
CREATE ROLE contour_declared_writer_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_declared_reader_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_declared_writer TO contour_declared_writer_test;
GRANT contour_declared_reader TO contour_declared_reader_test;
GRANT USAGE ON SCHEMA fixture TO contour_declared_writer_test, contour_declared_reader_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_declared_writer_test, contour_declared_reader_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_declared_writer_test -d contour_fixture < "$root/db/tests/declared.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.declared_versions SET declared_wire=declared_wire','23514');
SELECT fixture.expect_state('DELETE FROM contour.declared_versions','23514');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.observation_windows
    WHERE operation_id='00000000-0000-0000-0000-000000000051')
    AND NOT EXISTS(SELECT 1 FROM contour.variants
        WHERE operation_id='00000000-0000-0000-0000-000000000051'), 'declared operation needs no observed traffic');
SQL
echo 'PostgreSQL declared storage fixture passed'
admin_sql < "$root/db/provision_approval.sql"
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0006_approval.sql" | admin_sql; then
    echo 'Injected approval migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.approval_events') IS NULL
    AND to_regclass('contour.approval_heads') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=6)
    AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='declared_approval_scope'
        AND conrelid='contour.declared_versions'::regclass)
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polname IN ('approval_declared_read','approval_operation_read'))
    AND NOT has_schema_privilege('contour_approval_writer','contour','USAGE')
    AND NOT has_schema_privilege('contour_approval_reader','contour','USAGE')
    AND NOT has_table_privilege('contour_approval_writer','contour.operations','SELECT')
    AND NOT has_column_privilege('contour_approval_writer','contour.declared_versions','version_id','SELECT'),
    'approval migration rolls back tables constraints policies grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0006_approval.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6]::integer[], 'six migration ledger entries');
-- A valid second operation/version makes cross-operation FK tests discriminate.
INSERT INTO contour.declared_versions (tenant_id,version_id,operation_id,project_id,service_id,
    environment_id,codec_version,declared_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000052',operation_id,project_id,service_id,
        environment_id,1,decode('00','hex') FROM contour.operations
    WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'
        AND operation_id='00000000-0000-0000-0000-000000000002';
CREATE ROLE contour_approval_writer_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_approval_reader_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_approval_writer TO contour_approval_writer_test;
GRANT contour_approval_reader TO contour_approval_reader_test;
GRANT USAGE ON SCHEMA fixture TO contour_approval_writer_test, contour_approval_reader_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_approval_writer_test, contour_approval_reader_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_approval_writer_test -d contour_fixture < "$root/db/tests/approval.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.approval_events SET actor_id=actor_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.approval_events','23514');
SQL
echo 'PostgreSQL approval association storage fixture passed'
admin_sql < "$root/db/provision_comparison.sql"
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0007_comparison.sql" | admin_sql; then
    echo 'Injected comparison migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.comparisons') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=7)
    AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='approval_comparison_scope'
        AND conrelid='contour.approval_events'::regclass)
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polname IN ('comparison_declared_read','comparison_approval_read'))
    AND NOT has_schema_privilege('contour_comparison_writer','contour','USAGE')
    AND NOT has_schema_privilege('contour_comparison_reader','contour','USAGE')
    AND NOT has_column_privilege('contour_comparison_writer','contour.declared_versions','version_id','SELECT')
    AND NOT has_column_privilege('contour_comparison_reader','contour.approval_events','event_id','SELECT'),
    'comparison upgrade rolls back tables constraints policies grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0007_comparison.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7]::integer[], 'seven migration ledger entries');
-- Same operation, different immutable declared version and approval event.
INSERT INTO contour.declared_versions (tenant_id,version_id,operation_id,project_id,service_id,
    environment_id,codec_version,declared_wire)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000053',operation_id,project_id,service_id,
        environment_id,codec_version,declared_wire FROM contour.declared_versions
    WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND version_id='00000000-0000-0000-0000-000000000051';
INSERT INTO contour.approval_events (tenant_id,event_id,operation_id,project_id,service_id,
    environment_id,version_id,expected_event_id,actor_id)
    SELECT tenant_id,'00000000-0000-0000-0000-000000000063',operation_id,project_id,service_id,
        environment_id,'00000000-0000-0000-0000-000000000053',event_id,actor_id
    FROM contour.approval_events WHERE event_id='00000000-0000-0000-0000-000000000061';
CREATE ROLE contour_comparison_writer_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_comparison_reader_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_comparison_writer TO contour_comparison_writer_test;
GRANT contour_comparison_reader TO contour_comparison_reader_test;
GRANT USAGE ON SCHEMA fixture TO contour_comparison_writer_test, contour_comparison_reader_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_comparison_writer_test, contour_comparison_reader_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_comparison_writer_test -d contour_fixture < "$root/db/tests/comparison.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.comparisons SET result_wire=result_wire','23514');
SELECT fixture.expect_state('DELETE FROM contour.comparisons','23514');
SQL
echo 'PostgreSQL immutable comparison storage fixture passed'
admin_sql < "$root/db/provision_review.sql"
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0008_review.sql" | admin_sql; then
    echo 'Injected review migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.review_requests') IS NULL
    AND to_regclass('contour.review_decisions') IS NULL
    AND to_regprocedure('contour.check_review_request()') IS NULL
    AND to_regprocedure('contour.check_review_decision()') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=8)
    AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='comparison_review_scope'
        AND conrelid='contour.comparisons'::regclass)
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polname IN ('review_comparison_read','review_approval_read'))
    AND NOT has_schema_privilege('contour_review_writer','contour','USAGE')
    AND NOT has_schema_privilege('contour_review_reader','contour','USAGE')
    AND NOT has_column_privilege('contour_review_writer','contour.comparisons','comparison_id','SELECT')
    AND NOT has_column_privilege('contour_review_writer','contour.approval_events','actor_id','SELECT'),
    'review migration rolls back tables functions constraints policies grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0008_review.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8]::integer[], 'eight migration ledger entries');
CREATE ROLE contour_review_writer_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_review_reader_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_review_writer TO contour_review_writer_test;
GRANT contour_review_reader TO contour_review_reader_test;
GRANT USAGE ON SCHEMA fixture TO contour_review_writer_test, contour_review_reader_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text), fixture.expect_state(text,text)
    TO contour_review_writer_test, contour_review_reader_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_review_writer_test -d contour_fixture < "$root/db/tests/review.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.review_requests SET review_id=review_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.review_requests','23514');
SELECT fixture.expect_state('UPDATE contour.review_decisions SET actor_id=actor_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.review_decisions','23514');
SQL
echo 'PostgreSQL immutable review request and decision storage fixture passed'
admin_sql < "$root/db/provision_human.sql"
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0009_human.sql" | admin_sql; then
    echo 'Injected human metadata migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.human_actors') IS NULL
    AND to_regclass('contour.human_identities') IS NULL
    AND to_regclass('contour.human_tenant_memberships') IS NULL
    AND to_regclass('contour.human_project_memberships') IS NULL
    AND to_regclass('contour.human_service_roles') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=9)
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polname IN
        ('human_lookup','human_lookup_lock','human_provision'))
    AND NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgname='human_stable_actor')
    AND NOT has_schema_privilege('contour_human_provisioner','contour','USAGE')
    AND NOT has_schema_privilege('contour_human_lookup','contour','USAGE'),
    'human migration rolls back tables constraints policies triggers grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0009_human.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9]::integer[], 'nine migration ledger entries');
CREATE ROLE contour_human_provisioner_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
CREATE ROLE contour_human_lookup_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_human_provisioner TO contour_human_provisioner_test;
GRANT contour_human_lookup TO contour_human_lookup_test;
GRANT USAGE ON SCHEMA fixture TO contour_human_provisioner_test,contour_human_lookup_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text),fixture.expect_state(text,text)
    TO contour_human_provisioner_test,contour_human_lookup_test;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_human_provisioner_test -d contour_fixture < "$root/db/tests/human.sql"
echo 'PostgreSQL operator-provisioned human authorization metadata fixture passed'
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0010_public_contracts.sql" | admin_sql; then
    echo 'Injected public contract migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.service_import_defaults') IS NULL
    AND to_regclass('contour.public_declared_contracts') IS NULL
    AND to_regclass('contour.public_declared_members') IS NULL
    AND to_regprocedure('contour.check_public_contract_members()') IS NULL
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=10),
    'public contract migration rolls back tables functions grants and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0010_public_contracts.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10]::integer[], 'ten migration ledger entries');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_declared_writer_test -d contour_fixture < "$root/db/tests/public_contracts.sql"
echo 'PostgreSQL immutable whole-service contract membership fixture passed'
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0011_import_selectors.sql" | admin_sql; then
    echo 'Injected selector migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM information_schema.columns
    WHERE table_schema='contour' AND column_name IN ('projection_version','body_selector','media_type'))
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=11)
    AND position('projection_version' IN pg_get_functiondef('contour.check_public_contract_members()'::regprocedure))=0,
    'selector migration restores columns constraints grants function and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0011_import_selectors.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10,11]::integer[], 'eleven migration ledger entries');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_declared_writer_test -d contour_fixture < "$root/db/tests/import_selectors.sql"
echo 'PostgreSQL versioned whole-service import selectors fixture passed'
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0012_public_comparisons.sql" | admin_sql; then
    echo 'Injected public comparison migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.public_comparison_inputs') IS NULL
    AND to_regprocedure('contour.check_public_comparison_inputs()') IS NULL
    AND NOT EXISTS(SELECT 1 FROM information_schema.columns
        WHERE table_schema='contour' AND table_name='comparisons' AND column_name='public_projection')
    AND NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conname='public_member_comparison_scope')
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=12),
    'public comparison migration rolls back tables columns constraints functions and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0012_public_comparisons.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10,11,12]::integer[], 'twelve migration ledger entries');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_comparison_writer_test -d contour_fixture < "$root/db/tests/public_comparisons.sql"
echo 'PostgreSQL immutable public comparison association fixture passed'
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0013_instance_registry.sql" | admin_sql; then
    echo 'Injected instance registry migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.workload_instances') IS NULL
    AND to_regclass('contour.source_instance_bindings') IS NULL
    AND NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='contour'
        AND table_name='sources' AND column_name='binding_mode')
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=13), 'instance migration rollback');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0013_instance_registry.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13]::integer[], 'thirteen migration ledger entries');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_admin_test -d contour_fixture < "$root/db/tests/instance_registry.sql"
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.workload_instances SET instance_id=instance_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.source_instance_bindings','23514');
SQL
# A missing binding must fail at COMMIT under the actual restricted login.
if missing_binding_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 -v VERBOSITY=verbose \
    -h /var/run/postgresql -U contour_admin_test -d contour_fixture 2>&1 <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.lock_collector('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
INSERT INTO contour.sources VALUES ('aaaaaaaa-0000-0000-0000-000000000000',
 '00000000-0000-0000-0000-000000000104','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000104','instance');
COMMIT;
SQL
); then
    echo 'Unbound instance source unexpectedly committed' >&2; exit 1
fi
if [[ "$missing_binding_output" != *"23514"* ]]; then
    echo "$missing_binding_output" >&2; echo 'Missing binding failed for unexpected reason' >&2; exit 1
fi
echo 'PostgreSQL instance registry fixture passed'
# Seed another original record before upgrading, under the restricted writer.
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_catalog_worker_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ DECLARE row contour.observation_windows; BEGIN
    SELECT * INTO row FROM contour.observation_windows LIMIT 1;
    row.record_id := '00000000-0000-0000-0000-000000000096';
    INSERT INTO contour.observation_windows SELECT row.*;
END $$;
COMMIT;
SQL
# Upgrade populated catalog evidence; injected failure must leave no partial column.
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/migrations/0014_observation_evidence.sql" | admin_sql; then
    echo 'Injected observation identity migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='contour'
    AND table_name='observation_windows' AND column_name='observation_id')
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=14), 'observation identity migration rollback');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/migrations/0014_observation_evidence.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14]::integer[], 'fourteen migration ledger entries');
SELECT fixture.expect_state('UPDATE contour.observation_windows SET observation_id=observation_id','23514');
SQL
# Semantic mutation: removing both identity constraints must expose reuse across
# two otherwise valid operations. The failed fixture transaction rolls back its rows.
admin_sql <<'SQL'
ALTER TABLE contour.observation_windows DROP CONSTRAINT observation_windows_observation_id_key;
ALTER TABLE contour.observation_windows DROP CONSTRAINT observation_windows_scoped_observation_key;
SQL
if mutation_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_catalog_worker_test -d contour_fixture < "$root/db/tests/observation_evidence.sql" 2>&1); then
    echo 'Missing identity constraints unexpectedly passed' >&2; exit 1
fi
if [[ "$mutation_output" != *'global identity reused across operations'* ]]; then
    echo "$mutation_output" >&2; echo 'Identity mutation failed for an unexpected reason' >&2; exit 1
fi
admin_sql <<'SQL'
ALTER TABLE contour.observation_windows ADD CONSTRAINT observation_windows_observation_id_key UNIQUE (observation_id);
ALTER TABLE contour.observation_windows ADD CONSTRAINT observation_windows_scoped_observation_key UNIQUE (tenant_id, operation_id, observation_id);
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_catalog_worker_test -d contour_fixture < "$root/db/tests/observation_evidence.sql"
# Two independent sessions insert different records concurrently using the default.
# A third session holds an advisory barrier until both inserts are waiting at it.
docker exec -i -e PGAPPNAME=observation_barrier "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U postgres -d contour_fixture <<'SQL' &
BEGIN;
SELECT pg_advisory_xact_lock(140014);
SELECT pg_sleep(10);
COMMIT;
SQL
barrier_pid=$!
barrier_ready=false
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ $(docker exec "$container_id" psql -X -Atc "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND granted AND objid=140014" -h /var/run/postgresql -U postgres -d contour_fixture) == 1 ]]; then
        barrier_ready=true; break
    fi
    sleep 0.05
done
if [[ "$barrier_ready" != true ]]; then echo 'Observation barrier did not acquire lock' >&2; exit 1; fi
for record in 00000000-0000-0000-0000-000000000094 00000000-0000-0000-0000-000000000095; do
    docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 -v record="$record" \
        -h /var/run/postgresql -U contour_catalog_worker_test -d contour_fixture <<'SQL' &
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
INSERT INTO contour.observation_windows (tenant_id,collector_id,batch_id,record_id,operation_id,variant_id,
    source_id,project_id,service_id,environment_id,deployment_id,observation_count,sample_numerator,
    sample_denominator,visibility,completeness,reasons,route_uncertain,status_code,first_seen,last_seen,
    queued_at,expires_at,request_header_names,response_header_names,query_parameter_names)
SELECT tenant_id,collector_id,batch_id,:'record'::uuid,operation_id,variant_id,
    source_id,project_id,service_id,environment_id,deployment_id,observation_count,sample_numerator,
    sample_denominator,visibility,completeness,reasons,route_uncertain,status_code,first_seen,last_seen,
    queued_at,expires_at,request_header_names,response_header_names,query_parameter_names
FROM contour.observation_windows WHERE record_id='00000000-0000-0000-0000-000000000001';
SELECT pg_advisory_xact_lock(140014);
COMMIT;
SQL
    if [[ "$record" == *094 ]]; then first_pid=$!; else second_pid=$!; fi
done
overlap=false
for ((attempt = 0; attempt < 100; attempt++)); do
    if [[ $(docker exec "$container_id" psql -X -Atc "SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND NOT granted AND objid=140014" -h /var/run/postgresql -U postgres -d contour_fixture) == 2 ]]; then
        overlap=true; break
    fi
    sleep 0.05
done
if [[ "$overlap" != true ]]; then echo 'Concurrent observation inserts did not both reach barrier' >&2; exit 1; fi
wait "$barrier_pid"
wait "$first_pid"
wait "$second_pid"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT count(*)=2 AND count(DISTINCT observation_id)=2 FROM contour.observation_windows
    WHERE record_id IN ('00000000-0000-0000-0000-000000000094','00000000-0000-0000-0000-000000000095')),
    'concurrent inserts have distinct identities');
SQL
echo 'PostgreSQL observation identity fixture, mutation and concurrency passed'

# Opt-in origin registry is exercised only here, after every schema-14 check.
# Snapshot legacy rows before both failure injection and the successful upgrade.
admin_sql <<'SQL'
CREATE FUNCTION fixture.origin_v1_fingerprint() RETURNS text
LANGUAGE sql VOLATILE SET search_path=pg_catalog AS $$
 SELECT pg_catalog.md5(
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.sources t),'') || '|' ||
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.policy_revisions t),'') || '|' ||
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.collector_authorization t),'') || '|' ||
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.ingestion_batches t),'') || '|' ||
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.ingestion_payloads t),'') || '|' ||
   coalesce((SELECT string_agg(to_jsonb(t)::text, E'\n' ORDER BY to_jsonb(t)::text) FROM contour.observation_windows t),'')
 )
$$;
CREATE TABLE fixture.origin_v1_before AS SELECT fixture.origin_v1_fingerprint() AS fingerprint;
SQL
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/opt-in-migrations/0015_origin_lifecycle.sql" | admin_sql; then
    echo 'Injected origin lifecycle migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.origin_lifecycles') IS NULL
    AND to_regclass('contour.origin_credentials') IS NULL
    AND to_regclass('contour.origin_observer_grants') IS NULL
    AND to_regclass('contour.origin_terminal_events') IS NULL
    AND to_regprocedure('contour.enroll_origin(uuid,uuid,uuid,uuid,uuid,uuid,uuid,text,bytea)') IS NULL
    AND NOT EXISTS(SELECT 1 FROM pg_policy WHERE polname IN ('origin_owner_instance_read','origin_owner_source_read'))
    AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=15)
    AND fixture.origin_v1_fingerprint()=(SELECT fingerprint FROM fixture.origin_v1_before),
    'origin migration failure rolls back DDL policies grants and V1 rows');
SQL
# Owner membership is sufficient; no superuser/BYPASSRLS or legacy backfill.
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/opt-in-migrations/0015_origin_lifecycle.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
    = ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15]::integer[]
    AND fixture.origin_v1_fingerprint()=(SELECT fingerprint FROM fixture.origin_v1_before),
    'opt-in origin migration preserves V1 rows and ledger');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_admin_test -d contour_fixture < "$root/db/tests/origin_lifecycle.sql"
# Exercise each trigger row type directly without the required gate, including
# both terminal-event branches. Existing rows ensure every INSERT fires a guard.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert(EXISTS(SELECT 1 FROM contour.origin_lifecycles)
 AND EXISTS(SELECT 1 FROM contour.origin_credentials)
 AND EXISTS(SELECT 1 FROM contour.origin_observer_grants)
 AND EXISTS(SELECT 1 FROM contour.origin_terminal_events WHERE event_kind='grant_revoked')
 AND EXISTS(SELECT 1 FROM contour.origin_terminal_events WHERE event_kind='credential_revoked'), 'all guard row types seeded');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_lifecycles SELECT * FROM contour.origin_lifecycles LIMIT 1$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_credentials SELECT * FROM contour.origin_credentials LIMIT 1$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_observer_grants SELECT * FROM contour.origin_observer_grants LIMIT 1$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_terminal_events SELECT * FROM contour.origin_terminal_events WHERE event_kind='grant_revoked' LIMIT 1$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_terminal_events SELECT * FROM contour.origin_terminal_events WHERE event_kind='credential_revoked' LIMIT 1$q$,'42501');
ROLLBACK;
SQL
# Only in this isolated transaction, replace the private, no-argument clock
# helper with fixed earlier server instants. Rollback restores the real helper.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
DO $$ DECLARE early timestamptz; later timestamptz; BEGIN
  SELECT granted_at + interval '1 microsecond' INTO early FROM contour.origin_observer_grants
    WHERE tenant_id=contour.tenant_context() AND grant_id='00000000-0000-0000-0000-000000000522';
  SELECT enrolled_at INTO later FROM contour.origin_credentials
    WHERE tenant_id=contour.tenant_context() AND credential_id='00000000-0000-0000-0000-000000000516';
  PERFORM fixture.assert(early IS NOT NULL AND later IS NOT NULL AND early < later,'clock regression fixture gap');
  EXECUTE format('CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS %L',
    format('SELECT %L::timestamptz', early));
END $$;
SELECT fixture.expect_state($q$SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000000501')$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000000512')$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000000522')$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000517','00000000-0000-0000-0000-000000000501',decode(repeat('55',32),'hex'))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000527','00000000-0000-0000-0000-000000000501','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002','00000000-0000-0000-0000-000000000002')$q$,'23514');
DO $$ DECLARE early timestamptz; later timestamptz; BEGIN
  SELECT granted_at + interval '1 microsecond' INTO early FROM contour.origin_observer_grants
    WHERE tenant_id=contour.tenant_context() AND grant_id='00000000-0000-0000-0000-000000000525';
  SELECT event_at INTO later FROM contour.origin_terminal_events
    WHERE tenant_id=contour.tenant_context() AND grant_id='00000000-0000-0000-0000-000000000525' AND event_kind='grant_revoked';
  PERFORM fixture.assert(early IS NOT NULL AND later IS NOT NULL AND early < later,'regrant clock regression fixture gap');
  EXECUTE format('CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS %L',
    format('SELECT %L::timestamptz', early));
END $$;
SELECT fixture.expect_state($q$SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000526','00000000-0000-0000-0000-000000000505','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001')$q$,'23514');
ROLLBACK;
SELECT fixture.assert(pg_get_functiondef('contour.origin_server_time()'::regprocedure) LIKE '%pg_catalog.clock_timestamp()%','fixture clock replacement rolled back');
SQL
admin_sql <<'SQL'
SELECT fixture.expect_state('UPDATE contour.origin_lifecycles SET instance_id=instance_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.origin_credentials','23514');
SELECT fixture.expect_state('UPDATE contour.origin_observer_grants SET source_id=source_id','23514');
SELECT fixture.expect_state('DELETE FROM contour.origin_terminal_events','23514');
SELECT fixture.expect_state('TRUNCATE contour.origin_terminal_events','23514');
SQL
python3 "$root/scripts/test-origin-lifecycle-concurrency.py" "$container_id"
echo 'PostgreSQL opt-in origin lifecycle registry fixture passed'

# Opt-in V2 inbox migration: failure must leave legacy DDL, ACLs and data intact.
admin_sql < "$root/db/provision_v2_ingress.sql"
admin_sql <<'SQL'
CREATE FUNCTION fixture.v2_legacy_ddl_fingerprint() RETURNS text LANGUAGE sql AS $$
 SELECT md5(coalesce((SELECT string_agg(c.conrelid::regclass::text||':'||c.conname||':'||pg_get_constraintdef(c.oid), E'\n' ORDER BY c.conrelid::regclass::text,c.conname)
   FROM pg_constraint c WHERE c.conrelid IN ('contour.ingestion_batches'::regclass,'contour.ingestion_payloads'::regclass)), '') || '|' ||
   coalesce((SELECT string_agg(p.polrelid::regclass::text||':'||p.polname||':'||p.polpermissive::text||':'||p.polcmd::text||':'||p.polroles::text||':'||coalesce(pg_get_expr(p.polqual,p.polrelid),'')||':'||coalesce(pg_get_expr(p.polwithcheck,p.polrelid),''), E'\n' ORDER BY p.polrelid::regclass::text,p.polname)
   FROM pg_policy p WHERE p.polrelid IN ('contour.ingestion_batches'::regclass,'contour.ingestion_payloads'::regclass)), '') || '|' ||
   coalesce((SELECT string_agg(c.oid::regclass::text||':'||coalesce(c.relacl::text,''), E'\n' ORDER BY c.oid::regclass::text)
   FROM pg_class c WHERE c.oid IN ('contour.ingestion_batches'::regclass,'contour.ingestion_payloads'::regclass)), ''))
$$;
CREATE TABLE fixture.v2_before AS SELECT fixture.v2_legacy_ddl_fingerprint() AS ddl, fixture.origin_v1_fingerprint() AS rows;
SQL
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/opt-in-migrations/0016_v2_unattributed.sql" | admin_sql; then
    echo 'Injected V2 inbox migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.ingestion_v2_metadata') IS NULL
 AND NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=16)
 AND NOT has_schema_privilege('contour_v2_ingress','contour','USAGE')
 AND NOT has_table_privilege('contour_v2_ingress','contour.ingestion_batches','SELECT')
 AND fixture.v2_legacy_ddl_fingerprint()=(SELECT ddl FROM fixture.v2_before)
 AND fixture.origin_v1_fingerprint()=(SELECT rows FROM fixture.v2_before),
 'V2 migration failure restores constraints policies grants ledger and V1 rows');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/opt-in-migrations/0016_v2_unattributed.sql"
admin_sql <<'SQL'
SELECT fixture.assert((SELECT array_agg(version ORDER BY version) FROM contour.schema_migrations)
 = ARRAY[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]::integer[]
 AND fixture.origin_v1_fingerprint()=(SELECT rows FROM fixture.v2_before), 'V2 upgrade retains V1 rows');
CREATE ROLE contour_v2_ingress_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_v2_ingress TO contour_v2_ingress_test;
GRANT USAGE ON SCHEMA fixture TO contour_v2_ingress_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text),fixture.expect_state(text,text) TO contour_v2_ingress_test;
BEGIN;
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
INSERT INTO contour.policy_revisions VALUES ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001',1,decode('01','hex')) ON CONFLICT DO NOTHING;
COMMIT;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_v2_ingress_test -d contour_fixture < "$root/db/tests/v2_unattributed.sql"
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_ingest_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c011',decode(repeat('aa',32),'hex'),2,1)$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_payloads VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-00000000c011',2,decode('7b7d','hex'))$q$,'42501');
ROLLBACK;
SQL
echo 'PostgreSQL opt-in V2 inbox rollback and role fixtures passed'

# Dedicated pre-17 origin facts for the epoch fixture. Each enrollment runs
# in its own transaction and remains independent of the legacy concurrency cases.
admin_sql <<'SQL'
INSERT INTO contour.workload_instances VALUES
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001703'),
 ('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001704');
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001701','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001703','trusted_platform_v1',decode(repeat('a7',32),'hex'));
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',false);
SELECT contour.enroll_origin('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001702','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001704','trusted_platform_v1',decode(repeat('b7',32),'hex'));
SQL

# Phase 1 origin-ingress capability, isolated from the basic V2 role.
admin_sql < "$root/db/provision_origin_ingress.sql"
admin_sql <<'SQL'
CREATE TABLE fixture.origin_ingress_before AS SELECT fixture.origin_v1_fingerprint() AS fingerprint;
SQL
if awk '/-- transaction failure probe/ { print "SELECT 1 / 0;" } { print }' \
    "$root/db/opt-in-migrations/0017_origin_proofs.sql" | admin_sql; then
    echo 'Injected origin ingress migration failure unexpectedly succeeded' >&2; exit 1
fi
admin_sql <<'SQL'
SELECT fixture.assert(to_regclass('contour.origin_ingress_context') IS NULL, 'origin ingress rollback removes context table');
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.schema_migrations WHERE version=17), 'origin ingress rollback removes migration ledger entry');
SELECT fixture.assert(NOT has_schema_privilege('contour_origin_ingress','contour','USAGE'), 'origin ingress rollback removes schema grant');
SELECT fixture.assert(fixture.origin_v1_fingerprint()=(SELECT fingerprint FROM fixture.origin_ingress_before), 'origin ingress rollback preserves prior rows');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_provision_test -d contour_fixture < "$root/db/opt-in-migrations/0017_origin_proofs.sql"
admin_sql <<'SQL'
CREATE ROLE contour_origin_ingress_test LOGIN INHERIT NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB NOREPLICATION;
GRANT contour_origin_ingress TO contour_origin_ingress_test;
GRANT USAGE ON SCHEMA fixture TO contour_origin_ingress_test;
GRANT EXECUTE ON FUNCTION fixture.assert(boolean,text),fixture.expect_state(text,text) TO contour_origin_ingress_test;
CREATE FUNCTION fixture.origin_collector_key(uuid,uuid) RETURNS bigint LANGUAGE sql SECURITY DEFINER SET search_path=pg_catalog AS $$
 SELECT contour.collector_lock_key($1,$2)
$$;
REVOKE ALL ON FUNCTION fixture.origin_collector_key(uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION fixture.origin_collector_key(uuid,uuid) TO contour_origin_ingress_test;
SELECT fixture.assert(NOT pg_has_role('contour_origin_ingress','contour_v2_ingress','MEMBER')
 AND NOT pg_has_role('contour_origin_ingress','contour_ingestion','MEMBER'), 'origin role is independent');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture < "$root/db/tests/origin_proofs.sql"
admin_sql <<'SQL'
SELECT fixture.assert(NOT EXISTS(SELECT 1 FROM contour.origin_ingress_context), 'committed and aborted contexts leave no rows');
SQL
echo 'PostgreSQL opt-in origin ingress capability fixture passed'

# Registry epoch and tenant clock: deterministic clock overrides are rolled back.
admin_sql <<'SQL'
SELECT fixture.assert((SELECT bool_and(fact_epoch=0) FROM contour.origin_lifecycles)
 AND (SELECT bool_and(fact_epoch=0) FROM contour.origin_credentials)
 AND (SELECT bool_and(fact_epoch=0) FROM contour.origin_observer_grants)
 AND (SELECT bool_and(fact_epoch=0) FROM contour.origin_terminal_events), 'legacy facts have epoch zero');
SELECT fixture.assert((SELECT s.epoch=0 AND s.clock_floor=(SELECT max(h.t) FROM (
 SELECT enrolled_at AS t FROM contour.origin_lifecycles WHERE tenant_id=s.tenant_id
 UNION ALL SELECT enrolled_at FROM contour.origin_credentials WHERE tenant_id=s.tenant_id
 UNION ALL SELECT granted_at FROM contour.origin_observer_grants WHERE tenant_id=s.tenant_id
 UNION ALL SELECT event_at FROM contour.origin_terminal_events WHERE tenant_id=s.tenant_id
 ) h) FROM contour.origin_tenant_state s WHERE s.tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'lazy seed includes all legacy fact clocks');
SELECT fixture.assert(NOT has_table_privilege('contour_origin_ingress','contour.origin_tenant_state','SELECT')
 AND NOT has_table_privilege('contour_admin','contour.origin_tenant_state','INSERT')
 AND NOT has_table_privilege('contour_admin','contour.origin_tenant_state','UPDATE'), 'tenant state is private');
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001711','00000000-0000-0000-0000-000000001701',decode(repeat('99',32),'hex'));
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001721','00000000-0000-0000-0000-000000001701','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000001721');
SELECT fixture.assert((SELECT fact_epoch=1 FROM contour.origin_credentials WHERE credential_id='00000000-0000-0000-0000-000000001711')
 AND (SELECT fact_epoch=2 FROM contour.origin_observer_grants WHERE grant_id='00000000-0000-0000-0000-000000001721')
 AND (SELECT fact_epoch=3 FROM contour.origin_terminal_events WHERE grant_id='00000000-0000-0000-0000-000000001721')
 AND (SELECT epoch=3 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'post-activation facts advance epoch');
BEGIN;
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001712','00000000-0000-0000-0000-000000001701',decode(repeat('98',32),'hex'));
SELECT fixture.assert((SELECT epoch=4 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'epoch advances inside transaction');
ROLLBACK;
SELECT fixture.assert((SELECT epoch=3 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000')
 AND NOT EXISTS(SELECT 1 FROM contour.origin_credentials WHERE credential_id='00000000-0000-0000-0000-000000001712'), 'rollback restores epoch and fact');
BEGIN;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
RESET ROLE;
SELECT fixture.assert((SELECT c.fact_epoch=s.epoch AND c.started_at>=s.clock_floor FROM contour.origin_ingress_context c JOIN contour.origin_tenant_state s USING(tenant_id)), 'context snapshots epoch and checked clock');
ROLLBACK;
-- Different tenant starts its own epoch at zero even with prior tenant history.
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',false);
SELECT contour.enroll_origin_credential('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001712','00000000-0000-0000-0000-000000001702',decode(repeat('97',32),'hex'));
SELECT fixture.assert((SELECT epoch=1 FROM contour.origin_tenant_state WHERE tenant_id='bbbbbbbb-0000-0000-0000-000000000000'), 'tenant epochs independent');
SET ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_tenant_state$q$,'42501');
RESET ROLE;
-- Add a real unused instance for initial enrollment's global-floor check.
INSERT INTO contour.workload_instances VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001799');
BEGIN;
SET LOCAL ROLE contour_owner;
CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT '2000-01-01 UTC'::timestamptz $$;
RESET ROLE;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001798','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001799','trusted_platform_v1',decode(repeat('aa',32),'hex'))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001712','00000000-0000-0000-0000-000000001701',decode(repeat('98',32),'hex'))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001')$q$,'23514');
ROLLBACK;
SQL
# Do not force an index plan: retain the actual planner choice as evidence.
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',false);
SELECT contour.end_origin('bbbbbbbb-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000001712');
SELECT fixture.assert((SELECT count(DISTINCT tenant_id)>=2 FROM contour.origin_terminal_events), 'terminal history has multiple tenants');
-- Planner-only synthetic history: disable FK and mutation triggers only inside
-- this rolled-back transaction. These rows are not admission or epoch evidence.
BEGIN;
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,grant_id,event_at)
SELECT CASE WHEN n % 2=0 THEN 'aaaaaaaa-0000-0000-0000-000000000000'::uuid
            ELSE 'bbbbbbbb-0000-0000-0000-000000000000'::uuid END,
       'grant_revoked', md5('origin-planner-' || n::text)::uuid,
       '2020-01-01 UTC'::timestamptz + n * interval '1 second'
FROM generate_series(1,10000) AS n;
SET LOCAL session_replication_role=origin;
ANALYZE contour.origin_terminal_events;
EXPLAIN (ANALYZE, BUFFERS, TIMING OFF) SELECT max(event_at) FROM contour.origin_terminal_events
 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
ROLLBACK;
ANALYZE contour.origin_terminal_events;
SELECT fixture.assert((SELECT count(DISTINCT tenant_id)>=2 FROM contour.origin_lifecycles), 'epoch fixture has populated multiple tenants');
-- Owner-only fixture insertion deliberately supplies a false epoch under the
-- real lifecycle and credential locks. The trigger must overwrite it.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SET LOCAL ROLE contour_owner;
SELECT contour.begin_origin_operation('aaaaaaaa-0000-0000-0000-000000000000');
SELECT contour.lock_origin_credential(decode(repeat('96',32),'hex'));
INSERT INTO contour.origin_credentials (tenant_id,credential_id,lifecycle_id,leaf_sha256,enrolled_at,fact_epoch)
 VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001713','00000000-0000-0000-0000-000000001701',decode(repeat('96',32),'hex'),contour.origin_server_time(),777777);
RESET ROLE;
SELECT fixture.assert((SELECT c.fact_epoch=s.epoch AND c.fact_epoch<>777777 FROM contour.origin_credentials c JOIN contour.origin_tenant_state s USING(tenant_id) WHERE c.credential_id='00000000-0000-0000-0000-000000001713'), 'fact epoch overrides caller value');
ROLLBACK;
-- Exhaustion is a closed error and must not wrap the epoch.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SET LOCAL ROLE contour_owner;
UPDATE contour.origin_tenant_state SET epoch=9223372036854775807 WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
RESET ROLE;
SELECT fixture.expect_state($q$SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001713','00000000-0000-0000-0000-000000001701',decode(repeat('96',32),'hex'))$q$,'54000');
SELECT fixture.assert((SELECT epoch=9223372036854775807 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'exhaustion does not wrap epoch');
ROLLBACK;
-- Equal clock values are permitted and still advance epoch, with the trusted
-- clock override and inserted fact both rolled back at transaction end.
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
CREATE TEMP TABLE origin_equal_before AS SELECT epoch,clock_floor FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SET LOCAL ROLE contour_owner;
DO $$ DECLARE floor_time timestamptz; BEGIN
 SELECT clock_floor INTO floor_time FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
 EXECUTE pg_catalog.format('CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS %L', 'SELECT ' || pg_catalog.quote_literal(floor_time::text) || '::timestamptz');
END $$;
RESET ROLE;
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001713','00000000-0000-0000-0000-000000001701',decode(repeat('96',32),'hex'));
SELECT fixture.assert((SELECT s.epoch=b.epoch+1 AND s.clock_floor=b.clock_floor FROM contour.origin_tenant_state s CROSS JOIN origin_equal_before b WHERE s.tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'equal clock advances epoch');
ROLLBACK;
SQL
echo 'PostgreSQL opt-in origin epoch and clock fixture passed'

# Resolver fixture: historical synthetic strict-codec evidence only. Its October 6
# timestamps do not establish current-time, policy, admission, or TLS validity.
# The fixture is strict-decoded and canonicalized by the actual Rust codec.
# Missing compiler, dependencies, or probe is a hard failure.
fixture_target_dir=${CARGO_TARGET_DIR:-"$root/target"}
CARGO_TARGET_DIR="$fixture_target_dir" \
    cargo build --locked --offline --manifest-path "$root/Cargo.toml" -p contour-core --example fixture_v2_canonical
fixture_pair=$(python3 - "$root" "$fixture_target_dir" <<'PYCODE'
import copy, json, pathlib, subprocess, sys
root, target = map(pathlib.Path, sys.argv[1:])
body = json.loads((root / 'docs/specification/fixtures/batches-v2.json').read_text())[0]['body']
scope_id = '00000000-0000-0000-0000-000000000001'
tenant_id = 'aaaaaaaa-0000-0000-0000-000000000000'
batch_id = '00000000-0000-4000-8000-000000001831'
body.update(tenant_id=tenant_id, collector_id=scope_id, batch_id=batch_id)
row = body['records'][0]
body['records'] = []
for i, leaf in enumerate(('a1', 'a2', 'a3'), 1841):
    item = copy.deepcopy(row)
    item['record']['record_id'] = f'00000000-0000-4000-8000-{i:012d}'
    for field in ('source_id', 'project_id', 'service_id', 'environment_id', 'deployment_id'):
        item['record'][field] = scope_id
    item['origin_witness']['leaf_sha256'] = leaf * 32
    body['records'].append(item)
result = subprocess.run([str(target / 'debug/examples/fixture_v2_canonical')], input=json.dumps(body).encode(), capture_output=True, check=True)
value = json.loads(result.stdout)
assert set(value) == {'canonical_hex', 'digest'}
assert all(len(value[k]) % 2 == 0 and all(c in '0123456789abcdef' for c in value[k]) for k in value)
assert len(value['digest']) == 64
normalized = json.loads(bytes.fromhex(value['canonical_hex']))
assert (normalized['tenant_id'], normalized['collector_id'], normalized['batch_id'], normalized['wire_version']) == (tenant_id, scope_id, batch_id, 2)
assert len(normalized['records']) == 3
for i, (item, leaf) in enumerate(zip(normalized['records'], ('a1', 'a2', 'a3'), strict=True), 1841):
    record = item['record']
    assert record['record_id'] == f'00000000-0000-4000-8000-{i:012d}'
    assert all(record[field] == scope_id for field in ('source_id', 'project_id', 'service_id', 'environment_id', 'deployment_id'))
    assert record['parser_profile'] == 'http_json_v1' and record['policy_revision'] == 1
    assert item['origin_witness'] == {'kind': 'downstream_mtls_leaf_sha256_v1', 'leaf_sha256': leaf * 32}
body['batch_id'] = '00000000-0000-4000-8000-000000001859'
for item in body['records']:
    item['origin_witness'] = {'kind': 'unattributed'}
zero = json.loads(subprocess.run([str(target / 'debug/examples/fixture_v2_canonical')], input=json.dumps(body).encode(), capture_output=True, check=True).stdout)
assert set(zero) == {'canonical_hex', 'digest'}
print(value['canonical_hex'], value['digest'], zero['canonical_hex'], zero['digest'])
PYCODE
)
read -r fixture_hex fixture_digest zero_fixture_hex zero_fixture_digest <<< "$fixture_pair"
admin_sql <<SQL
CREATE TABLE fixture.origin_resolver_payload AS SELECT decode('$fixture_hex','hex') AS canonical, decode('$fixture_digest','hex') AS digest;
CREATE TABLE fixture.origin_zero_payload AS SELECT decode('$zero_fixture_hex','hex') AS canonical, decode('$zero_fixture_digest','hex') AS digest;
SQL
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
-- The caller workload has a different complete scope from the API target.
INSERT INTO contour.projects VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001800');
INSERT INTO contour.services VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800');
INSERT INTO contour.environments VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800');
INSERT INTO contour.deployments VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800');
INSERT INTO contour.workload_instances VALUES
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001803'),
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001804'),
 ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001805');
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001801','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001800','00000000-0000-0000-0000-000000001803','trusted_platform_v1',decode(repeat('a1',32),'hex'));
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001802','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001804','trusted_platform_v1',decode(repeat('a2',32),'hex'));
SELECT contour.enroll_origin('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001806','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001805','trusted_platform_v1',decode(repeat('a3',32),'hex'));
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001811','00000000-0000-0000-0000-000000001801',decode(repeat('a1',32),'hex'));
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001812','00000000-0000-0000-0000-000000001802',decode(repeat('a2',32),'hex'));
SELECT contour.enroll_origin_credential('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001813','00000000-0000-0000-0000-000000001806',decode(repeat('a3',32),'hex'));
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001821','00000000-0000-0000-0000-000000001801','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001822','00000000-0000-0000-0000-000000001802','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
SELECT contour.grant_origin_observer('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001824','00000000-0000-0000-0000-000000001806','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001');
GRANT SELECT ON fixture.origin_resolver_payload TO contour_origin_ingress_test, contour_catalog_worker_test;
GRANT SELECT ON fixture.origin_zero_payload TO contour_origin_ingress_test, contour_catalog_worker_test;
INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
 SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',digest,2,3 FROM fixture.origin_resolver_payload;
INSERT INTO contour.ingestion_payloads SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',2,canonical FROM fixture.origin_resolver_payload;
INSERT INTO contour.ingestion_v2_metadata
 SELECT b.tenant_id,b.collector_id,b.batch_id,r.id::uuid,2,b.request_digest,b.accepted_at,
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1','unattributed'
 FROM contour.ingestion_batches b CROSS JOIN (VALUES ('00000000-0000-4000-8000-000000001841'),('00000000-0000-4000-8000-000000001842'),('00000000-0000-4000-8000-000000001843')) r(id)
 WHERE b.batch_id='00000000-0000-4000-8000-000000001831';
INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
 SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001859',digest,2,3 FROM fixture.origin_zero_payload;
INSERT INTO contour.ingestion_payloads SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001859',2,canonical FROM fixture.origin_zero_payload;
INSERT INTO contour.ingestion_v2_metadata
 SELECT b.tenant_id,b.collector_id,b.batch_id,r.id::uuid,2,b.request_digest,b.accepted_at,
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1','unattributed'
 FROM contour.ingestion_batches b CROSS JOIN (VALUES ('00000000-0000-4000-8000-000000001841'),('00000000-0000-4000-8000-000000001842'),('00000000-0000-4000-8000-000000001843')) r(id)
 WHERE b.batch_id='00000000-0000-4000-8000-000000001859';
SQL
# A mixed batch for real restricted-role writes. Canonical bytes are checked by
# the SQL digest contract; strict SDK admission is exercised by the Rust suite.
admin_sql <<'SQL'
CREATE TABLE fixture.origin_binding_floor AS SELECT epoch,clock_floor FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
CREATE TABLE fixture.origin_binding_payload AS
WITH source AS (
 SELECT jsonb_set(jsonb_set(convert_from(canonical,'UTF8')::jsonb,
   '{batch_id}',to_jsonb('00000000-0000-4000-8000-000000001860'::text)),
   '{records,2,origin_witness}','{"kind":"unattributed"}'::jsonb) AS body
 FROM fixture.origin_resolver_payload
), encoded AS (SELECT convert_to(body::text,'UTF8') AS canonical FROM source)
SELECT canonical,sha256(convert_to(E'apicontour/batch/2\n','UTF8') || canonical) AS digest FROM encoded;
GRANT SELECT ON fixture.origin_binding_payload TO contour_origin_ingress_test;
CREATE FUNCTION fixture.origin_binding_insert(metadata_count integer DEFAULT 3) RETURNS void
LANGUAGE plpgsql SECURITY INVOKER AS $$
BEGIN
 INSERT INTO contour.ingestion_batches(tenant_id,collector_id,batch_id,request_digest,digest_version,record_count)
 SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',digest,2,3 FROM fixture.origin_binding_payload;
 INSERT INTO contour.ingestion_payloads SELECT 'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',2,canonical FROM fixture.origin_binding_payload;
 INSERT INTO contour.ingestion_v2_metadata
 SELECT b.tenant_id,b.collector_id,b.batch_id,r.id::uuid,2,b.request_digest,b.accepted_at,
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',
 '00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001',1,'http_json_v1',
 CASE WHEN r.n<3 OR metadata_count=4 THEN 'verified_origin_v1' ELSE 'unattributed' END
 FROM contour.ingestion_batches b CROSS JOIN (VALUES (1,'00000000-0000-4000-8000-000000001841'),(2,'00000000-0000-4000-8000-000000001842'),(3,'00000000-0000-4000-8000-000000001843')) r(n,id)
 WHERE b.batch_id='00000000-0000-4000-8000-000000001860' AND r.n<=metadata_count;
END $$;
GRANT EXECUTE ON FUNCTION fixture.origin_binding_insert(integer) TO contour_origin_ingress_test;
SQL
# Exercise an actual COMMIT failure, and require the intended integrity SQLSTATE.
if binding_commit_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture 2>&1 <<'SQL'
\set VERBOSITY verbose
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(3);
CREATE TEMP TABLE origin_pending_batch (transaction_id bigint, backend_pid integer, tenant_id uuid, collector_id uuid, batch_id uuid);
INSERT INTO origin_pending_batch VALUES (txid_current(),pg_backend_pid(),'aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860');
SELECT 'pending temp forgery prepared';
COMMIT;
SQL
); then
    printf '%s\n' "$binding_commit_output"
    echo 'missing proof unexpectedly committed' >&2
    exit 1
fi
printf '%s\n' "$binding_commit_output"
if [[ "$binding_commit_output" != *'23514'* || "$binding_commit_output" != *'pending temp forgery prepared'* ]]; then
    echo 'missing proof failed for an unexpected reason' >&2
    exit 1
fi
# Fault injection is isolated in transactions that must fail at COMMIT. All
# writes before the injection use the real restricted ingress role and writer.
for binding_fault in missing_proof extra_proof corrupt_proof missing_marker corrupt_marker; do
    if binding_fault_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 -v binding_fault="$binding_fault" \
        -h /var/run/postgresql -U postgres -d contour_fixture 2>&1 <<'SQL'
\set VERBOSITY verbose
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT set_config('fixture.binding_fault', :'binding_fault', true);
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(3);
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',canonical)=2 FROM fixture.origin_binding_payload), 'fault fixture starts with complete proofs');
RESET ROLE;
SET LOCAL session_replication_role=replica;
DO $$ DECLARE p contour.origin_proofs; changed integer; fault text := current_setting('fixture.binding_fault'); BEGIN
 IF fault='missing_proof' THEN
  DELETE FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841';
 ELSIF fault='extra_proof' THEN
  SELECT * INTO STRICT p FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841';
  p.proof_id:=pg_catalog.gen_random_uuid(); p.record_id:='00000000-0000-4000-8000-000000001843';
  INSERT INTO contour.origin_proofs SELECT (p).*;
 ELSIF fault='corrupt_proof' THEN
  UPDATE contour.origin_proofs SET canonical_proof=decode('00','hex') WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841';
 ELSIF fault='missing_marker' THEN
  DELETE FROM contour.origin_batch_proof_completion WHERE batch_id='00000000-0000-4000-8000-000000001860';
 ELSIF fault='corrupt_marker' THEN
  UPDATE contour.origin_batch_proof_completion SET proof_set_digest=decode(repeat('00',32),'hex') WHERE batch_id='00000000-0000-4000-8000-000000001860';
 ELSE RAISE EXCEPTION 'unknown fixture fault'; END IF;
 GET DIAGNOSTICS changed = ROW_COUNT;
 IF changed<>1 THEN RAISE EXCEPTION 'fixture fault did not alter one row'; END IF;
END $$;
SET LOCAL session_replication_role=origin;
SELECT 'binding mutation ready';
COMMIT;
SQL
    ); then
        printf '%s\n' "$binding_fault_output"
        echo "$binding_fault unexpectedly committed" >&2
        exit 1
    fi
    printf '%s\n' "$binding_fault_output"
    if [[ "$binding_fault_output" != *'binding mutation ready'* || "$binding_fault_output" != *'23514'* ]]; then
        echo "$binding_fault failed before COMMIT or with an unexpected SQLSTATE" >&2
        exit 1
    fi
done
# Flushing only the proof guard must not let a later unattributed metadata row
# escape the final integrity check while the real Q+C capability is still live.
if binding_late_metadata_output=$(docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture 2>&1 <<'SQL'
\set VERBOSITY verbose
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(3);
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',canonical)=2 FROM fixture.origin_binding_payload), 'late metadata fixture starts with complete verified batch');
SET CONSTRAINTS contour.check_origin_pending_batch IMMEDIATE;
SELECT contour.require_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET CONSTRAINTS contour.check_origin_pending_batch DEFERRED;
INSERT INTO contour.ingestion_v2_metadata
 SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-000000001849',digest_version,request_digest,accepted_at,
 source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,'unattributed'
 FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841';
SELECT 'late metadata inserted after named guard';
COMMIT;
SQL
); then
    printf '%s\n' "$binding_late_metadata_output"
    echo 'extra metadata unexpectedly committed after named guard' >&2
    exit 1
fi
printf '%s\n' "$binding_late_metadata_output"
if [[ "$binding_late_metadata_output" != *'late metadata inserted after named guard'* || "$binding_late_metadata_output" != *'23514'* ]]; then
    echo 'late metadata failed before COMMIT or with an unexpected SQLSTATE' >&2
    exit 1
fi
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_pending_batch$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_pending_batch DEFAULT VALUES$q$,'42501');
SELECT fixture.expect_state($q$SELECT fixture.origin_binding_insert(3)$q$,'42501');
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.origin_insert_authorized('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000002')$q$,'42501');
SELECT fixture.origin_binding_insert(3);
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',(SELECT canonical || decode('20','hex') FROM fixture.origin_binding_payload))$q$,'23514');
-- A missing proof set must fail even when deferred checks are forced early.
SELECT fixture.expect_state($q$SET CONSTRAINTS contour.check_origin_pending_batch IMMEDIATE$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(2);
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',(SELECT canonical FROM fixture.origin_binding_payload))$q$,'23514');
SELECT fixture.expect_state($q$SET CONSTRAINTS contour.check_origin_pending_batch IMMEDIATE$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(4);
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',(SELECT canonical FROM fixture.origin_binding_payload))$q$,'23514');
SELECT fixture.expect_state($q$SET CONSTRAINTS contour.check_origin_pending_batch IMMEDIATE$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.origin_binding_insert(3);
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',canonical)=2 FROM fixture.origin_binding_payload), 'mixed verified proof set');
-- Context cleanup is queued first; changed caller GUC must not hide the batch.
SELECT set_config('apicontour.tenant_id','bbbbbbbb-0000-0000-0000-000000000000',true);
COMMIT;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',canonical)=2 FROM fixture.origin_binding_payload), 'mixed batch historical verification');
ROLLBACK;
SQL
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.origin_pending_batch), 'deferred queue cleared after commit and abort');
SET ROLE contour_v2_ingress_test;
-- Basic V2 cannot append even an unattributed row to a verified batch.
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_v2_metadata
 SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-000000001849',digest_version,request_digest,accepted_at,
 source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,'unattributed'
 FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841'$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.ingestion_v2_metadata
 SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-000000001849',digest_version,request_digest,accepted_at,
 source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,'verified_origin_v1'
 FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841'$q$,'42501');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=2 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860'), 'mixed batch retained exact proofs');
SELECT fixture.assert((SELECT origin_project_id='00000000-0000-0000-0000-000000001800' AND project_id='00000000-0000-0000-0000-000000000001' FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860' AND record_id='00000000-0000-4000-8000-000000001841'), 'origin and API scopes remain distinct');
-- Close a real lifecycle after commit. The restricted historical retry must be
-- read-only and retain the original receipt, all proof bytes, and quota usage.
CREATE TEMP TABLE origin_binding_receipt_before AS
 SELECT receipt_id,accepted_at,request_digest FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-000000001860';
CREATE TEMP TABLE origin_binding_proofs_before AS
 SELECT * FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860';
CREATE TEMP TABLE origin_binding_usage_before AS
 SELECT * FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000001801');
SET ROLE contour_origin_ingress_test;
SELECT fixture.assert((SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001860',canonical)=2 FROM fixture.origin_binding_payload), 'verified historical retry after closure');
RESET ROLE;
SELECT fixture.assert(NOT EXISTS ((SELECT receipt_id,accepted_at,request_digest FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-000000001860' EXCEPT ALL SELECT * FROM origin_binding_receipt_before) UNION ALL (SELECT * FROM origin_binding_receipt_before EXCEPT ALL SELECT receipt_id,accepted_at,request_digest FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-000000001860')), 'historical retry preserves receipt');
SELECT fixture.assert(NOT EXISTS ((SELECT * FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860' EXCEPT ALL SELECT * FROM origin_binding_proofs_before) UNION ALL (SELECT * FROM origin_binding_proofs_before EXCEPT ALL SELECT * FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860')), 'historical retry preserves proofs');
SELECT fixture.assert(NOT EXISTS ((SELECT * FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' EXCEPT ALL SELECT * FROM origin_binding_usage_before) UNION ALL (SELECT * FROM origin_binding_usage_before EXCEPT ALL SELECT * FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000')), 'historical retry preserves usage');
-- Restore the isolated fixture state for the pre-existing B2 quota tests.
BEGIN;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001860';
DELETE FROM contour.origin_batch_proof_completion WHERE batch_id='00000000-0000-4000-8000-000000001860';
DELETE FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001860';
DELETE FROM contour.ingestion_payloads WHERE batch_id='00000000-0000-4000-8000-000000001860';
DELETE FROM contour.ingestion_batches WHERE batch_id='00000000-0000-4000-8000-000000001860';
DELETE FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
DELETE FROM contour.origin_terminal_events WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND event_kind='lifecycle_closed' AND lifecycle_id='00000000-0000-0000-0000-000000001801';
UPDATE contour.origin_tenant_state SET epoch=(SELECT epoch FROM fixture.origin_binding_floor),clock_floor=(SELECT clock_floor FROM fixture.origin_binding_floor) WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
COMMIT;
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT fixture.assert((SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001859',canonical)=0 FROM fixture.origin_zero_payload), 'readonly zero fingerprint batch');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'42501');
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001859',canonical)=0 FROM fixture.origin_zero_payload), 'writer zero fingerprint batch');
SELECT fixture.assert((SELECT (contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',canonical)).lifecycle_id='00000000-0000-0000-0000-000000001801' FROM fixture.origin_resolver_payload), 'leaf A resolves dedicated lifecycle');
SELECT fixture.assert((SELECT (contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001842',canonical)).instance_id='00000000-0000-0000-0000-000000001804' FROM fixture.origin_resolver_payload), 'leaf B resolves distinct instance');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical||decode('20','hex') FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001849',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'42501');
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_credentials$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_credentials DEFAULT VALUES$q$,'42501');
ROLLBACK;
SQL
# The real restricted role exercises the writer; the fixture transaction rolls
# back all proofs and the synthetic ledger seeds used for boundary arithmetic.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
CREATE TEMP TABLE origin_writer_floor_before AS SELECT clock_floor FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SAVEPOINT writer_probe;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=3 FROM fixture.origin_resolver_payload), 'three newly admitted proofs');
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_logical_usage$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_logical_usage VALUES ('aaaaaaaa-0000-0000-0000-000000000000',0)$q$,'42501');
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_batch_proof_completion$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_batch_proof_completion DEFAULT VALUES$q$,'42501');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=3 AND count(DISTINCT instance_id)=3 AND bool_and(contour.verify_origin_proof(tenant_id,proof_id)) FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'distinct proof bindings verify');
SELECT fixture.assert((SELECT used_bytes=(SELECT sum(octet_length(canonical_proof)) FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831') FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'usage equals encoded proof bytes');
SELECT fixture.assert((SELECT clock_floor >= (SELECT max(proof_accepted_at) FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831') FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'proof advances tenant clock');
SELECT fixture.assert((SELECT s.clock_floor > f.clock_floor FROM contour.origin_tenant_state s CROSS JOIN origin_writer_floor_before f WHERE s.tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'proof advances previous floor');
CREATE TEMP TABLE origin_writer_clock_original AS SELECT proof_id,proof_accepted_at,canonical_proof FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831';
CREATE TEMP TABLE origin_writer_usage_original AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
-- The admission still holds Q; a second public begin is deliberately refused as
-- preheld. Exercise the same enrollment insert/epoch trigger under that gate.
GRANT SELECT ON origin_writer_floor_before TO contour_owner;
SET LOCAL ROLE contour_owner;
DO $$ DECLARE prior_floor timestamptz; BEGIN
 SELECT clock_floor INTO STRICT prior_floor FROM origin_writer_floor_before;
 IF prior_floor IS NULL OR NOT pg_catalog.isfinite(prior_floor) THEN RAISE EXCEPTION 'invalid pre-proof fixture floor'; END IF;
 EXECUTE pg_catalog.format('CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS %L', 'SELECT ' || pg_catalog.quote_literal(prior_floor::text) || '::timestamptz');
END $$;
RESET ROLE;
SELECT fixture.expect_state($q$INSERT INTO contour.origin_lifecycles (tenant_id,lifecycle_id,project_id,service_id,environment_id,deployment_id,instance_id,platform_kind,platform_evidence_sha256,enrolled_at) VALUES ('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000001798','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000000001','00000000-0000-0000-0000-000000001799','trusted_platform_v1',decode(repeat('aa',32),'hex'),contour.origin_server_time())$q$,'23514');
SELECT fixture.assert((SELECT count(*)=3 FROM contour.origin_proofs p JOIN origin_writer_clock_original o USING (proof_id,proof_accepted_at,canonical_proof)), 'regressed enrollment preserves proof');
SELECT fixture.assert((SELECT u.used_bytes=o.used_bytes FROM contour.origin_logical_usage u CROSS JOIN origin_writer_usage_original o WHERE u.tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'regressed enrollment preserves usage');
-- Save the measured bounded encoding size in a session variable across rollback.
SELECT used_bytes AS origin_proof_total FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' \gset
ROLLBACK TO writer_probe;
INSERT INTO contour.origin_logical_usage VALUES ('aaaaaaaa-0000-0000-0000-000000000000',1073741824-:'origin_proof_total'::bigint);
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=3 FROM fixture.origin_resolver_payload), 'exact quota accepted');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=0 FROM fixture.origin_resolver_payload), 'duplicate succeeds at full quota');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'exact quota counted');
SELECT fixture.assert((SELECT count(*)=1 AND proof_count=3 FROM contour.origin_batch_proof_completion WHERE batch_id='00000000-0000-4000-8000-000000001831' GROUP BY proof_count), 'completion marker binds proof count');
SELECT fixture.expect_state($q$UPDATE contour.origin_batch_proof_completion SET proof_count=proof_count$q$,'23514');
SELECT fixture.expect_state($q$DELETE FROM contour.origin_batch_proof_completion$q$,'23514');
SAVEPOINT marker_damage;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_proofs WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'missing one never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'missing all never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
UPDATE contour.origin_proofs SET record_id='00000000-0000-4000-8000-000000001849' WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'remapped proof never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
DO $$ DECLARE p contour.origin_proofs; BEGIN SELECT * INTO STRICT p FROM contour.origin_proofs WHERE record_id='00000000-0000-4000-8000-000000001841'; p.proof_id:=pg_catalog.gen_random_uuid(); p.record_id:='00000000-0000-4000-8000-000000001849'; INSERT INTO contour.origin_proofs SELECT (p).*; END $$;
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'extra proof never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
UPDATE contour.origin_batch_proof_completion SET proof_set_digest=decode(repeat('00',32),'hex') WHERE batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'corrupt marker never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_batch_proof_completion WHERE batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'missing marker never charges');
ROLLBACK TO marker_damage;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_proofs WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND collector_id='00000000-0000-0000-0000-000000000001' AND batch_id='00000000-0000-4000-8000-000000001831';
DELETE FROM contour.origin_batch_proof_completion WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND collector_id='00000000-0000-0000-0000-000000000001' AND batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831') AND NOT EXISTS (SELECT 1 FROM contour.origin_batch_proof_completion WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'readonly verification does not recreate erased evidence');
SELECT fixture.assert((SELECT used_bytes=1073741824 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'readonly verification does not alter usage');
ROLLBACK TO marker_damage;
-- A later terminal event leaves the original immutable proof and full ledger intact.
CREATE TEMP TABLE origin_writer_original AS SELECT proof_id,proof_accepted_at,canonical_proof FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,lifecycle_id,event_at,fact_epoch)
 SELECT tenant_id,'lifecycle_closed',lifecycle_id,greatest(context_time+interval '1 second',proof_accepted_at),context_epoch+1 FROM contour.origin_proofs WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=0 FROM fixture.origin_resolver_payload), 'closed origin exact retry');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=3 FROM contour.origin_proofs p JOIN origin_writer_original o USING (proof_id,proof_accepted_at,canonical_proof)), 'retry preserves original evidence');
SET LOCAL session_replication_role=replica;
UPDATE contour.origin_proofs SET canonical_proof=decode('00','hex') WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
-- Fixture-only constraint removal models a damaged oversized stored value.
ALTER TABLE contour.origin_proofs DROP CONSTRAINT origin_proofs_canonical_proof_check;
SET LOCAL session_replication_role=replica;
UPDATE contour.origin_proofs SET canonical_proof=decode(repeat('00',4097),'hex') WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
ROLLBACK TO writer_probe;
INSERT INTO contour.origin_logical_usage VALUES ('aaaaaaaa-0000-0000-0000-000000000000',1073741825-:'origin_proof_total'::bigint);
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'54000');
DO $$ DECLARE constraint_name text; BEGIN
 BEGIN
  PERFORM contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload));
  RAISE EXCEPTION 'quota unexpectedly accepted';
 EXCEPTION WHEN SQLSTATE '54000' THEN
  GET STACKED DIAGNOSTICS constraint_name = CONSTRAINT_NAME;
  IF constraint_name IS DISTINCT FROM 'origin_logical_quota_exhausted' THEN
   RAISE EXCEPTION 'incorrect quota constraint tag';
  END IF;
 END;
END $$;
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=0 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'quota failure rolls back earlier proof inserts');
SELECT fixture.assert((SELECT used_bytes=1073741825-:'origin_proof_total'::bigint FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'quota failure rolls back charges');
ROLLBACK TO writer_probe;
-- Delete the second grant only in this rolled-back fixture: the first proof
-- would otherwise be inserted before resolution of the second fails.
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_observer_grants WHERE grant_id='00000000-0000-0000-0000-000000001822';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=0 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'later missing grant rolls back earlier proof');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'later missing grant rolls back ledger');
ROLLBACK TO writer_probe;
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,lifecycle_id,event_at,fact_epoch)
 SELECT tenant_id,'lifecycle_closed','00000000-0000-0000-0000-000000001802',clock_timestamp(),epoch+1 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=0 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'lifecycle_closed blocks new proof and rolls back batch');
ROLLBACK TO writer_probe;
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,credential_id,event_at,fact_epoch)
 SELECT tenant_id,'credential_revoked','00000000-0000-0000-0000-000000001812',clock_timestamp(),epoch+1 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=0 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'credential_revoked blocks new proof and rolls back batch');
ROLLBACK TO writer_probe;
SET LOCAL session_replication_role=replica;
INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,grant_id,event_at,fact_epoch)
 SELECT tenant_id,'grant_revoked','00000000-0000-0000-0000-000000001822',clock_timestamp(),epoch+1 FROM contour.origin_tenant_state WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SET LOCAL session_replication_role=origin;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
RESET ROLE;
SELECT fixture.assert((SELECT count(*)=0 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'grant_revoked blocks new proof and rolls back batch');
ROLLBACK;
SQL
# Real admission and real later terminal mutations at the same server timestamp.
# This isolated fixture commits only in the disposable harness database, then
# removes its proof/terminal/ledger rows with triggers disabled for fixture cleanup.
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'equal-clock fixture starts without usage');
SELECT fixture.assert(NOT EXISTS (SELECT 1 FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'equal-clock fixture starts without proofs');
CREATE TEMP TABLE origin_clock_original AS SELECT pg_get_functiondef('contour.origin_server_time()'::regprocedure) AS definition;
SET ROLE contour_owner;
DO $$ DECLARE fixed_time timestamptz; BEGIN
 SELECT greatest(pg_catalog.clock_timestamp(),s.clock_floor,b.accepted_at) INTO STRICT fixed_time
 FROM contour.origin_tenant_state s JOIN contour.ingestion_batches b ON b.tenant_id=s.tenant_id
 WHERE s.tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND b.collector_id='00000000-0000-0000-0000-000000000001' AND b.batch_id='00000000-0000-4000-8000-000000001831';
 EXECUTE pg_catalog.format('CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS %L', 'SELECT ' || pg_catalog.quote_literal(fixed_time::text) || '::timestamptz');
END $$;
RESET ROLE;
BEGIN;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=3 FROM fixture.origin_resolver_payload), 'equal-clock real admissions');
COMMIT;
CREATE TEMP TABLE origin_equal_original AS SELECT proof_id,proof_accepted_at,canonical_proof FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831';
CREATE TEMP TABLE origin_equal_usage AS SELECT used_bytes FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000001801');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000001812');
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000001824');
SELECT fixture.assert((SELECT count(*)=3 AND bool_and(e.fact_epoch>p.context_epoch AND e.event_at=p.proof_accepted_at)
 FROM contour.origin_proofs p JOIN contour.origin_terminal_events e ON e.tenant_id=p.tenant_id AND
 ((e.event_kind='lifecycle_closed' AND e.lifecycle_id=p.lifecycle_id) OR (e.event_kind='credential_revoked' AND e.credential_id=p.credential_id) OR (e.event_kind='grant_revoked' AND e.grant_id=p.grant_id))
 WHERE p.batch_id='00000000-0000-4000-8000-000000001831'), 'real later epochs share proof timestamp');
SELECT fixture.assert((SELECT count(*)=3 AND bool_and(contour.verify_origin_proof(tenant_id,proof_id)) FROM contour.origin_proofs WHERE batch_id='00000000-0000-4000-8000-000000001831'), 'equal-clock historical proofs verify');
-- The read-only capability needs no ingress begin or advisory locks.
SET ROLE contour_origin_ingress_test;
SELECT fixture.assert((SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=3 FROM fixture.origin_resolver_payload), 'readonly ingress verifies closed batch');
RESET ROLE;
SET ROLE contour_catalog_worker_test;
SELECT fixture.assert((SELECT contour.verify_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=3 FROM fixture.origin_resolver_payload), 'readonly catalog verifies closed batch');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_batch_proofs('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'42501');
RESET ROLE;
BEGIN;
SET LOCAL ROLE contour_origin_ingress_test;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.assert((SELECT contour.write_origin_batch_proofs('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831',canonical)=0 FROM fixture.origin_resolver_payload), 'equal-clock exact retry costs zero');
COMMIT;
SELECT fixture.assert((SELECT count(*)=3 FROM contour.origin_proofs p JOIN origin_equal_original o USING (proof_id,proof_accepted_at,canonical_proof)), 'equal-clock retry preserves proof');
SELECT fixture.assert((SELECT u.used_bytes=o.used_bytes FROM contour.origin_logical_usage u CROSS JOIN origin_equal_usage o WHERE u.tenant_id='aaaaaaaa-0000-0000-0000-000000000000'), 'equal-clock retry preserves usage');
DO $$ DECLARE original text; BEGIN SELECT definition INTO STRICT original FROM origin_clock_original; EXECUTE original; END $$;
BEGIN;
SET LOCAL session_replication_role=replica;
DELETE FROM contour.origin_terminal_events WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND ((event_kind='lifecycle_closed' AND lifecycle_id='00000000-0000-0000-0000-000000001801') OR (event_kind='credential_revoked' AND credential_id='00000000-0000-0000-0000-000000001812') OR (event_kind='grant_revoked' AND grant_id='00000000-0000-0000-0000-000000001824'));
DELETE FROM contour.origin_proofs WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND batch_id='00000000-0000-4000-8000-000000001831';
DELETE FROM contour.origin_batch_proof_completion WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000' AND collector_id='00000000-0000-0000-0000-000000000001' AND batch_id='00000000-0000-4000-8000-000000001831';
DELETE FROM contour.origin_logical_usage WHERE tenant_id='aaaaaaaa-0000-0000-0000-000000000000';
COMMIT;
SQL
# Exercise the private parsed-record helper under the real gate with deliberately
# altered typed metadata and an unrecognized leaf. No caller has this privilege.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SET LOCAL ROLE contour_owner;
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
DO $$ DECLARE m contour.ingestion_v2_metadata; w jsonb; BEGIN
 SELECT * INTO STRICT m FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001831' AND record_id='00000000-0000-4000-8000-000000001842';
 w := jsonb_build_object('kind','downstream_mtls_leaf_sha256_v1','leaf_sha256',repeat('ff',32));
 BEGIN PERFORM contour.resolve_origin_record_checked(m.tenant_id,m.collector_id,m,w); RAISE EXCEPTION 'unknown leaf accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 w := jsonb_build_object('kind','downstream_mtls_leaf_sha256_v1','leaf_sha256',repeat('a2',32));
 m.source_id := '00000000-0000-0000-0000-000000000002';
 BEGIN PERFORM contour.resolve_origin_record_checked(m.tenant_id,m.collector_id,m,w); RAISE EXCEPTION 'ungranted source accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
 m.source_id := '00000000-0000-0000-0000-000000000001'; m.deployment_id := '00000000-0000-0000-0000-000000000002';
 BEGIN PERFORM contour.resolve_origin_record_checked(m.tenant_id,m.collector_id,m,w); RAISE EXCEPTION 'ungranted target accepted'; EXCEPTION WHEN check_violation THEN NULL; END;
END $$;
ROLLBACK;
SQL
# Controlled corruption is fixture-only, rolled back, and never bypasses the
# resolver's checks. It tests stored wire and metadata binding independently.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET LOCAL session_replication_role=replica;
UPDATE contour.ingestion_payloads SET checked_batch=convert_to('{}','UTF8') WHERE batch_id='00000000-0000-4000-8000-000000001831';
SET LOCAL session_replication_role=origin;
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET LOCAL session_replication_role=replica;
UPDATE contour.ingestion_v2_metadata SET source_id='00000000-0000-0000-0000-000000000002' WHERE record_id='00000000-0000-4000-8000-000000001841';
SET LOCAL session_replication_role=origin;
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
SQL
# Whole-batch metadata corruption is checked even when resolving a different record.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET LOCAL session_replication_role=replica;
UPDATE contour.ingestion_v2_metadata SET policy_revision=1.000 WHERE record_id='00000000-0000-4000-8000-000000001842';
SET LOCAL session_replication_role=origin;
SELECT fixture.assert((SELECT (contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',canonical)).lifecycle_id='00000000-0000-0000-0000-000000001801' FROM fixture.origin_resolver_payload), 'numeric metadata scale accepted');
ALTER TABLE contour.ingestion_v2_metadata DROP CONSTRAINT ingestion_v2_metadata_attribution_class_check;
DO $$ DECLARE mutation text; BEGIN
 FOREACH mutation IN ARRAY ARRAY[
  $m$UPDATE contour.ingestion_v2_metadata SET source_id='00000000-0000-0000-0000-000000000002' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET parser_profile='other' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET policy_revision=1.5 WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET policy_revision='NaN' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET policy_revision='Infinity' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET policy_revision=18446744073709551616 WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET attribution_class='verified' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET accepted_at=accepted_at+interval '1 second' WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET request_digest=decode(repeat('aa',32),'hex') WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$DELETE FROM contour.ingestion_v2_metadata WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$INSERT INTO contour.ingestion_v2_metadata SELECT tenant_id,collector_id,batch_id,'00000000-0000-4000-8000-000000001849',digest_version,request_digest,accepted_at,source_id,project_id,service_id,environment_id,deployment_id,policy_revision,parser_profile,attribution_class FROM contour.ingestion_v2_metadata WHERE record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$INSERT INTO contour.ingestion_v2_metadata SELECT m.tenant_id,m.collector_id,m.batch_id,('00000000-0000-4000-8000-' || lpad(to_hex(n),12,'0'))::uuid,m.digest_version,m.request_digest,m.accepted_at,m.source_id,m.project_id,m.service_id,m.environment_id,m.deployment_id,m.policy_revision,m.parser_profile,m.attribution_class FROM contour.ingestion_v2_metadata m CROSS JOIN generate_series(100000,100500) n WHERE m.record_id='00000000-0000-4000-8000-000000001842'$m$,
  $m$UPDATE contour.ingestion_payloads SET checked_batch=convert_to('{"wire_version":2,' || substring(convert_from(checked_batch,'UTF8') from 2),'UTF8') WHERE batch_id='00000000-0000-4000-8000-000000001831'$m$
 ] LOOP
  BEGIN
   PERFORM set_config('session_replication_role','replica',true);
   EXECUTE mutation;
   PERFORM set_config('session_replication_role','origin',true);
   PERFORM fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
   RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P9001';
  EXCEPTION WHEN SQLSTATE 'P9001' THEN NULL; END;
 END LOOP;
END $$;
ROLLBACK;
SQL
# Fixture-only proof seeding for independent malformed-history checks.
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SET LOCAL ROLE contour_owner;
DO $$ DECLARE p contour.origin_proofs; m contour.ingestion_v2_metadata; l contour.origin_lifecycles;
 c contour.origin_credentials; g contour.origin_observer_grants; BEGIN
 SELECT * INTO STRICT m FROM contour.ingestion_v2_metadata WHERE batch_id='00000000-0000-4000-8000-000000001831' AND record_id='00000000-0000-4000-8000-000000001841';
 SELECT * INTO STRICT l FROM contour.origin_lifecycles WHERE lifecycle_id='00000000-0000-0000-0000-000000001801';
 SELECT * INTO STRICT c FROM contour.origin_credentials WHERE credential_id='00000000-0000-0000-0000-000000001811';
 SELECT * INTO STRICT g FROM contour.origin_observer_grants WHERE grant_id='00000000-0000-0000-0000-000000001821';
 p.tenant_id:=m.tenant_id; p.proof_id:='00000000-0000-4000-8000-000000001851';
 p.collector_id:=m.collector_id; p.batch_id:=m.batch_id; p.record_id:=m.record_id; p.request_digest:=m.request_digest;
 p.accepted_at:=m.accepted_at; p.proof_accepted_at:=clock_timestamp();
 p.source_id:=m.source_id; p.project_id:=m.project_id; p.service_id:=m.service_id; p.environment_id:=m.environment_id; p.deployment_id:=m.deployment_id;
 p.policy_revision:=m.policy_revision; p.parser_profile:=m.parser_profile;
 p.lifecycle_id:=l.lifecycle_id; p.credential_id:=c.credential_id; p.grant_id:=g.grant_id;
 p.origin_project_id:=l.project_id; p.origin_service_id:=l.service_id; p.origin_environment_id:=l.environment_id; p.origin_deployment_id:=l.deployment_id; p.instance_id:=l.instance_id;
 p.leaf_sha256:=c.leaf_sha256; p.platform_evidence_sha256:=l.platform_evidence_sha256;
 p.lifecycle_epoch:=l.fact_epoch; p.credential_epoch:=c.fact_epoch; p.grant_epoch:=g.fact_epoch;
 SELECT epoch INTO p.context_epoch FROM contour.origin_tenant_state WHERE tenant_id=m.tenant_id;
 p.context_time:=m.accepted_at; p.canonical_proof:=contour.encode_origin_proof(p);
 INSERT INTO contour.origin_proofs SELECT (p).*;
END $$;
RESET ROLE;
SELECT fixture.assert(contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851'), 'historical proof verified');
SELECT fixture.expect_state($q$UPDATE contour.origin_proofs SET source_id=source_id$q$,'23514');
SELECT fixture.expect_state($q$DELETE FROM contour.origin_proofs$q$,'23514');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_proof('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851')$q$,'42501');
SET LOCAL ROLE contour_origin_ingress_test;
SELECT fixture.assert(contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851'), 'restricted historical verifier');
SELECT fixture.expect_state($q$SELECT * FROM contour.origin_proofs$q$,'42501');
SELECT fixture.expect_state($q$INSERT INTO contour.origin_proofs DEFAULT VALUES$q$,'42501');
RESET ROLE;
SET LOCAL ROLE contour_catalog_worker_test;
SELECT fixture.assert(contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851'), 'catalog historical verifier');
SELECT fixture.expect_state($q$SELECT contour.verify_origin_proof('bbbbbbbb-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851')$q$,'42501');
RESET ROLE;
-- Fixture-only malformed timestamps and historical ordering are rolled back.
ALTER TABLE contour.origin_proofs DROP CONSTRAINT origin_proofs_context_time_check;
DO $$ DECLARE p contour.origin_proofs; kind text; scenario text; event_epoch bigint; event_time timestamptz; BEGIN
 SELECT * INTO STRICT p FROM contour.origin_proofs WHERE proof_id='00000000-0000-4000-8000-000000001851';
 FOREACH kind IN ARRAY ARRAY['lifecycle_closed','credential_revoked','grant_revoked'] LOOP
  FOREACH scenario IN ARRAY ARRAY['before','equal_time','equal_epoch','legacy','earlier_than_acceptance','after'] LOOP
   BEGIN
    event_epoch := CASE WHEN scenario='legacy' THEN 0 WHEN scenario IN ('before','equal_epoch') THEN p.context_epoch ELSE p.context_epoch+1 END;
    event_time := CASE WHEN scenario='before' THEN p.context_time-interval '1 second' WHEN scenario='equal_time' THEN p.context_time WHEN scenario='earlier_than_acceptance' THEN p.proof_accepted_at-interval '1 microsecond' ELSE greatest(p.context_time+interval '1 second',p.proof_accepted_at) END;
    PERFORM set_config('session_replication_role','replica',true);
    INSERT INTO contour.origin_terminal_events (tenant_id,event_kind,lifecycle_id,credential_id,grant_id,event_at,fact_epoch)
     VALUES (p.tenant_id,kind,CASE WHEN kind='lifecycle_closed' THEN p.lifecycle_id END,
      CASE WHEN kind='credential_revoked' THEN p.credential_id END,CASE WHEN kind='grant_revoked' THEN p.grant_id END,event_time,event_epoch);
    PERFORM set_config('session_replication_role','origin',true);
    IF scenario='after' THEN
     PERFORM fixture.assert(contour.verify_origin_proof(p.tenant_id,p.proof_id), 'strictly later terminal event retains proof');
    ELSE
     PERFORM fixture.expect_state($q$SELECT contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851')$q$,'23514');
    END IF;
    RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P9001';
   EXCEPTION WHEN SQLSTATE 'P9001' THEN NULL; END;
  END LOOP;
 END LOOP;
 BEGIN
  PERFORM set_config('session_replication_role','replica',true);
  UPDATE contour.ingestion_batches SET accepted_at=p.context_time+interval '1 second' WHERE batch_id=p.batch_id;
  UPDATE contour.ingestion_v2_metadata SET accepted_at=p.context_time+interval '1 second' WHERE tenant_id=p.tenant_id AND collector_id=p.collector_id AND batch_id=p.batch_id;
  UPDATE contour.origin_proofs SET accepted_at=p.context_time+interval '1 second',proof_accepted_at=p.context_time+interval '2 seconds' WHERE proof_id=p.proof_id;
  UPDATE contour.origin_proofs x SET canonical_proof=contour.encode_origin_proof(x) WHERE proof_id=p.proof_id;
  PERFORM set_config('session_replication_role','origin',true);
  PERFORM fixture.assert(contour.verify_origin_proof(p.tenant_id,p.proof_id), 'inbox acceptance may follow context start');
  RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P9001';
 EXCEPTION WHEN SQLSTATE 'P9001' THEN NULL; END;
END $$;
ALTER TABLE contour.ingestion_v2_metadata DROP CONSTRAINT ingestion_v2_metadata_attribution_class_check;
ALTER TABLE contour.origin_lifecycles DROP CONSTRAINT origin_lifecycles_platform_kind_check;
ALTER TABLE contour.ingestion_payloads DROP CONSTRAINT ingestion_payloads_checked_batch_check;
ALTER TABLE contour.ingestion_batches DROP CONSTRAINT ingestion_batches_record_count_check;
DO $$ DECLARE mutation text; BEGIN
 FOREACH mutation IN ARRAY ARRAY[
  $m$UPDATE contour.origin_proofs SET canonical_proof=decode('00','hex')$m$,
  $m$UPDATE contour.origin_proofs SET context_time='infinity'$m$,
  $m$UPDATE contour.origin_proofs SET source_id='00000000-0000-0000-0000-000000000002'$m$,
  $m$UPDATE contour.origin_proofs SET credential_id='00000000-0000-0000-0000-000000001812'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET parser_profile='other' WHERE record_id='00000000-0000-4000-8000-000000001841'$m$,
  $m$UPDATE contour.ingestion_v2_metadata SET attribution_class=repeat('x',5000) WHERE record_id='00000000-0000-4000-8000-000000001841'$m$,
  $m$UPDATE contour.origin_lifecycles SET platform_kind=repeat('x',5000) WHERE lifecycle_id='00000000-0000-0000-0000-000000001801'$m$,
  $m$UPDATE contour.ingestion_payloads SET checked_batch=decode(repeat('20',1048577),'hex') WHERE batch_id='00000000-0000-4000-8000-000000001831'$m$,
  $m$UPDATE contour.ingestion_batches SET record_count=501 WHERE batch_id='00000000-0000-4000-8000-000000001831'$m$
 ] LOOP
  BEGIN
   PERFORM set_config('session_replication_role','replica',true); EXECUTE mutation;
   IF mutation LIKE '%SET source_id=%' OR mutation LIKE '%SET credential_id=%' THEN
    UPDATE contour.origin_proofs p SET canonical_proof=contour.encode_origin_proof(p);
   END IF;
   PERFORM set_config('session_replication_role','origin',true);
   PERFORM fixture.expect_state($q$SELECT contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851')$q$,'23514');
   RAISE EXCEPTION 'fixture rollback' USING ERRCODE='P9001';
  EXCEPTION WHEN SQLSTATE 'P9001' THEN NULL; END;
 END LOOP;
END $$;
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000001801');
SELECT fixture.assert(contour.verify_origin_proof('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-4000-8000-000000001851'), 'closed lifecycle retains historical proof');
ROLLBACK;
SQL
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','grant_revoked','00000000-0000-0000-0000-000000001821');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
SQL
admin_sql <<'SQL'
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','credential_revoked','00000000-0000-0000-0000-000000001812');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001842',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
SQL
admin_sql <<'SQL'
-- Close the independently enrolled third lifecycle while its credential and grant remain live.
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',false);
SELECT contour.end_origin('aaaaaaaa-0000-0000-0000-000000000000','lifecycle_closed','00000000-0000-0000-0000-000000001806');
SQL
docker exec -i "$container_id" psql -X -v ON_ERROR_STOP=1 \
    -h /var/run/postgresql -U contour_origin_ingress_test -d contour_fixture <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001843',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT pg_advisory_xact_lock(1330792270,hashtext('aaaaaaaa-0000-0000-0000-000000000000'));
SELECT pg_advisory_xact_lock(fixture.origin_collector_key('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001'));
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001841',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'42501');
ROLLBACK;
SQL
admin_sql <<'SQL'
BEGIN;
SELECT set_config('apicontour.tenant_id','aaaaaaaa-0000-0000-0000-000000000000',true);
SELECT contour.begin_origin_ingress('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001');
SET LOCAL ROLE contour_owner;
CREATE OR REPLACE FUNCTION contour.origin_server_time() RETURNS timestamptz LANGUAGE sql VOLATILE SECURITY INVOKER SET search_path=pg_catalog AS $$ SELECT '2000-01-01 UTC'::timestamptz $$;
RESET ROLE;
SELECT fixture.expect_state($q$SELECT contour.resolve_origin_record('aaaaaaaa-0000-0000-0000-000000000000','00000000-0000-0000-0000-000000000001','00000000-0000-4000-8000-000000001831','00000000-0000-4000-8000-000000001842',(SELECT canonical FROM fixture.origin_resolver_payload))$q$,'23514');
ROLLBACK;
SQL
echo 'PostgreSQL opt-in current origin resolver fixture passed'
