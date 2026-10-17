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
