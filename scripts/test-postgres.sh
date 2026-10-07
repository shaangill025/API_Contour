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
