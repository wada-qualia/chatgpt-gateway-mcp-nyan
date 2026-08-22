#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <gateway-test-image>" >&2
  exit 64
fi

image="$1"
commit="${GIT_COMMIT:-manual}"
build_number="${BUILD_NUMBER:-manual}"
short_commit="${commit:0:12}"
suffix="${build_number}-${short_commit}"
network="gateway-pgtest-${suffix}"
container="gateway-pgtest-pg-${suffix}"
label_commit="com.k-lab.gateway.pgtest.commit=${commit}"
label_build="com.k-lab.gateway.pgtest.build=${build_number}"

cleanup() {
  docker rm -f "${container}" >/dev/null 2>&1 || true
  docker network rm "${network}" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

# BUILD_NUMBER + commit makes these resources job-owned. Clearing an exact stale
# name is bounded recovery for the same Jenkins execution identity only.
cleanup

docker image inspect "${image}" >/dev/null
docker network create \
  --label "${label_commit}" \
  --label "${label_build}" \
  "${network}" >/dev/null

docker run -d \
  --name "${container}" \
  --network "${network}" \
  --label "${label_commit}" \
  --label "${label_build}" \
  -e POSTGRES_HOST_AUTH_METHOD=trust \
  -e POSTGRES_DB=gateway_test \
  postgres:16-alpine >/dev/null

ready=false
for _attempt in $(seq 1 60); do
  if docker exec "${container}" pg_isready -h 127.0.0.1 -U postgres -d gateway_test >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "${ready}" != "true" ]]; then
  echo "PostgreSQL 16 test database did not become ready within 60 seconds" >&2
  docker logs --tail 100 "${container}" >&2 || true
  exit 1
fi

docker exec "${container}" pg_isready -h 127.0.0.1 -U postgres -d gateway_test

docker run --rm \
  --network "${network}" \
  -e "GATEWAY_TEST_POSTGRES_URL=postgresql+psycopg://postgres@${container}:5432/gateway_test" \
  --entrypoint /bin/sh \
  "${image}" \
  -lc 'cd /app && python -m pytest services/gateway-api/tests/test_schema_migrations_postgresql.py services/gateway-api/tests/test_outbox_history_delete_postgresql.py services/gateway-api/tests/test_outbox_history_rehydrate_postgresql.py -q'

echo "PostgreSQL 16 schema-migration, outbox-offload and rehydration gate passed commit=${commit} build=${build_number}"
