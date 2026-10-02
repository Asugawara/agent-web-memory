#!/usr/bin/env bash
# Self-hosting smoke test (plan-v3-team §3.9.4 item 2, TM30).
#
# One server, two clients (A, the admin, and B, a member), the whole generic path:
#   init (bootstrap hash), start, create, invite, join, approve, share, capture a fixture,
#   push, pull (B's search shows A's note), backup --verify, one more record, kill -9 before the
#   next incremental, wipe, restore, start, check (no FAIL), A's sync re-seeds the lost record,
#   forget on A removes the record from B.
#
# Modes (one per run):
#   --store sqlite --tls pebble   awm serve --data DIR --domain localhost against a local Pebble
#                                 ACME server (needs PEBBLE_BIN and openssl); the default
#   --store pg                    awm serve --database-url-env ... behind a (pretend) proxy on
#                                 loopback against the Postgres of AWM_TEST_PG_URL (a superuser
#                                 URL; the run creates and drops its own database and two roles)
#   --image TAG                   the container image (docker run, ports on 127.0.0.1, named
#                                 volume, the TLS-free proxy mode of docs/self-host.md)
# Options:
#   --seed N                      add N records to A before the backup and print the restore time
#   --keep                        keep the scratch directory (and print its path)
#
# Environment: AWM_BIN (default target/release/awm, built with --features sync,serve --locked
# when missing), PEBBLE_BIN, AWM_TEST_PG_URL, AWM_SMOKE_PG_CONTAINER (only when psql is not
# installed: a running Postgres container to run psql in). Needs jq, sqlite3, curl; openssl in
# the Pebble mode; psql in the pg mode; docker in the image mode.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
FIXTURE="$ROOT/crates/awm/tests/fixtures/hooks/PostToolUse-WebFetch-plugin-3.json"

STORE=sqlite
TLS=""
IMAGE=""
SEED=0
KEEP=0

usage() {
  sed -n '2,/^set -euo/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'
}

die() {
  printf 'smoke: %s\n' "$*" >&2
  exit 1
}

while [ $# -gt 0 ]; do
  case "$1" in
    --store) STORE="${2:?--store takes sqlite or pg}"; shift 2 ;;
    --tls) TLS="${2:?--tls takes pebble}"; shift 2 ;;
    --image) IMAGE="${2:?--image takes an image name}"; shift 2 ;;
    --seed) SEED="${2:?--seed takes a number}"; shift 2 ;;
    --keep) KEEP=1; shift ;;
    -h | --help) usage; exit 0 ;;
    *) die "unknown argument: $1 (try --help)" ;;
  esac
done

case "$SEED" in '' | *[!0-9]*) die "--seed takes a number" ;; esac
if [ -n "$IMAGE" ]; then
  MODE=image
elif [ "$STORE" = pg ]; then
  MODE=pg
elif [ "$STORE" = sqlite ]; then
  MODE=sqlite
  TLS="${TLS:-pebble}"
  [ "$TLS" = pebble ] || die "--tls takes pebble"
else
  die "--store takes sqlite or pg"
fi

for tool in jq sqlite3 curl; do
  command -v "$tool" >/dev/null 2>&1 || die "$tool is required"
done

# A configuration from the caller's environment must not leak into the server under test.
unset AWM_CONFIG AWM_DATA AWM_DATABASE_URL_ENV AWM_DATABASE_URL_OWNER_ENV AWM_DOMAIN AWM_BACKUP \
  AWM_BEHIND_TLS_PROXY AWM_TRUSTED_PROXY AWM_LISTEN AWM_ACME_EMAIL AWM_ACME_CHALLENGE \
  AWM_ACME_DIRECTORY AWM_ACME_STAGING AWM_ACME_CA_FILE AWM_ACME_HTTP_LISTEN \
  AWM_BOOTSTRAP_SHA256 AWM_BOOTSTRAP_EXPIRES AWM_HOME AWM_DEBUG

RUN="$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || true)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/awm-smoke.XXXXXX")"
WORK="$(cd "$WORK" && pwd -P)"
DATA="$WORK/data"
BACKUP="$WORK/backup"
PROJ="$WORK/proj"
mkdir -p "$BACKUP" "$PROJ" "$WORK/a/awm" "$WORK/a/home" "$WORK/b/awm" "$WORK/b/home"

# ---------------------------------------------------------------------------------------------
# State for the cleanup trap

SERVER_PID=""
PEBBLE_PID=""
CNAME="awm-smoke-$RUN"
DVOL="awm-smoke-$RUN-data"
DOCKER_USED=0
PG_DB=""
PG_OWNER=""
PG_APP=""
CURRENT_STEP="setup"
STEP_NAMES=()
STEP_SECS=()
RESTORE_SECS=""
RESTORE_RECORDS=""

now() {
  if [ -n "${EPOCHREALTIME:-}" ]; then
    printf '%s' "${EPOCHREALTIME/,/.}"
  elif command -v perl >/dev/null 2>&1; then
    perl -MTime::HiRes=time -e 'printf "%.3f", time'
  else
    date +%s
  fi
}

elapsed() {
  awk -v a="$1" -v b="$2" 'BEGIN { printf "%.1f", b - a }'
}

run_step() {
  local name=$1 t0 t1
  shift
  CURRENT_STEP=$name
  printf '== %s\n' "$name"
  t0="$(now)"
  "$@"
  t1="$(now)"
  STEP_NAMES+=("$name")
  STEP_SECS+=("$(elapsed "$t0" "$t1")")
}

print_table() {
  local i total=0
  printf '\nstep                          seconds   (mode %s)\n' "$MODE"
  for i in "${!STEP_NAMES[@]}"; do
    printf '%-28s %8s\n' "${STEP_NAMES[$i]}" "${STEP_SECS[$i]}"
    total="$(awk -v a="$total" -v b="${STEP_SECS[$i]}" 'BEGIN { printf "%.1f", a + b }')"
  done
  printf '%-28s %8s\n' "total" "$total"
  if [ -n "$RESTORE_SECS" ]; then
    printf 'restore of %s seeded records: %s s\n' "$RESTORE_RECORDS" "$RESTORE_SECS"
  fi
}

stop_pid() {
  local pid=$1 i
  [ -n "$pid" ] || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
}

cleanup() {
  stop_pid "$SERVER_PID"
  SERVER_PID=""
  stop_pid "$PEBBLE_PID"
  PEBBLE_PID=""
  if [ "$DOCKER_USED" = 1 ]; then
    docker rm -f "$CNAME" >/dev/null 2>&1 || true
    docker volume rm "$DVOL" >/dev/null 2>&1 || true
  fi
  if [ -n "$PG_DB" ]; then
    psql_su "DROP DATABASE IF EXISTS \"$PG_DB\" WITH (FORCE)" >/dev/null 2>&1 || true
    psql_su "DROP ROLE IF EXISTS \"$PG_APP\"" >/dev/null 2>&1 || true
    psql_su "DROP ROLE IF EXISTS \"$PG_OWNER\"" >/dev/null 2>&1 || true
  fi
  if [ "$KEEP" = 1 ]; then
    printf 'scratch directory kept: %s\n' "$WORK"
  else
    # Files that a container wrote into the backup directory belong to another uid on Linux.
    chmod -R u+rwX "$WORK" 2>/dev/null || true
    rm -rf "$WORK" 2>/dev/null || true
  fi
}

on_exit() {
  local rc=$?
  trap - EXIT INT TERM
  set +e
  if [ "$rc" -ne 0 ]; then
    printf '\nsmoke: FAILED at step "%s" (exit %s)\n' "$CURRENT_STEP" "$rc" >&2
    if [ "$MODE" = image ] && [ "$DOCKER_USED" = 1 ]; then
      docker logs --tail 40 "$CNAME" >&2 2>&1
    elif [ -f "$WORK/server.log" ]; then
      printf -- '--- server.log (tail)\n' >&2
      tail -n 40 "$WORK/server.log" >&2
    fi
  fi
  print_table
  cleanup
  if [ "$rc" -eq 0 ]; then
    printf 'smoke: ok (%s)\n' "$MODE"
  fi
  exit "$rc"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ---------------------------------------------------------------------------------------------
# Helpers

PORTS_USED=" "
free_port() {
  local p
  while :; do
    p=$((20000 + RANDOM % 20000))
    case "$PORTS_USED" in *" $p "*) continue ;; esac
    if ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null; then
      PORTS_USED="$PORTS_USED$p "
      printf '%s' "$p"
      return 0
    fi
  done
}

# The client commands: A and B each have an AWM_HOME and a HOME of their own.
awm_as() {
  local who=$1
  shift
  AWM_HOME="$WORK/$who/awm" HOME="$WORK/$who/home" "$AWM_BIN" "$@"
}

# Extracts the number after "word " in a sync summary line ("synced: pushed 3, pulled 1").
count_of() {
  local word=$1 text=$2
  printf '%s\n' "$text" | sed -n "s/.*${word} \([0-9][0-9]*\).*/\1/p" | sed -n 1p
}

# Pipes a copy of the WebFetch fixture, moved into the shared project, to the capture hook.
capture() {
  local who=$1 url=$2 text=$3
  jq -c --arg cwd "$PROJ" --arg url "$url" --arg text "$text" --arg id "toolu_smoke_$RANDOM$RANDOM$RANDOM" '
      .cwd = $cwd | .tool_use_id = $id
      | .tool_input.url = $url | .tool_response.url = $url | .tool_response.result = $text' \
    "$FIXTURE" | awm_as "$who" hook capture
}

wait_http() {
  local url=$1 i
  shift
  for i in $(seq 1 180); do
    if curl -fsS --max-time 2 "$@" "$url" >/dev/null 2>&1; then
      return 0
    fi
    if [ -n "$SERVER_PID" ] && ! kill -0 "$SERVER_PID" 2>/dev/null; then
      die "the server exited while starting"
    fi
    sleep 0.5
  done
  die "$url did not answer within 90 s"
}

psql_su() {
  # A superuser statement on the maintenance database of AWM_TEST_PG_URL.
  if command -v psql >/dev/null 2>&1; then
    PGOPTIONS="-c client_min_messages=warning" psql "$AWM_TEST_PG_URL" -v ON_ERROR_STOP=1 -qAt -c "$1"
  else
    [ -n "${AWM_SMOKE_PG_CONTAINER:-}" ] || die "psql is not installed (set AWM_SMOKE_PG_CONTAINER)"
    docker exec -i "$AWM_SMOKE_PG_CONTAINER" psql -U "$PG_SU_USER" -d "$PG_SU_DB" \
      -v ON_ERROR_STOP=1 -qAt -c "$1"
  fi
}

psql_db() {
  # A superuser statement inside the run's database.
  if command -v psql >/dev/null 2>&1; then
    PGOPTIONS="-c client_min_messages=warning" psql "${AWM_TEST_PG_URL%/*}/$PG_DB" -v ON_ERROR_STOP=1 -qAt -c "$1"
  else
    docker exec -i "$AWM_SMOKE_PG_CONTAINER" psql -U "$PG_SU_USER" -d "$PG_DB" \
      -v ON_ERROR_STOP=1 -qAt -c "$1"
  fi
}

# ---------------------------------------------------------------------------------------------
# Mode set-up

SERVE_ARGS=()
SERVER_ENV=()
URL=""
CA_ARGS=()
BOOT_TOKEN=""
BOOT_ENV=()

setup_binary() {
  if [ "$MODE" = image ]; then
    command -v docker >/dev/null 2>&1 || die "docker is required for --image"
    docker image inspect "$IMAGE" >/dev/null 2>&1 \
      || die "image $IMAGE is missing: docker build -t $IMAGE ."
  fi
  # The clients are always the native binary.
  AWM_BIN="${AWM_BIN:-$ROOT/target/release/awm}"
  if [ ! -x "$AWM_BIN" ]; then
    (cd "$ROOT" && cargo build --release --locked -p agent-web-memory --features sync,serve)
  fi
  [ -x "$AWM_BIN" ] || die "no awm binary at $AWM_BIN"
}

setup_mode() {
  local port
  port="$(free_port)"
  case "$MODE" in
    sqlite)
      setup_pebble
      URL="https://localhost:$port"
      CA_ARGS=(--ca-file "$WORK/pebble/root.pem")
      SERVE_ARGS=(--data "$DATA" --domain localhost --listen "127.0.0.1:$port"
        --acme-directory "$PEBBLE_DIR" --acme-ca-file "$WORK/pebble/ca.pem"
        --backup "file://$BACKUP")
      ;;
    pg)
      setup_pg
      URL="http://127.0.0.1:$port"
      SERVE_ARGS=(--database-url-env AWM_SMOKE_PG_APP_URL
        --database-url-owner-env AWM_SMOKE_PG_OWNER_URL
        --behind-tls-proxy --trusted-proxy 127.0.0.1/32 --listen "127.0.0.1:$port"
        --backup "file://$BACKUP")
      SERVER_ENV=("AWM_SMOKE_PG_APP_URL=$PG_APP_URL" "AWM_SMOKE_PG_OWNER_URL=$PG_OWNER_URL")
      ;;
    image)
      DOCKER_USED=1
      URL="http://127.0.0.1:$port"
      DOCKER_PORT="$port"
      # The container's backup volume is a bind mount that the container's uid may write to.
      chmod 0777 "$BACKUP"
      docker volume create "$DVOL" >/dev/null
      ;;
  esac
  if [ "$SEED" -gt 0 ]; then
    [ "$MODE" != image ] || die "--seed is not supported with --image (the limits need a server.toml that the container's uid can read)"
    # The default limits (60 requests a minute, 5,000 records a day per member) would stop a
    # 20,000-record push; a server.toml (0600) raises them for this run only.
    (
      umask 077
      printf 'requests_per_minute = 60000\nrequest_burst = 60000\nrecords_per_day = %s\n' \
        "$((SEED + 1000))" >"$WORK/server.toml"
    )
    SERVE_ARGS+=(--config "$WORK/server.toml")
  fi
}

setup_pebble() {
  [ -n "${PEBBLE_BIN:-}" ] && [ -x "$PEBBLE_BIN" ] || die "PEBBLE_BIN must name the pebble binary"
  command -v openssl >/dev/null 2>&1 || die "openssl is required for --tls pebble"
  local d="$WORK/pebble" listen mgmt http tls
  mkdir -p "$d"
  listen="$(free_port)"
  mgmt="$(free_port)"
  http="$(free_port)"
  tls="$(free_port)"
  # A test CA, and a leaf for localhost / 127.0.0.1 that Pebble's own listeners present.
  cat >"$d/ca.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no
[dn]
CN = awm smoke CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
EOF
  cat >"$d/leaf.cnf" <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
CN = localhost
[v3_leaf]
subjectAltName = DNS:localhost,IP:127.0.0.1
basicConstraints = CA:FALSE
EOF
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/ca.key" 2>/dev/null
  openssl req -x509 -new -key "$d/ca.key" -config "$d/ca.cnf" -days 2 -out "$d/ca.pem"
  openssl ecparam -name prime256v1 -genkey -noout -out "$d/leaf.key" 2>/dev/null
  openssl req -new -key "$d/leaf.key" -config "$d/leaf.cnf" -out "$d/leaf.csr"
  openssl x509 -req -in "$d/leaf.csr" -CA "$d/ca.pem" -CAkey "$d/ca.key" -CAcreateserial \
    -days 2 -extfile "$d/leaf.cnf" -extensions v3_leaf -out "$d/leaf.pem" 2>/dev/null
  jq -n --arg listen "127.0.0.1:$listen" --arg mgmt "127.0.0.1:$mgmt" \
    --arg cert "$d/leaf.pem" --arg key "$d/leaf.key" --argjson http "$http" --argjson tls "$tls" '{
      pebble: {
        listenAddress: $listen, managementListenAddress: $mgmt,
        certificate: $cert, privateKey: $key, httpPort: $http, tlsPort: $tls,
        ocspResponderURL: "", externalAccountBindingRequired: false,
        profiles: {
          default: { description: "The default profile", validityPeriod: 7776000 }
        }
      }
    }' >"$d/pebble.json"
  PEBBLE_VA_ALWAYS_VALID=1 PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 PEBBLE_AUTHZREUSE=0 \
    "$PEBBLE_BIN" -config "$d/pebble.json" >"$d/pebble.log" 2>&1 &
  PEBBLE_PID=$!
  PEBBLE_DIR="https://127.0.0.1:$listen/dir"
  wait_http "$PEBBLE_DIR" --cacert "$d/ca.pem"
  # The root that signs the certificates Pebble issues: what the clients must trust.
  curl -fsS --cacert "$d/ca.pem" "https://127.0.0.1:$mgmt/roots/0" -o "$d/root.pem"
  [ -s "$d/root.pem" ] || die "Pebble served no root certificate"
}

setup_pg() {
  [ -n "${AWM_TEST_PG_URL:-}" ] || die "AWM_TEST_PG_URL (a superuser URL) is required for --store pg"
  local rest
  rest="${AWM_TEST_PG_URL#*://}"
  PG_SU_USER="${rest%%:*}"
  PG_SU_DB="${rest##*/}"
  PG_SU_DB="${PG_SU_DB%%\?*}"
  PG_HOSTPORT="${rest#*@}"
  PG_HOSTPORT="${PG_HOSTPORT%%/*}"
  PG_DB="awm_smoke_$RUN"
  PG_OWNER="awm_smoke_o_$RUN"
  PG_APP="awm_smoke_a_$RUN"
  psql_su "CREATE ROLE \"$PG_OWNER\" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '$PG_OWNER'"
  psql_su "CREATE ROLE \"$PG_APP\" LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '$PG_APP'"
  psql_su "CREATE DATABASE \"$PG_DB\" OWNER \"$PG_OWNER\""
  pg_fresh_schema
  PG_APP_URL="postgres://$PG_APP:$PG_APP@$PG_HOSTPORT/$PG_DB"
  PG_OWNER_URL="postgres://$PG_OWNER:$PG_OWNER@$PG_HOSTPORT/$PG_DB"
}

# An empty `public` schema owned by the owner role: a new database, or a wiped one.
pg_fresh_schema() {
  psql_db "DROP SCHEMA IF EXISTS public CASCADE"
  psql_db "CREATE SCHEMA public AUTHORIZATION \"$PG_OWNER\""
}

# ---------------------------------------------------------------------------------------------
# The server, per mode

# Runs `awm serve ARGS` against the live server's configuration.
srv_exec() {
  case "$MODE" in
    image) docker exec "$CNAME" awm serve "$@" ;;
    *) env ${SERVER_ENV[@]+"${SERVER_ENV[@]}"} "$AWM_BIN" serve "${SERVE_ARGS[@]}" "$@" ;;
  esac
}

# The same with the server stopped (restore): a container of its own in the image mode.
srv_offline() {
  case "$MODE" in
    image) docker run --rm "${DOCKER_COMMON[@]}" "$IMAGE" serve "$@" ;;
    *) srv_exec "$@" ;;
  esac
}

# The state directory inside the container. The image's own /data is 0755 (the Dockerfile's
# `COPY --from=builder /data /data` does not keep the 0700 of the builder stage), so a fresh
# `awm serve check` FAILs on it (report TM30, finding F1). The smoke works around it by letting
# `awm serve` create a 0700 subdirectory of the volume; AWM_SMOKE_IMAGE_DATA=/data tests the
# image's layout as shipped.
IMAGE_DATA="${AWM_SMOKE_IMAGE_DATA:-/data/awm}"
DOCKER_COMMON=()
docker_common() {
  DOCKER_COMMON=(--security-opt no-new-privileges:true --cap-drop ALL
    -v "$DVOL:/data" -v "$BACKUP:/backup"
    -e "AWM_DATA=$IMAGE_DATA"
    -e AWM_BEHIND_TLS_PROXY=1 -e AWM_TRUSTED_PROXY=0.0.0.0/0 -e AWM_BACKUP=file:///backup)
}

start_server() {
  : >>"$WORK/server.log"
  case "$MODE" in
    image)
      docker_common
      docker run -d --name "$CNAME" -p "127.0.0.1:$DOCKER_PORT:8443" "${DOCKER_COMMON[@]}" \
        ${BOOT_ENV[@]+"${BOOT_ENV[@]}"} "$IMAGE" >/dev/null
      wait_http "$URL/healthz"
      ;;
    *)
      env ${SERVER_ENV[@]+"${SERVER_ENV[@]}"} ${BOOT_ENV[@]+"${BOOT_ENV[@]}"} \
        "$AWM_BIN" serve "${SERVE_ARGS[@]}" >>"$WORK/server.log" 2>&1 &
      SERVER_PID=$!
      if [ "$MODE" = sqlite ]; then
        wait_http "$URL/healthz" --cacert "$WORK/pebble/root.pem"
      else
        wait_http "$URL/healthz"
      fi
      ;;
  esac
}

kill_server_9() {
  case "$MODE" in
    image)
      docker kill --signal KILL "$CNAME" >/dev/null
      docker rm -f "$CNAME" >/dev/null
      ;;
    *)
      kill -KILL "$SERVER_PID"
      wait "$SERVER_PID" 2>/dev/null || true
      SERVER_PID=""
      ;;
  esac
}

wipe_data() {
  case "$MODE" in
    sqlite) rm -rf "$DATA" ;;
    pg) pg_fresh_schema ;;
    image)
      docker volume rm "$DVOL" >/dev/null
      docker volume create "$DVOL" >/dev/null
      ;;
  esac
}

# ---------------------------------------------------------------------------------------------
# Steps

step_init() {
  local out
  out="$("$AWM_BIN" serve init --print-hash)"
  BOOT_TOKEN="$(printf '%s\n' "$out" | sed -n 's/^bootstrap token: //p')"
  local sha exp
  sha="$(printf '%s\n' "$out" | sed -n 's/^AWM_BOOTSTRAP_SHA256=//p')"
  exp="$(printf '%s\n' "$out" | sed -n 's/^AWM_BOOTSTRAP_EXPIRES=//p')"
  [ -n "$BOOT_TOKEN" ] && [ -n "$sha" ] && [ -n "$exp" ] || die "serve init --print-hash printed no token"
  if [ "$MODE" = image ]; then
    BOOT_ENV=(-e "AWM_BOOTSTRAP_SHA256=$sha" -e "AWM_BOOTSTRAP_EXPIRES=$exp")
  else
    BOOT_ENV=("AWM_BOOTSTRAP_SHA256=$sha" "AWM_BOOTSTRAP_EXPIRES=$exp")
  fi
}

step_start() {
  start_server
  local body
  if [ "$MODE" = sqlite ]; then
    body="$(curl -fsS --cacert "$WORK/pebble/root.pem" "$URL/v1/info")"
  else
    body="$(curl -fsS "$URL/v1/info")"
  fi
  printf '%s\n' "$body" | jq -e '.generation' >/dev/null || die "/v1/info has no generation"
}

step_compose_config() {
  # The compose file parses and resolves with a scratch .env (nothing is started).
  if ! docker compose version >/dev/null 2>&1; then
    printf 'docker compose is not installed: skipped\n'
    return 0
  fi
  printf 'AWM_BEHIND_TLS_PROXY=1\nAWM_TRUSTED_PROXY=172.16.0.0/12\nAWM_IMAGE=%s\n' "$IMAGE" \
    >"$WORK/compose.env"
  docker compose --project-name "awm-smoke-$RUN" --env-file "$WORK/compose.env" \
    -f "$ROOT/deploy/compose/docker-compose.yml" config -q
}

step_create() {
  # Each client gets its database and recording consent first (no import, nothing outside the
  # scratch HOME).
  awm_as a init --record >/dev/null
  awm_as b init --record >/dev/null
  local out
  out="$(awm_as a team create "$URL" --token "$BOOT_TOKEN" --handle ann ${CA_ARGS[@]+"${CA_ARGS[@]}"})"
  printf '%s\n' "$out"
  grep -q 'created organisation' <<<"$out" || die "team create printed no organisation"
  awm_as a sync --once
}

INVITE_TOKEN=""
JOIN_CODE=""
step_invite() {
  local line
  line="$(awm_as a team invite --handle bob 2>"$WORK/invite.err")"
  INVITE_TOKEN="${line##*--token }"
  case "$INVITE_TOKEN" in awmi1_*) ;; *) die "no invite string in: $line" ;; esac
}

step_join() {
  local out
  out="$(awm_as b team join "$URL" --token "$INVITE_TOKEN" ${CA_ARGS[@]+"${CA_ARGS[@]}"})"
  printf '%s\n' "$out"
  JOIN_CODE="$(printf '%s\n' "$out" \
    | sed -n 's/^read this code to the person who invited you: //p' | tr -d ' ')"
  case "$JOIN_CODE" in [0-9][0-9][0-9][0-9][0-9][0-9]) ;; *) die "no 6-digit code in the join output" ;; esac
}

step_approve() {
  awm_as a team approve bob --code "$JOIN_CODE"
  awm_as b sync --once
  local status
  status="$(awm_as b team status --json | jq -r '.approval')"
  [ "$status" = approved ] || die "bob's approval is '$status', expected approved"
}

step_share() {
  awm_as a team share "$PROJ"
  awm_as a team status --json | jq -e '.shares // .share // . ' >/dev/null
}

MARK1=""
MARK2=""
URL1=""
URL2=""
step_capture() {
  MARK1="smokeneedle${RUN}alpha"
  MARK2="smokeneedle${RUN}bravo"
  URL1="https://docs.example.org/smoke-$RUN/alpha"
  URL2="https://docs.example.org/smoke-$RUN/bravo"
  capture a "$URL1" "The alpha guide: $MARK1 explains the staging deployment checklist for the team."
  local n
  n="$(sqlite3 "$WORK/a/awm/awm.db" "SELECT COUNT(*) FROM event WHERE url = '$URL1'")"
  [ "$n" = 1 ] || die "the capture hook stored $n rows for $URL1, expected 1"
}

step_seed() {
  local cwd_hash now_ms
  cwd_hash="$(printf '%s' "$PROJ" | { shasum -a 256 2>/dev/null || sha256sum; } | cut -d' ' -f1)"
  # After the share rule (second precision of date +%s, plus a margin), not in the future for long.
  now_ms="$(($(date +%s) * 1000 + 2000))"
  sqlite3 "$WORK/a/awm/awm.db" <<SQL
.timeout 20000
PRAGMA trusted_schema = ON;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < $SEED)
INSERT INTO event (tool_use_id, tool, session_id, cwd_hash, created_at, url, url_norm,
                   fetch_prompt, status, summary, match_text, source)
SELECT 'toolu_seed_' || i, 'WebFetch', 'sess-seed', '$cwd_hash', $now_ms,
       'https://docs.example.org/seed/' || i, 'https://docs.example.org/seed/' || i,
       'what does it say', 'ok', 'Seed note ' || i || ' about configuration and setup.',
       'https://docs.example.org/seed/' || i || ' Seed note ' || i, 'hook'
FROM n;
SQL
  RESTORE_RECORDS="$SEED"
}

# Runs `awm sync --once` as WHO until a run pushes and pulls nothing; echoes the totals.
sync_all() {
  local who=$1 out pushed pulled tp=0 tl=0 i
  for i in $(seq 1 400); do
    out="$(awm_as "$who" sync --once)"
    pushed="$(count_of pushed "$out")"
    pulled="$(count_of pulled "$out")"
    : "${pushed:=0}" "${pulled:=0}"
    tp=$((tp + pushed))
    tl=$((tl + pulled))
    if [ "$pushed" = 0 ] && [ "$pulled" = 0 ]; then
      break
    fi
  done
  printf '%s sync: pushed %s, pulled %s (%s runs)\n' "$who" "$tp" "$tl" "$i" >&2
  SYNC_PUSHED=$tp
  SYNC_PULLED=$tl
}

# B's `awm search --url URL --json` has a row whose summary holds MARKER. (The text output of
# `awm search` carries no handle; the JSON rows carry no origin: see the report, FT2.)
b_sees() {
  awm_as b search --url --json "$1" \
    | jq -e --arg m "$2" 'any(.[]; (.summary // "") | contains($m))' >/dev/null
}

# `awm log` marks a teammate's row with @handle before the target.
b_has_handle() {
  local out
  out="$(awm_as b log --origin team --limit "$((SEED + 100))")"
  grep -qF -- "@ann $1" <<<"$out"
}

SYNC_PUSHED=0
SYNC_PULLED=0
step_push() {
  sync_all a
  local want=$((1 + SEED))
  [ "$SYNC_PUSHED" -ge "$want" ] || die "A pushed $SYNC_PUSHED records, expected at least $want"
}

step_pull() {
  sync_all b
  local want=$((1 + SEED))
  [ "$SYNC_PULLED" -ge "$want" ] || die "B pulled $SYNC_PULLED records, expected at least $want"
  b_sees "$URL1" "$MARK1" || die "B's search does not show $MARK1"
  b_has_handle "$URL1" || die "B's log does not show @ann for $URL1"
  awm_as b search --url "$URL1"
}

step_backup_verify() {
  srv_exec backup --verify
}

server_rec_count() {
  # Records on the server, where the test can look (the SqliteStore file).
  if [ "$MODE" = sqlite ] && [ -f "$DATA/server.db" ]; then
    sqlite3 "$DATA/server.db" "SELECT COUNT(*) FROM record WHERE tag = 'rec'"
  else
    printf 'n/a'
  fi
}

REC_BEFORE_EXTRA=""
REC_AFTER_EXTRA=""
step_extra_record() {
  REC_BEFORE_EXTRA="$(server_rec_count)"
  capture a "$URL2" "The bravo guide: $MARK2 explains the rollback procedure for the team."
  local out
  out="$(awm_as a sync --once)"
  printf '%s\n' "$out"
  [ "$(count_of pushed "$out")" -ge 1 ] || die "A did not push the extra record"
  REC_AFTER_EXTRA="$(server_rec_count)"
}

step_kill9() {
  kill_server_9
}

step_wipe() {
  wipe_data
}

step_restore() {
  local out t0 t1
  t0="$(now)"
  case "$MODE" in
    image) out="$(srv_offline restore --from file:///backup)" ;;
    *) out="$(srv_offline restore --from "file://$BACKUP")" ;;
  esac
  t1="$(now)"
  printf '%s\n' "$out"
  grep -q 'restored; new generation' <<<"$out" || die "restore printed no new generation"
  if [ "$SEED" -gt 0 ]; then
    RESTORE_SECS="$(elapsed "$t0" "$t1")"
    if [ -n "${AWM_SMOKE_MAX_RESTORE_S:-}" ]; then
      awk -v s="$RESTORE_SECS" -v m="$AWM_SMOKE_MAX_RESTORE_S" 'BEGIN { exit !(s <= m) }' \
        || die "the restore took $RESTORE_SECS s, above AWM_SMOKE_MAX_RESTORE_S=$AWM_SMOKE_MAX_RESTORE_S"
    fi
  fi
}

step_restart() {
  if [ "$MODE" != image ]; then
    BOOT_ENV=()
  fi
  start_server
  if [ "$MODE" = sqlite ]; then
    local lost
    lost="$(server_rec_count)"
    printf 'records on the restored server before A syncs: %s (before the extra record: %s, after: %s)\n' \
      "$lost" "$REC_BEFORE_EXTRA" "$REC_AFTER_EXTRA"
    if [ "$lost" = "$REC_AFTER_EXTRA" ]; then
      printf 'note: an incremental change set won the race; the re-seed is not exercised by this run\n'
    fi
  fi
}

# `awm serve check` on the running server: no FAIL line and no WARN other than the known ones
# (§3.9.4 item 4). Run on the fresh install and again after the restore.
step_check() {
  local out rc=0 fails
  out="$(srv_exec check --json)" || rc=$?
  printf '%s\n' "$out" | jq -r '.checks[] | "\(.level)\t\(.name)\t\(.text)"'
  fails="$(printf '%s\n' "$out" | jq -r '.failures')"
  [ "$fails" = 0 ] || die "awm serve check printed $fails FAIL line(s) (exit $rc)"
  [ "$rc" -le 1 ] || die "awm serve check exited $rc"
  # Only the known WARNs are allowed: a single admin (`tokens`) and no verification since the
  # restore (`backup`).
  local unexpected
  unexpected="$(printf '%s\n' "$out" | jq -r '.checks[] | select(.level == "WARN") | .name' \
    | grep -vxE 'backup|tokens' || true)"
  [ -z "$unexpected" ] || die "unexpected WARN line(s): $unexpected"
}

step_reseed() {
  local out
  out="$(awm_as a sync --once)"
  printf '%s\n' "$out"
  grep -q 'server was restored' <<<"$out" || die "A's sync did not report the re-seed"
  sync_all b
  b_sees "$URL2" "$MARK2" || die "the extra record is not back for B"
  b_has_handle "$URL2" || die "B's log does not show @ann for $URL2"
}

step_forget() {
  awm_as a forget "$URL1" --yes
  awm_as a sync --once
  sync_all b
  if b_sees "$URL1" "$MARK1"; then
    die "the forgotten record is still visible to B"
  fi
  # The other record is untouched.
  b_sees "$URL2" "$MARK2" || die "forget removed the wrong record"
}

# ---------------------------------------------------------------------------------------------

printf 'smoke: mode %s%s, work %s\n' "$MODE" "$([ "$SEED" -gt 0 ] && printf ', seed %s' "$SEED")" "$WORK"
setup_binary
setup_mode

run_step init step_init
run_step start step_start
if [ "$MODE" = image ]; then
  run_step compose-config step_compose_config
fi
run_step create step_create
run_step check-fresh step_check
run_step invite step_invite
run_step join step_join
run_step approve step_approve
run_step share step_share
run_step capture step_capture
if [ "$SEED" -gt 0 ]; then
  run_step seed step_seed
fi
run_step push step_push
run_step pull step_pull
run_step backup-verify step_backup_verify
run_step extra-record step_extra_record
run_step kill-9 step_kill9
run_step wipe step_wipe
run_step restore step_restore
run_step restart step_restart
run_step check-restored step_check
run_step reseed step_reseed
run_step forget step_forget
