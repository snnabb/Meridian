#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2329
set -euo pipefail
# Exercise real root-owned snapshots; systemctl below is fully mocked. GitHub
# runners start unprivileged, while the deployment test host runs as root.
if [ "$(id -u)" -ne 0 ]; then
    exec sudo -n -- bash "$0" "$@"
fi
REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export MERIDIAN_INSTALL_DIR="${TEST_ROOT}/bin"
export MERIDIAN_DATA_DIR="${TEST_ROOT}/data"
export MERIDIAN_BACKUP_DIR="${TEST_ROOT}/backups"
export MERIDIAN_SERVICE_FILE="${TEST_ROOT}/meridian.service"
export MERIDIAN_ASSUME_YES=1
# shellcheck disable=SC1091
source "${REPO_ROOT}/install.sh"
as_root() { "$@"; }
init_privilege() { :; }
is_systemd() { return 0; }
service_is_active() { return 0; }
systemctl() { printf '%s\n' "$*" >> "${TEST_ROOT}/service-calls"; }
restore_data_permissions() { :; }
wait_for_health() { [ ! -e "${TEST_ROOT}/fail-health" ]; }
mkdir -p "$INSTALL_DIR" "$DATA_DIR"
printf 'DB_PATH=%s/meridian.db\n' "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'old database' > "${DATA_DIR}/meridian.db"
printf 'old service' > "$SERVICE_FILE"
printf '#!/bin/sh\necho v1.14.2\n' > "${INSTALL_DIR}/meridian"
chmod 0755 "${INSTALL_DIR}/meridian"
UPDATE_SNAPSHOT_DIR="${TEST_ROOT}/snapshot"
snapshot_data_dir "$UPDATE_SNAPSHOT_DIR"
# A lexical prefix is insufficient: traversal and symlinks could leave the
# actual database outside the paired data snapshot.
for unsafe_path in "${DATA_DIR}/../outside.db" "${DATA_DIR}/linked.db"; do
    printf 'outside database' > "${TEST_ROOT}/outside.db"
    ln -sf "${TEST_ROOT}/outside.db" "${DATA_DIR}/linked.db"
    printf 'DB_PATH=%s\n' "$unsafe_path" > "${DATA_DIR}/.env"
    if stage_rollback_snapshot v1.14.2 "${TEST_ROOT}/unsafe-ready"; then
        echo 'FAIL: database outside the paired snapshot was accepted'; exit 1
    fi
    # Real update entrypoint must reject this before download or service stop.
    if (
        ensure_cli_dependencies() { :; }
        validate_existing_secret_configuration() { :; }
        validate_panel_endpoint_consistency() { :; }
        migrate_managed_nginx_redaction() { :; }
        resolve_latest_version() { printf 'v1.15.0\n'; }
        download_release_binary() { touch "${TEST_ROOT}/download-called"; return 1; }
        do_update
    ) >"${TEST_ROOT}/preflight.log" 2>&1; then
        echo 'FAIL: update accepted unsupported rollback database'; exit 1
    fi
    grep -Fq '未停止服务或替换程序' "${TEST_ROOT}/preflight.log"
    [ ! -e "${TEST_ROOT}/service-calls" ]
    [ ! -e "${TEST_ROOT}/download-called" ]
done
rm "${DATA_DIR}/linked.db"
printf 'DB_PATH=%s/meridian.db\n' "$DATA_DIR" > "${DATA_DIR}/.env"
stage_rollback_snapshot v1.14.2 "${TEST_ROOT}/ready"
publish_rollback_snapshot "${TEST_ROOT}/ready"
printf 'new database' > "${DATA_DIR}/meridian.db"
printf 'new service' > "$SERVICE_FILE"
printf '#!/bin/sh\necho v1.15.0-beta.1\n' > "${INSTALL_DIR}/meridian"
# Force a failed rollback first. The transaction must restore the current state.
touch "${TEST_ROOT}/fail-health"
set +e
( do_rollback )
result=$?
set -e
[ "$result" -ne 0 ] || { echo 'FAIL: unhealthy rollback accepted'; exit 1; }
[ "$(cat "${DATA_DIR}/meridian.db")" = 'new database' ]
[ "$(cat "$SERVICE_FILE")" = 'new service' ]
[ "$("${INSTALL_DIR}/meridian" --version)" = v1.15.0-beta.1 ]
rm -- "${TEST_ROOT}/fail-health"
( do_rollback )
[ "$(cat "${DATA_DIR}/meridian.db")" = 'old database' ]
[ "$(cat "$SERVICE_FILE")" = 'old service' ]
[ "$("${INSTALL_DIR}/meridian" --version)" = v1.14.2 ]
[ ! -e "${BACKUP_DIR}/rollback-current" ]
compgen -G "${BACKUP_DIR}/meridian-pre-rollback-*.tar.gz" >/dev/null
echo 'PASS: manual rollback restores binary/data/service, and failed rollback restores current state'
