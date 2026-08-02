#!/usr/bin/env bash
# shellcheck disable=SC2317
# This file is a mock harness: the mock functions it defines are invoked
# indirectly by the sourced install.sh, which ShellCheck cannot statically
# trace, so every mock body would otherwise look unreachable.

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)

cleanup() {
    if [ "${EUID}" -eq 0 ]; then
        rm -rf -- "$TEST_ROOT"
    else
        sudo rm -rf -- "$TEST_ROOT"
    fi
}
trap cleanup EXIT

export MERIDIAN_INSTALL_DIR="${TEST_ROOT}/bin"
export MERIDIAN_DATA_DIR="${TEST_ROOT}/data"
export MERIDIAN_BACKUP_DIR="${TEST_ROOT}/backups"
export MERIDIAN_SERVICE_FILE="${TEST_ROOT}/meridian.service"
export MERIDIAN_NGINX_CONFIG="${TEST_ROOT}/nginx/conf.d/meridian-panel.conf"
export MERIDIAN_NGINX_ROOT="${TEST_ROOT}/nginx"
export MERIDIAN_ASSUME_YES=1

# The path is computed so this test works from an arbitrary checkout.
# shellcheck disable=SC1091
source "${REPO_ROOT}/install.sh"

assert_eq() {
    local expected="$1" actual="$2" label="$3"
    if [ "$expected" != "$actual" ]; then
        printf 'FAIL: %s: expected %q, got %q\n' "$label" "$expected" "$actual" >&2
        exit 1
    fi
}

assert_file() {
    [ -f "$1" ] || { printf 'FAIL: missing file %s\n' "$1" >&2; exit 1; }
}

assert_dir() {
    [ -d "$1" ] || { printf 'FAIL: missing directory %s\n' "$1" >&2; exit 1; }
}

assert_contains() {
    local file="$1" value="$2"
    grep -Fq -- "$value" "$file" || { printf 'FAIL: %s does not contain %s\n' "$file" "$value" >&2; exit 1; }
}

assert_not_contains() {
    local file="$1" value="$2"
    if grep -Fiq -- "$value" "$file"; then
        printf 'FAIL: %s unexpectedly contains %s\n' "$file" "$value" >&2
        exit 1
    fi
}

run_test_root_command() {
    local command_name="$1" arg
    shift
    if [ "$command_name" != install ]; then
        command "$command_name" "$@"
        return
    fi

    local install_args=()
    while [ "$#" -gt 0 ]; do
        arg="$1"
        shift
        case "$arg" in
            -o|-g)
                [ "$#" -gt 0 ] || return 1
                shift
                ;;
            *) install_args+=("$arg") ;;
        esac
    done
    command install "${install_args[@]}"
}

run_as_test_root() {
    if [ "${EUID}" -eq 0 ]; then
        command "$@"
    else
        sudo "$@"
    fi
}

for valid in example.com panel.example.com xn--fsqu00a.xn--0zwm56d; do
    valid_domain "$valid" || { printf 'FAIL: valid domain rejected: %s\n' "$valid" >&2; exit 1; }
done
for invalid in \
    'https://example.com' 'example.com/path' 'example.com:443' '127.0.0.1' \
    '*.example.com' 'example..com' '-example.com' 'example.com-' 'localhost' \
    'example.com;touch /tmp/x' 'EXAMPLE.COM'; do
    if valid_domain "$invalid"; then
        printf 'FAIL: invalid domain accepted: %s\n' "$invalid" >&2
        exit 1
    fi
done

for unsafe_path in / /opt/ /opt/../opt /tmp//meridian; do
    if MERIDIAN_DATA_DIR="$unsafe_path" bash -c 'source "$1"; validate_data_dir' _ "${REPO_ROOT}/install.sh" >/dev/null 2>&1; then
        printf 'FAIL: unsafe data directory accepted: %s\n' "$unsafe_path" >&2
        exit 1
    fi
done
if MERIDIAN_BACKUP_DIR=/var/ bash -c 'source "$1"; validate_backup_dir' _ "${REPO_ROOT}/install.sh" >/dev/null 2>&1; then
    echo 'FAIL: unsafe backup directory accepted' >&2
    exit 1
fi

# Pre-release/build suffixes must not corrupt numeric version comparison:
# v1.5.6-rc1 is patch 6, not patch 61.
version_gt v1.5.10 v1.5.6-rc1 || { echo 'FAIL: v1.5.10 must be newer than v1.5.6-rc1' >&2; exit 1; }
version_gt v1.5.6-rc1 v1.5.5 || { echo 'FAIL: v1.5.6-rc1 must be newer than v1.5.5' >&2; exit 1; }
version_gt v1.6.0-rc1 v1.5.10 || { echo 'FAIL: v1.6.0-rc1 must be newer than v1.5.10' >&2; exit 1; }
version_gt v2.0.0-beta.1 v1.9.9 || { echo 'FAIL: v2.0.0-beta.1 must be newer than v1.9.9' >&2; exit 1; }
version_gt v1.5.7 v1.5.6-rc1 || { echo 'FAIL: v1.5.7 must be newer than v1.5.6-rc1' >&2; exit 1; }
if version_gt v1.5.6-rc1 v1.5.6; then
    echo 'FAIL: v1.5.6-rc1 must not compare as newer than v1.5.6' >&2
    exit 1
fi
if version_gt v1.5.6 v1.5.6-rc1; then
    echo 'FAIL: v1.5.6 must not compare as newer than v1.5.6-rc1' >&2
    exit 1
fi
if version_gt v1.5.6+beta2 v1.5.6; then
    echo 'FAIL: v1.5.6+beta2 must not compare as newer than v1.5.6' >&2
    exit 1
fi
if version_gt v1.5.6 v1.5.6; then
    echo 'FAIL: equal versions must not compare as newer' >&2
    exit 1
fi
if version_gt v1.5.6 v1.5.10; then
    echo 'FAIL: v1.5.6 must not compare as newer than v1.5.10' >&2
    exit 1
fi

package_log="${TEST_ROOT}/package.log"
for manager in apt dnf yum apk pacman; do
    : > "$package_log"
    (
        as_root() { printf '%s\n' "$*" >> "$package_log"; }
        install_panel_packages "$manager"
    )
    assert_contains "$package_log" nginx
    assert_contains "$package_log" certbot
done

mkdir -p "$(dirname -- "$NGINX_CONFIG")"
generated_nginx="${TEST_ROOT}/generated-nginx.conf"
write_panel_nginx_config panel.example.com 19090 "$generated_nginx"
assert_contains "$generated_nginx" "$NGINX_MARKER"
assert_contains "$generated_nginx" 'proxy_pass http://127.0.0.1:19090;'
# The dollar sign is intentionally literal Nginx syntax.
# shellcheck disable=SC2016
assert_contains "$generated_nginx" 'proxy_set_header Upgrade $http_upgrade;'
assert_contains "$generated_nginx" 'proxy_buffering off;'
for forbidden in 50001 target_url playback '/emby' '/Items/' 'System/Info'; do
    assert_not_contains "$generated_nginx" "$forbidden"
done

conflict_file="${NGINX_ROOT}/sites-enabled/existing-panel"
mkdir -p "$(dirname -- "$conflict_file")"
printf 'server { server_name panel.example.com; }\n' > "$conflict_file"
find_domain_conflict panel.example.com || { echo 'FAIL: Nginx domain conflict was not detected' >&2; exit 1; }
assert_eq "$conflict_file" "$NGINX_CONFLICT_PATH" 'conflicting Nginx path'
rm -f -- "$conflict_file"

# Wildcard and regex server names can also claim the requested host. Regexes
# are deliberately treated as conflicts because reliably evaluating arbitrary
# Nginx regular expressions in the installer would be unsafe.
for server_name in '*.example.com' '.example.com' 'panel.*' '~^unrelated\.example\.net$'; do
    printf 'server { server_name %s; }\n' "$server_name" > "$conflict_file"
    find_domain_conflict panel.example.com || {
        printf 'FAIL: Nginx wildcard/regex conflict was not detected: %s\n' "$server_name" >&2
        exit 1
    }
    assert_eq "$conflict_file" "$NGINX_CONFLICT_PATH" "wildcard/regex conflict path: $server_name"
done
rm -f -- "$conflict_file"

printf 'server {\n  server_name\n    panel.example.com\n    www.panel.example.com;\n}\n' > "$conflict_file"
find_domain_conflict panel.example.com || { echo 'FAIL: multiline Nginx server_name conflict was not detected' >&2; exit 1; }
rm -f -- "$conflict_file"

printf 'server { server_name *.unrelated.example; }\n' > "$conflict_file"
if find_domain_conflict panel.example.com; then
    echo 'FAIL: unrelated Nginx wildcard was treated as a conflict' >&2
    exit 1
fi
rm -f -- "$conflict_file"

printf 'server { server_name unrelated.example.com; }\n' > "$NGINX_CONFIG"
if (
    as_root() { run_test_root_command "$@"; }
    is_systemd() { return 0; }
    configure_panel_domain panel.example.com ""
); then
    echo 'FAIL: unmarked Nginx target file was overwritten' >&2
    exit 1
fi
assert_contains "$NGINX_CONFIG" 'unrelated.example.com'
rm -f -- "$NGINX_CONFIG"

# Certbot failure must restore both the exact .env and the previous managed vhost.
mkdir -p "$DATA_DIR" "$(dirname -- "$NGINX_CONFIG")"
printf 'JWT_SECRET=old-test-jwt-secret-000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=old.example.com\nTRUSTED_PROXY_CIDRS=10.0.0.0/8\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf '%s\nserver { server_name old.example.com; }\n' "$NGINX_MARKER" > "$NGINX_CONFIG"
cp "${DATA_DIR}/.env" "${TEST_ROOT}/env.expected"
cp "$NGINX_CONFIG" "${TEST_ROOT}/nginx.expected"
certbot_log="${TEST_ROOT}/certbot.log"
if (
    as_root() {
        if [ "$1" = certbot ]; then
            printf '%s\n' "$*" > "$certbot_log"
            return 1
        fi
        run_test_root_command "$@"
    }
    is_systemd() { return 0; }
    install_panel_dependencies() { return 0; }
    start_nginx() { return 0; }
    nginx_test_and_reload() { return 0; }
    restart_meridian_and_health() { return 0; }
    install_env_file() { cp "$1" "$(env_file_path)"; }
    configure_panel_domain panel.example.com ""
); then
    echo 'FAIL: Certbot failure unexpectedly succeeded' >&2
    exit 1
fi
cmp -s "${DATA_DIR}/.env" "${TEST_ROOT}/env.expected" || { echo 'FAIL: .env was not restored after Certbot failure' >&2; exit 1; }
cmp -s "$NGINX_CONFIG" "${TEST_ROOT}/nginx.expected" || { echo 'FAIL: Nginx config was not restored after Certbot failure' >&2; exit 1; }
assert_contains "$certbot_log" '--nginx'
assert_contains "$certbot_log" '--redirect'
assert_contains "$certbot_log" 'panel.example.com'
assert_contains "$certbot_log" '--register-unsafely-without-email'

# A successful domain transaction binds only the panel to loopback and trusts only
# the loopback proxy additions; site listener configuration is never consulted.
if ! (
    as_root() {
        if [ "$1" = certbot ]; then
            return 0
        fi
        run_test_root_command "$@"
    }
    is_systemd() { return 0; }
    install_panel_dependencies() { return 0; }
    start_nginx() { return 0; }
    nginx_test_and_reload() { return 0; }
    restart_meridian_and_health() { return 0; }
    install_env_file() { cp "$1" "$(env_file_path)"; }
    configure_panel_domain panel.example.com admin@example.com
); then
    echo 'FAIL: mocked domain configuration failed' >&2
    exit 1
fi
assert_eq '127.0.0.1' "$(read_env_value PANEL_BIND_ADDR)" 'panel bind address'
assert_eq 'panel.example.com' "$(read_env_value PANEL_DOMAIN)" 'panel domain'
assert_eq '127.0.0.1/32,::1/128' "$(read_env_value TRUSTED_PROXY_CIDRS)" 'trusted proxies'
assert_not_contains "$NGINX_CONFIG" 50001

# Mock release downloads so install/update behavior can be tested without network.
MOCK_LATEST='v9.9.9'
get_latest_version() { printf '%s\n' "$MOCK_LATEST"; }
detect_platform() { printf 'linux-amd64\n'; }
download() {
    local url="$1" output="$2" version
    version=$(printf '%s' "$url" | awk -F/ '{print $(NF-1)}')
    if [[ "$url" == */SHA256SUMS ]]; then
        printf '%s  meridian-linux-amd64\n' "$(sha256_file "${TEST_ROOT}/release-binary")" > "$output"
        return
    fi
    cat > "${TEST_ROOT}/release-binary" <<BINARY
#!/usr/bin/env sh
if [ "\${1:-}" = "--version" ]; then
    echo "${version}"
fi
BINARY
    chmod 0755 "${TEST_ROOT}/release-binary"
    cp "${TEST_ROOT}/release-binary" "$output"
}
is_systemd() { return 1; }
service_is_active() { return 1; }
DOMAIN_MODE='ask'
REQUESTED_DOMAIN=''
CERTBOT_EMAIL=''
rm -rf -- "$INSTALL_DIR" "$DATA_DIR" "$BACKUP_DIR" "$NGINX_ROOT"

if ! (do_install) >"${TEST_ROOT}/install-first.log" 2>&1; then
    cat "${TEST_ROOT}/install-first.log" >&2
    exit 1
fi
assert_eq 'v9.9.9' "$(get_current_version)" 'first installed version'
assert_file "${DATA_DIR}/.env"
assert_eq '0.0.0.0' "$(read_env_value PANEL_BIND_ADDR)" 'fresh IP bind'

MOCK_LATEST='v9.9.10'
DOMAIN_MODE='ask'
if ! (do_install) >"${TEST_ROOT}/install-existing.log" 2>&1; then
    cat "${TEST_ROOT}/install-existing.log" >&2
    exit 1
fi
assert_eq 'v9.9.9' "$(get_current_version)" 'install must not update existing installation'

domain_env_before=$(sha256_file "${DATA_DIR}/.env")
if ! (do_update) >"${TEST_ROOT}/update.log" 2>&1; then
    cat "${TEST_ROOT}/update.log" >&2
    exit 1
fi
assert_eq 'v9.9.10' "$(get_current_version)" 'updated latest version'
assert_eq 'v9.9.9' "$($PREVIOUS_BIN --version)" 'retained previous version'
assert_eq "$domain_env_before" "$(sha256_file "${DATA_DIR}/.env")" 'update preserves .env'
assert_dir "$BACKUP_DIR"

backup_count_before=$(run_as_test_root find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | wc -l | tr -d '[:space:]')
if ! (do_update) >"${TEST_ROOT}/update-current.log" 2>&1; then
    cat "${TEST_ROOT}/update-current.log" >&2
    exit 1
fi
backup_count_after=$(run_as_test_root find "$BACKUP_DIR" -maxdepth 1 -type f -name '*.tar.gz' | wc -l | tr -d '[:space:]')
assert_eq "$backup_count_before" "$backup_count_after" 'latest update is a no-op'

# Older uninitialized installations did not have SETUP_TOKEN in .env. Updating
# one must backfill a fresh token and tell the operator that it is required.
printf 'JWT_SECRET=legacy-jwt-secret-000000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
MOCK_LATEST='v9.9.11'
if ! (do_update) >"${TEST_ROOT}/update-legacy-setup.log" 2>&1; then
    cat "${TEST_ROOT}/update-legacy-setup.log" >&2
    exit 1
fi
[ -n "$(read_env_value SETUP_TOKEN)" ] || { echo 'FAIL: legacy update did not backfill SETUP_TOKEN' >&2; exit 1; }
assert_contains "${TEST_ROOT}/update-legacy-setup.log" '初始化令牌'

# A newer installed version must never be silently downgraded.
MOCK_LATEST='v9.8.0'
if (do_update) >"${TEST_ROOT}/update-downgrade.log" 2>&1; then
    echo 'FAIL: downgrade update unexpectedly succeeded' >&2; exit 1
fi
assert_eq 'v9.9.11' "$(get_current_version)" 'downgrade attempt must keep the installed version'
assert_contains "${TEST_ROOT}/update-downgrade.log" '拒绝降级'

# A failing new release must roll back the previous binary AND the exact
# pre-update database and configuration. The mock new binary mutates the
# database before "starting", then fails the health check.
printf 'JWT_SECRET=rollback-jwt-secret-00000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\nSETUP_TOKEN=rollback-setup-token-0000000000000000000000000000\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'pre-update-db-state\n' > "${DATA_DIR}/meridian.db"
cp "${DATA_DIR}/.env" "${TEST_ROOT}/rollback-env-before"
cp "${DATA_DIR}/meridian.db" "${TEST_ROOT}/rollback-db-before"
touch "$SERVICE_FILE"
# MOCK_DB_PATH must reach the mock binaries inside every subshell. Exporting
# it once at top level (instead of inside each subshell) keeps the assignment
# in the parent scope (SC2030/SC2031) and is inherited by all subshells.
export MOCK_DB_PATH="${DATA_DIR}/meridian.db"
failing_binary="${TEST_ROOT}/failing-meridian"
cat > "$failing_binary" <<'MOCKBIN'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
    echo v9.9.12
    exit 0
fi
printf 'mutated-by-failing-version\n' >> "${MOCK_DB_PATH:?}"
exit 1
MOCKBIN
chmod 0755 "$failing_binary"
if (
    is_systemd() { return 0; }
    service_is_active() { return 0; }
    systemctl() {
        case "$*" in
            *restart*) "${INSTALL_DIR}/${BIN_NAME}" >/dev/null 2>&1 || true ;; # run the new binary like systemd would
        esac
        return 0
    }
    wait_for_health() { return 1; }
    MOCK_LATEST='v9.9.12'
    download() {
        local url="$1" output="$2"
        if [[ "$url" == */SHA256SUMS ]]; then
            printf '%s  meridian-linux-amd64\n' "$(sha256_file "$failing_binary")" > "$output"
            return
        fi
        cp "$failing_binary" "$output"
    }
    do_update
) >"${TEST_ROOT}/update-rollback.log" 2>&1; then
    echo 'FAIL: failing update unexpectedly succeeded' >&2; exit 1
fi
assert_contains "${TEST_ROOT}/update-rollback.log" '自动回滚'
assert_eq 'v9.9.11' "$(get_current_version)" 'rollback must restore the previous binary'
# The restored DATA_DIR is owned by the service user (0750, db 0600,
# .env root:meridian 0640), so a non-root runner cannot read it directly.
run_as_test_root cmp -s "${DATA_DIR}/meridian.db" "${TEST_ROOT}/rollback-db-before" \
    || { echo 'FAIL: database was not restored after failed update' >&2; exit 1; }
run_as_test_root cmp -s "${DATA_DIR}/.env" "${TEST_ROOT}/rollback-env-before" \
    || { echo 'FAIL: configuration was not restored after failed update' >&2; exit 1; }
assert_contains "${TEST_ROOT}/update-rollback.log" '自动回滚'

# A missing snapshot must fail the restore without touching the live data.
# DATA_DIR is still service-user-owned (0750) after the systemd rollback
# above, so the reset must run as root; the mkdir below returns it to the
# runner.
run_as_test_root rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-missing"
mkdir -p "$DATA_DIR"
printf 'live-marker\n' > "${DATA_DIR}/live.txt"
if restore_data_snapshot "${TEST_ROOT}/snapshot-missing" 2>/dev/null; then
    echo 'FAIL: restore with a missing snapshot unexpectedly succeeded' >&2; exit 1
fi
assert_file "${DATA_DIR}/live.txt"

# A snapshot without the configuration must be rejected before any swap: the
# live directory stays byte-identical and no staging residue is left behind.
rm -rf -- "${TEST_ROOT}/snapshot-noenv"
mkdir -p "${TEST_ROOT}/snapshot-noenv/data"
printf 'orphan\n' > "${TEST_ROOT}/snapshot-noenv/data/orphan.txt"
if restore_data_snapshot "${TEST_ROOT}/snapshot-noenv" 2>/dev/null; then
    echo 'FAIL: restore of a snapshot without .env unexpectedly succeeded' >&2; exit 1
fi
assert_file "${DATA_DIR}/live.txt"
[ ! -e "${TEST_ROOT}/.data.restore.$$" ] || { echo 'FAIL: staging residue after rejected restore' >&2; exit 1; }

# A failed swap must return non-zero and move the displaced directory back, so
# the live data directory is never lost.
rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-swap-fail"
mkdir -p "$DATA_DIR" "${TEST_ROOT}/snapshot-swap-fail/data"
printf 'live-marker\n' > "${DATA_DIR}/live.txt"
printf 'JWT_SECRET=swap-jwt-secret-00000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${TEST_ROOT}/snapshot-swap-fail/data/.env"
printf 'snapshot-db\n' > "${TEST_ROOT}/snapshot-swap-fail/data/meridian.db"
restore_swap_log="${TEST_ROOT}/restore-swap.log"
if (
    as_root() {
        printf '%s\n' "$*" >> "$restore_swap_log"
        if [ "$1" = "mv" ] && [ "$2" = "-f" ] && [ "$3" = "--" ] \
            && [ "$4" = "${TEST_ROOT}/.data.restore.$$" ]; then
            return 1
        fi
        command "$@"
    }
    restore_data_snapshot "${TEST_ROOT}/snapshot-swap-fail"
); then
    echo 'FAIL: restore with a failing swap unexpectedly succeeded' >&2; exit 1
fi
assert_file "${DATA_DIR}/live.txt"
assert_contains "$restore_swap_log" "mv -f -- $DATA_DIR"

# A successful restore swaps in the snapshot contents and, outside systemd,
# gives the calling user back ownership of the data directory.
rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-ok"
mkdir -p "$DATA_DIR" "${TEST_ROOT}/snapshot-ok/data"
printf 'JWT_SECRET=live-jwt-secret-000000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'live-db\n' > "${DATA_DIR}/meridian.db"
printf 'live-marker\n' > "${DATA_DIR}/live.txt"
printf 'JWT_SECRET=snapshot-jwt-secret-0000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${TEST_ROOT}/snapshot-ok/data/.env"
printf 'snapshot-db\n' > "${TEST_ROOT}/snapshot-ok/data/meridian.db"
printf 'snapshot-extra\n' > "${TEST_ROOT}/snapshot-ok/data/extra.txt"
(
    is_systemd() { return 1; }
    restore_data_snapshot "${TEST_ROOT}/snapshot-ok"
) || { echo 'FAIL: snapshot restore failed' >&2; exit 1; }
[ ! -e "${DATA_DIR}/live.txt" ] || { echo 'FAIL: live files survived restore' >&2; exit 1; }
assert_file "${DATA_DIR}/extra.txt"
cmp -s "${DATA_DIR}/.env" "${TEST_ROOT}/snapshot-ok/data/.env" \
    || { echo 'FAIL: .env not restored' >&2; exit 1; }
cmp -s "${DATA_DIR}/meridian.db" "${TEST_ROOT}/snapshot-ok/data/meridian.db" \
    || { echo 'FAIL: database not restored' >&2; exit 1; }
[ "$(stat -c %u "$DATA_DIR")" = "$(id -u)" ] || { echo 'FAIL: data directory owner not restored to the calling user' >&2; exit 1; }
[ "$(stat -c %a "$DATA_DIR")" = "750" ] || { echo 'FAIL: data directory mode not restored to 0750' >&2; exit 1; }

# Under systemd the restore must leave DATA_DIR traversable and owned by the
# service user, the database writable by the service user, and .env back at
# root:SERVICE_GROUP 0640, matching prepare_data_and_config.
rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-systemd"
mkdir -p "$DATA_DIR" "${TEST_ROOT}/snapshot-systemd/data"
printf 'JWT_SECRET=systemd-jwt-secret-0000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'live-db\n' > "${DATA_DIR}/meridian.db"
cp "${DATA_DIR}/.env" "${TEST_ROOT}/snapshot-systemd/data/.env"
cp "${DATA_DIR}/meridian.db" "${TEST_ROOT}/snapshot-systemd/data/meridian.db"
restore_perm_log="${TEST_ROOT}/restore-perm.log"
: > "$restore_perm_log"
(
    as_root() {
        printf '%s\n' "$*" >> "$restore_perm_log"
        # This case only asserts that the chown/chmod arguments are correct;
        # actually running them as a non-root runner would EPERM. File
        # operations (cp/mv/rm/test/awk) still execute for real.
        case "$1" in
            chown|chmod) return 0 ;;
            *) command "$@" ;;
        esac
    }
    is_systemd() { return 0; }
    restore_data_snapshot "${TEST_ROOT}/snapshot-systemd"
) || { echo 'FAIL: systemd snapshot restore failed' >&2; exit 1; }
assert_contains "$restore_perm_log" "chown meridian:meridian $DATA_DIR"
assert_contains "$restore_perm_log" "chmod 0750 $DATA_DIR"
assert_contains "$restore_perm_log" "chown root:meridian ${DATA_DIR}/.env"
assert_contains "$restore_perm_log" "chmod 0640 ${DATA_DIR}/.env"
assert_contains "$restore_perm_log" "chown meridian:meridian ${DATA_DIR}/meridian.db"
assert_contains "$restore_perm_log" "chmod 0600 ${DATA_DIR}/meridian.db"

# A restore whose permission normalization fails must return non-zero (so
# UPDATE_SNAPSHOT_RESTORED stays unset and the transaction is retried or
# escalated) and must say what is broken, even though the data contents were
# already swapped in.
# The previous systemd-mode restore left DATA_DIR service-user-owned, and
# the chown failure below leaves it root-owned; both need root to reset.
run_as_test_root rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-permfail"
mkdir -p "$DATA_DIR" "${TEST_ROOT}/snapshot-permfail/data"
printf 'JWT_SECRET=permfail-jwt-secret-00000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'live-db\n' > "${DATA_DIR}/meridian.db"
printf 'JWT_SECRET=permfail-snapshot-secret-0000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${TEST_ROOT}/snapshot-permfail/data/.env"
printf 'snapshot-db\n' > "${TEST_ROOT}/snapshot-permfail/data/meridian.db"
perm_fail_out="${TEST_ROOT}/restore-permfail.out"
if (
    as_root() {
        if [ "$1" = "chown" ]; then return 1; fi
        command "$@"
    }
    is_systemd() { return 0; }
    restore_data_snapshot "${TEST_ROOT}/snapshot-permfail"
) >"$perm_fail_out" 2>&1; then
    echo 'FAIL: restore with failing permission fix unexpectedly succeeded' >&2; exit 1
fi
# The swapped-in directory is still root-owned here (chown was mocked to
# fail), so the content check needs root.
run_as_test_root cmp -s "${DATA_DIR}/meridian.db" "${TEST_ROOT}/snapshot-permfail/data/meridian.db" \
    || { echo 'FAIL: database content not restored despite permission failure' >&2; exit 1; }
assert_contains "$perm_fail_out" '无法设置数据目录属主'
assert_contains "$perm_fail_out" '请手动修复'

# A restore that cannot remove the displaced directory must return non-zero,
# keep the live DATA_DIR on the restored contents, and name the residue for
# manual cleanup.
# DATA_DIR is root-owned (0700) after the permfail restore above; the reset
# must run as root, then mkdir returns it to the runner.
run_as_test_root rm -rf -- "$DATA_DIR" "${TEST_ROOT}/snapshot-oldresidue"
mkdir -p "$DATA_DIR" "${TEST_ROOT}/snapshot-oldresidue/data"
printf 'JWT_SECRET=oldresidue-jwt-secret-000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'live-db\n' > "${DATA_DIR}/meridian.db"
printf 'JWT_SECRET=oldresidue-snapshot-secret-000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${TEST_ROOT}/snapshot-oldresidue/data/.env"
printf 'snapshot-db\n' > "${TEST_ROOT}/snapshot-oldresidue/data/meridian.db"
old_residue_out="${TEST_ROOT}/restore-oldresidue.out"
if (
    as_root() {
        if [ "$1" = "rm" ]; then return 1; fi
        command "$@"
    }
    is_systemd() { return 1; }
    restore_data_snapshot "${TEST_ROOT}/snapshot-oldresidue"
) >"$old_residue_out" 2>&1; then
    echo 'FAIL: restore with uncleaned old directory unexpectedly succeeded' >&2; exit 1
fi
cmp -s "${DATA_DIR}/meridian.db" "${TEST_ROOT}/snapshot-oldresidue/data/meridian.db" \
    || { echo 'FAIL: database content not restored' >&2; exit 1; }
assert_contains "$old_residue_out" '旧数据目录残留'
assert_contains "$old_residue_out" "${TEST_ROOT}/.data.pre-restore.$$"
[ -d "${TEST_ROOT}/.data.pre-restore.$$" ] || { echo 'FAIL: displaced directory was not preserved for manual cleanup' >&2; exit 1; }

# The update transaction cleanup must remove the root-owned snapshot through
# as_root (a plain rm would silently leave root-owned files behind) and must
# say so when the cleanup itself fails.
update_tmp="${TEST_ROOT}/update-tmp"
mkdir -p "$update_tmp"
rm_log="${TEST_ROOT}/cleanup-rm.log"
(
    as_root() {
        printf '%s\n' "$*" >> "$rm_log"
        command "$@"
    }
    UPDATE_TMP_DIR="$update_tmp"
    UPDATE_TRANSACTION=0
    UPDATE_BINARY_CHANGED=0
    UPDATE_SNAPSHOT_DIR=""
    UPDATE_SNAPSHOT_RESTORED=0
    UPDATE_WAS_ACTIVE=0
    cleanup_update_transaction
)
assert_contains "$rm_log" "rm -rf -- $update_tmp"
UPDATE_TMP_DIR=""

update_tmp_fail="${TEST_ROOT}/update-tmp-fail"
mkdir -p "$update_tmp_fail"
(
    as_root() { return 1; }
    UPDATE_TMP_DIR="$update_tmp_fail"
    UPDATE_TRANSACTION=0
    UPDATE_BINARY_CHANGED=0
    UPDATE_SNAPSHOT_DIR=""
    UPDATE_SNAPSHOT_RESTORED=0
    UPDATE_WAS_ACTIVE=0
    cleanup_update_transaction
    exit 0
) >"${TEST_ROOT}/cleanup-fail.out" 2>&1
assert_contains "${TEST_ROOT}/cleanup-fail.out" '无法清理更新临时目录'
assert_contains "${TEST_ROOT}/cleanup-fail.out" "$update_tmp_fail"

# After a successful restore the exit-trap cleanup must not restore again.
restore_gate_log="${TEST_ROOT}/restore-gate.log"
update_tmp_gate="${TEST_ROOT}/update-tmp-gate"
mkdir -p "$update_tmp_gate" "${TEST_ROOT}/snapshot-gate"
(
    set +e
    as_root() {
        printf '%s\n' "$*" >> "$restore_gate_log"
        command "$@"
    }
    restore_data_snapshot() { printf 'restore-called\n' >> "$restore_gate_log"; }
    UPDATE_TMP_DIR="$update_tmp_gate"
    UPDATE_TRANSACTION=1
    UPDATE_BINARY_CHANGED=0
    UPDATE_SNAPSHOT_DIR="${TEST_ROOT}/snapshot-gate"
    UPDATE_SNAPSHOT_RESTORED=1
    UPDATE_WAS_ACTIVE=0
    false
    cleanup_update_transaction
    exit 0
) >"${TEST_ROOT}/cleanup-gate.out" 2>&1
if grep -Fq 'restore-called' "$restore_gate_log"; then
    echo 'FAIL: cleanup restored again after a successful restore' >&2; exit 1
fi

# A restore that fails inside cleanup must be reported with the backup
# reference and must not be silently swallowed.
restore_fail_log="${TEST_ROOT}/restore-fail.log"
update_tmp_retry="${TEST_ROOT}/update-tmp-retry"
mkdir -p "$update_tmp_retry" "${TEST_ROOT}/snapshot-retry"
(
    set +e
    as_root() {
        printf '%s\n' "$*" >> "$restore_fail_log"
        command "$@"
    }
    restore_data_snapshot() {
        printf 'restore-called\n' >> "$restore_fail_log"
        return 1
    }
    is_systemd() { return 1; }
    # The UPDATE_* values below are consumed by cleanup_update_transaction
    # (defined in install.sh), which shellcheck cannot trace; each assignment
    # carries its own local SC2034 suppression.
    # shellcheck disable=SC2034
    UPDATE_TMP_DIR="$update_tmp_retry"
    # shellcheck disable=SC2034
    UPDATE_TRANSACTION=1
    # shellcheck disable=SC2034
    UPDATE_BINARY_CHANGED=0
    # shellcheck disable=SC2034
    UPDATE_SNAPSHOT_DIR="${TEST_ROOT}/snapshot-retry"
    # shellcheck disable=SC2034
    UPDATE_SNAPSHOT_RESTORED=0
    # shellcheck disable=SC2034
    UPDATE_WAS_ACTIVE=0
    LAST_BACKUP_PATH="${TEST_ROOT}/backup.tar.gz"
    false
    cleanup_update_transaction
    exit 0
) >"${TEST_ROOT}/cleanup-restore-fail.out" 2>&1
assert_contains "${TEST_ROOT}/cleanup-restore-fail.out" '数据快照恢复失败'
assert_contains "${TEST_ROOT}/cleanup-restore-fail.out" "${TEST_ROOT}/backup.tar.gz"
grep -Fq 'restore-called' "$restore_fail_log" || { echo 'FAIL: cleanup did not attempt the restore' >&2; exit 1; }

# A failing snapshot restore during an update must not be marked as restored:
# the in-flow rollback warns, the live data directory is left alone, and the
# exit-trap cleanup retries the restore instead of skipping it.
printf 'JWT_SECRET=retry-jwt-secret-0000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\nSETUP_TOKEN=retry-setup-token-000000000000000000000000000000\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
printf 'pre-update-db-state\n' > "${DATA_DIR}/meridian.db"
cp "${DATA_DIR}/.env" "${TEST_ROOT}/restore-retry-env-before"
cp "${DATA_DIR}/meridian.db" "${TEST_ROOT}/restore-retry-db-before"
touch "$SERVICE_FILE"
restore_attempt_file="${TEST_ROOT}/restore-attempts"
printf '0\n' > "$restore_attempt_file"
retry_failing_binary="${TEST_ROOT}/retry-failing-meridian"
cat > "$retry_failing_binary" <<'MOCKBIN'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
    echo v9.9.13
    exit 0
fi
printf 'mutated-by-retry-failing-version\n' >> "${MOCK_DB_PATH:?}"
exit 1
MOCKBIN
chmod 0755 "$retry_failing_binary"
if (
    is_systemd() { return 0; }
    service_is_active() { return 0; }
    systemctl() { return 0; }
    wait_for_health() { return 1; }
    restore_data_snapshot() {
        local n
        n=$(cat "$restore_attempt_file")
        printf '%s\n' "$((n + 1))" > "$restore_attempt_file"
        return 1
    }
    MOCK_LATEST='v9.9.13'
    download() {
        local url="$1" output="$2"
        if [[ "$url" == */SHA256SUMS ]]; then
            printf '%s  meridian-linux-amd64\n' "$(sha256_file "$retry_failing_binary")" > "$output"
            return
        fi
        cp "$retry_failing_binary" "$output"
    }
    do_update
) >"${TEST_ROOT}/update-restore-retry.log" 2>&1; then
    echo 'FAIL: failing update unexpectedly succeeded' >&2; exit 1
fi
assert_eq '2' "$(cat "$restore_attempt_file")" 'failed restore must be retried by the exit-trap cleanup'
assert_contains "${TEST_ROOT}/update-restore-retry.log" '数据快照恢复失败'
# The update's systemd path chowns DATA_DIR to the service user and .env to
# root:meridian 0640, so a non-root runner cannot compare them directly.
run_as_test_root cmp -s "${DATA_DIR}/meridian.db" "${TEST_ROOT}/restore-retry-db-before" \
    || { echo 'FAIL: live database was modified when restore failed' >&2; exit 1; }
run_as_test_root cmp -s "${DATA_DIR}/.env" "${TEST_ROOT}/restore-retry-env-before" \
    || { echo 'FAIL: live .env was modified when restore failed' >&2; exit 1; }

# Exercise the password transaction with a mock binary. The real command and
# bcrypt behavior are covered by Go tests.
# Recreate DATA_DIR as the runner's own directory: the previous systemd-mode
# tests left it owned by the service user, and the mock binary runs as the
# runner, not as root.
run_as_test_root rm -rf -- "$DATA_DIR"
mkdir -p "$DATA_DIR"
printf 'old-database-state\n' > "${DATA_DIR}/meridian.db"
printf 'JWT_SECRET=old-jwt-secret-000000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
password_mock_binary="${TEST_ROOT}/password-mock-meridian"
cat > "$password_mock_binary" <<'MOCKBIN'
#!/usr/bin/env bash
if [ "${1:-}" = "--version" ]; then
    echo v9.9.10
    exit 0
fi
if [ "${1:-}" = "admin" ] && [ "${2:-}" = "reset-password" ]; then
    IFS= read -r supplied
    [ -n "$supplied" ] || exit 1
    printf 'new-database-state\n' > "${MOCK_DB_PATH:?}"
    echo 'administrator password updated'
    exit 0
fi
exit 1
MOCKBIN
chmod 0755 "$password_mock_binary"
run_as_test_root install -m 0755 "$password_mock_binary" "${INSTALL_DIR}/${BIN_NAME}"
touch "$SERVICE_FILE"

run_password_case() {
    local health_result="$1"
    init_privilege() { ROOT_PREFIX=(); }
    as_root() {
        if [ "$1" = systemctl ]; then return 0; fi
        command "$@"
    }
    is_systemd() { return 0; }
    wait_for_health() { [ "$health_result" = success ]; }
    install_env_file() { cp "$1" "$(env_file_path)"; }
    fix_database_permissions() { return 0; }
    snapshot_auth_files() {
        mkdir -p "$1"
        cp "$(env_file_path)" "$1/env"
        cp "$2" "$1/db"
    }
    archive_auth_snapshot() {
        run_as_test_root mkdir -p "$BACKUP_DIR"
        LAST_BACKUP_PATH="${BACKUP_DIR}/password-test.tar.gz"
        run_as_test_root tar -C "$1" -czf "$LAST_BACKUP_PATH" .
    }
    printf 'test-password-123\ntest-password-123\n' | do_password
}

if ! (run_password_case success) >"${TEST_ROOT}/password-success.log" 2>&1; then
    cat "${TEST_ROOT}/password-success.log" >&2
    exit 1
fi
assert_contains "${DATA_DIR}/meridian.db" 'new-database-state'
if grep -Fq 'old-jwt-secret' "${DATA_DIR}/.env"; then
    echo 'FAIL: JWT secret was not rotated after password change' >&2
    exit 1
fi
assert_contains "${TEST_ROOT}/password-success.log" '所有旧登录令牌已失效'
assert_not_contains "${TEST_ROOT}/password-success.log" 'test-password-123'

printf 'old-database-state\n' > "${DATA_DIR}/meridian.db"
printf 'JWT_SECRET=rollback-jwt-secret-0000000000000000000000000000\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=0.0.0.0\nPANEL_DOMAIN=\nTRUSTED_PROXY_CIDRS=\n' \
    "$DATA_DIR" > "${DATA_DIR}/.env"
cp "${DATA_DIR}/.env" "${TEST_ROOT}/password-env-before"
if (run_password_case failure) >"${TEST_ROOT}/password-failure.log" 2>&1; then
    echo 'FAIL: failed health check did not fail password transaction' >&2
    exit 1
fi
cmp -s "${DATA_DIR}/.env" "${TEST_ROOT}/password-env-before" || { echo 'FAIL: JWT config was not rolled back' >&2; exit 1; }
assert_contains "${DATA_DIR}/meridian.db" 'old-database-state'

# Uninstall removes only marked panel config and keeps data/backups by default.
mock_bin_dir="${TEST_ROOT}/mock-bin"
mkdir -p "$mock_bin_dir" "$(dirname -- "$NGINX_CONFIG")"
printf '#!/usr/bin/env sh\nexit 0\n' > "${mock_bin_dir}/nginx"
chmod 0755 "${mock_bin_dir}/nginx"
PATH="${mock_bin_dir}:$PATH"
export PATH
printf '%s\nserver { server_name panel.example.com; }\n' "$NGINX_MARKER" > "$NGINX_CONFIG"
is_systemd() { return 1; }
nginx_test_and_reload() { return 0; }
PURGE_DATA=0
do_uninstall >"${TEST_ROOT}/uninstall-keep.log" 2>&1
[ ! -e "${INSTALL_DIR}/${BIN_NAME}" ] || { echo 'FAIL: binary not removed' >&2; exit 1; }
[ ! -e "$NGINX_CONFIG" ] || { echo 'FAIL: managed Nginx config not removed' >&2; exit 1; }
assert_dir "$DATA_DIR"
assert_dir "$BACKUP_DIR"

run_as_test_root install -m 0755 "${mock_bin_dir}/nginx" "${INSTALL_DIR}/${BIN_NAME}"
PURGE_DATA=1
do_uninstall >"${TEST_ROOT}/uninstall-purge.log" 2>&1
[ ! -e "$DATA_DIR" ] || { echo 'FAIL: data directory not purged' >&2; exit 1; }
assert_dir "$BACKUP_DIR"

help_text=$(usage)
for command_name in install update password uninstall; do
    printf '%s' "$help_text" | grep -q "install.sh ${command_name}"
done
for removed_command in status restart logs backup rollback; do
    if printf '%s' "$help_text" | grep -Eq "install\.sh ${removed_command}([[:space:]]|$)"; then
        printf 'FAIL: removed public command remains in help: %s\n' "$removed_command" >&2
        exit 1
    fi
    if bash "${REPO_ROOT}/install.sh" "$removed_command" >/dev/null 2>&1; then
        printf 'FAIL: removed public command is callable: %s\n' "$removed_command" >&2
        exit 1
    fi
done

menu_text=$(printf '0\n' | main_menu)
for menu_item in '1) 安装' '2) 更新到最新版' '3) 修改管理员密码' '4) 卸载' '0) 退出'; do
    printf '%s' "$menu_text" | grep -Fq "$menu_item"
done
if printf '%s' "$menu_text" | grep -Eq '^  [5-9]\)'; then
    echo 'FAIL: menu exposes more than four operations' >&2
    exit 1
fi

echo 'installer tests passed'
