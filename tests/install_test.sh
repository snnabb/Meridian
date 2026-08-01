#!/usr/bin/env bash
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

# Exercise the password transaction with a mock binary. The real command and
# bcrypt behavior are covered by Go tests.
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
export MOCK_DB_PATH="${DATA_DIR}/meridian.db"

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
