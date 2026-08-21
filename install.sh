#!/usr/bin/env bash
set -euo pipefail

# Meridian one-click installer.
# Public operations are intentionally limited to install, update, password,
# and uninstall. Backups and rollback remain internal safety mechanisms.

REPO="${MERIDIAN_REPO:-snnabb/Meridian}"
INSTALL_DIR="${MERIDIAN_INSTALL_DIR:-/usr/local/bin}"
DATA_DIR="${MERIDIAN_DATA_DIR:-/opt/meridian}"
BACKUP_DIR="${MERIDIAN_BACKUP_DIR:-/opt/meridian-backups}"
SERVICE_FILE="${MERIDIAN_SERVICE_FILE:-/etc/systemd/system/meridian.service}"
SERVICE_NAME="${MERIDIAN_SERVICE_NAME:-meridian}"
NGINX_CONFIG="${MERIDIAN_NGINX_CONFIG:-/etc/nginx/conf.d/meridian-panel.conf}"
NGINX_ROOT="${MERIDIAN_NGINX_ROOT:-/etc/nginx}"
BIN_NAME="meridian"
COSIGN_VERSION="v2.6.4"
SERVICE_USER="meridian"
SERVICE_GROUP="meridian"
SYSTEMD_RESTRICT_ADDRESS_FAMILIES="AF_UNIX AF_INET AF_INET6 AF_NETLINK"
ROOT_GROUP="${MERIDIAN_ROOT_GROUP:-$(id -gn 0 2>/dev/null || printf 'root')}"
NGINX_MARKER="# Managed by Meridian installer - panel only"
NGINX_REDACTION_MARKER="# Meridian redacted URI access log"

while [ "$INSTALL_DIR" != "/" ] && [[ "$INSTALL_DIR" == */ ]]; do INSTALL_DIR="${INSTALL_DIR%/}"; done
while [ "$DATA_DIR" != "/" ] && [[ "$DATA_DIR" == */ ]]; do DATA_DIR="${DATA_DIR%/}"; done
while [ "$BACKUP_DIR" != "/" ] && [[ "$BACKUP_DIR" == */ ]]; do BACKUP_DIR="${BACKUP_DIR%/}"; done

PREVIOUS_BIN="${INSTALL_DIR}/${BIN_NAME}.previous"
ASSUME_YES="${MERIDIAN_ASSUME_YES:-0}"
PURGE_DATA=0
DOMAIN_MODE="ask"
REQUESTED_DOMAIN=""
CERTBOT_EMAIL=""
INITIAL_SETUP_TOKEN=""
SETUP_TOKEN_ORIGIN=""
LAST_BACKUP_PATH=""
ROOT_PREFIX=()
UPDATE_TMP_DIR=""
UPDATE_WAS_ACTIVE=0
UPDATE_BINARY_CHANGED=0
UPDATE_TRANSACTION=0
UPDATE_SNAPSHOT_DIR=""
UPDATE_SNAPSHOT_RESTORED=0
UPDATE_SERVICE_SNAPSHOT=""
UPDATE_SERVICE_CHANGED=0
PASSWORD_TMP_DIR=""
PASSWORD_SNAPSHOT_DIR=""
PASSWORD_DB_PATH=""
PASSWORD_TRANSACTION=0
PANEL_WORK_DIR=""
PANEL_TRANSACTION=0
COSIGN_BIN=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info() { printf "${CYAN}[INFO]${NC} %s\n" "$*"; }
ok() { printf "${GREEN}[OK]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*"; }
fail() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; exit 1; }

need_cmd() {
    command -v "$1" >/dev/null 2>&1 || fail "缺少必要命令: $1"
}

init_privilege() {
    if [ "${EUID}" -eq 0 ]; then
        ROOT_PREFIX=()
        return
    fi
    need_cmd sudo
    sudo -v
    ROOT_PREFIX=(sudo)
}

as_root() {
    "${ROOT_PREFIX[@]}" "$@"
}

is_systemd() {
    [ "$(uname -s)" = "Linux" ] && [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

service_is_active() {
    is_systemd && systemctl is-active --quiet "$SERVICE_NAME"
}

ask_yes_no() {
    local prompt="$1" default_yes="${2:-0}" answer
    if [ "$ASSUME_YES" = "1" ]; then
        return 0
    fi
    if [ "$default_yes" = "1" ]; then
        read -r -p "$(printf "${CYAN}%s [Y/n]:${NC} " "$prompt")" answer
        [[ "$answer" != "n" && "$answer" != "N" ]]
    else
        read -r -p "$(printf "${CYAN}%s [y/N]:${NC} " "$prompt")" answer
        [[ "$answer" = "y" || "$answer" = "Y" ]]
    fi
}

validate_safe_directory() {
    local value="$1" label="$2"
    case "$value" in
        ""|/|/bin|/boot|/dev|/etc|/home|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/usr/local|/var)
            fail "拒绝使用不安全的${label}: ${value:-<empty>}"
            ;;
        *//*|*/../*|*/..|*/./*|*/.|*$'\n'*|*$'\r'*|*$'\t'*)
            fail "${label}包含不安全的路径片段: $value"
            ;;
    esac
    [[ "$value" = /* ]] || fail "${label}必须是绝对路径: $value"
}

validate_install_dir() {
    validate_safe_directory "$INSTALL_DIR" "安装目录"
}

validate_data_dir() {
    validate_safe_directory "$DATA_DIR" "数据目录"
}

validate_backup_dir() {
    validate_safe_directory "$BACKUP_DIR" "备份目录"
}

validate_nginx_config_path() {
    case "$NGINX_CONFIG" in
        ""|/|*//*|*/../*|*/..|*/./*|*/.|*$'\n'*)
            fail "Nginx 配置路径不安全: ${NGINX_CONFIG:-<empty>}"
            ;;
    esac
    [[ "$NGINX_CONFIG" = /* ]] || fail "Nginx 配置路径必须是绝对路径: $NGINX_CONFIG"
    [ "$(basename -- "$NGINX_CONFIG")" = "meridian-panel.conf" ] \
        || fail "Nginx 配置文件名必须为 meridian-panel.conf"
}

validate_db_path() {
    local db_path="$1"
    case "$db_path" in
        ""|/|/bin|/boot|/dev|/etc|/home|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/usr/local|/var|*//*|*/../*|*/..|*/./*|*/.|*$'\n'*)
            return 1
            ;;
    esac
    [[ "$db_path" = /* ]]
}

valid_version() {
    [[ "$1" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]
}

version_gt() {
    # Returns 0 (true) when $1 (vA.B.C[-suffix]) is newer than $2. The numeric
    # major.minor.patch triple decides; pre-release/build suffixes ("-rc1",
    # "+build") are stripped before parsing so v1.5.6-rc1 compares as 1.5.6,
    # not as a patch of 61.
    # shellcheck disable=SC2016
    printf '%s\n%s\n' "${1#v}" "${2#v}" | awk -F. '
        function num(s) { sub(/[-+].*$/, "", s); gsub(/[^0-9]/, "", s); return s+0 }
        NR == 1 { a1=num($1); a2=num($2); a3=num($3) }
        NR == 2 { b1=num($1); b2=num($2); b3=num($3) }
        END {
            if (a1 != b1) exit (a1 > b1) ? 0 : 1
            if (a2 != b2) exit (a2 > b2) ? 0 : 1
            exit (a3 > b3) ? 0 : 1
        }'
}

snapshot_data_dir() {
    # Byte-level copy of the data directory for automatic rollback. The update
    # flow stops the service first, so the database, WAL/SHM, and .env are
    # quiescent when this runs.
    local snapshot_dir="$1"
    validate_data_dir
    as_root test -d "$DATA_DIR" || return 1
    as_root install -d -o root -g "$ROOT_GROUP" -m 0700 "$snapshot_dir"
    as_root install -d -o root -g "$ROOT_GROUP" -m 0700 "${snapshot_dir}/data"
    as_root cp -a -- "$DATA_DIR"/. "${snapshot_dir}/data/"
}

restore_data_snapshot() {
    # Restores the exact pre-update data directory without ever deleting the
    # live DATA_DIR unless the replacement is already staged and verified. The
    # snapshot is first copied to a staging directory next to DATA_DIR (same
    # filesystem), checked for the configuration and database, and only then
    # swapped in with two renames. Any failure leaves the original DATA_DIR
    # untouched and returns non-zero; a partially staged copy is removed so no
    # sensitive residue survives the attempt. Post-swap cleanup (permission
    # normalization, removal of the displaced directory) is part of the
    # contract too: if either cannot be completed, the function still returns
    # non-zero so the caller keeps the transaction unrecovered for a retry or
    # manual intervention.
    local snapshot_dir="$1" staging_dir old_dir db_path data_base data_parent
    validate_data_dir
    as_root test -d "${snapshot_dir}/data" || return 1
    data_parent=$(dirname -- "$DATA_DIR")
    data_base=$(basename -- "$DATA_DIR")
    staging_dir="${data_parent}/.${data_base}.restore.$$"
    old_dir="${data_parent}/.${data_base}.pre-restore.$$"
    as_root rm -rf -- "$staging_dir" 2>/dev/null || true
    as_root rm -rf -- "$old_dir" 2>/dev/null || true
    if ! as_root cp -a -- "${snapshot_dir}/data" "$staging_dir"; then
        as_root rm -rf -- "$staging_dir" 2>/dev/null || true
        return 1
    fi
    # Verify the staged copy actually carries the configuration and database
    # before the live directory is touched.
    if ! as_root test -f "${staging_dir}/.env"; then
        as_root rm -rf -- "$staging_dir" 2>/dev/null || true
        return 1
    fi
    db_path=$(read_env_value DB_PATH)
    case "$db_path" in
        "$DATA_DIR"/*)
            if ! as_root test -f "${staging_dir}/${db_path#"$DATA_DIR"/}"; then
                as_root rm -rf -- "$staging_dir" 2>/dev/null || true
                return 1
            fi
            ;;
    esac
    if ! as_root mv -f -- "$DATA_DIR" "$old_dir"; then
        as_root rm -rf -- "$staging_dir" 2>/dev/null || true
        return 1
    fi
    if ! as_root mv -f -- "$staging_dir" "$DATA_DIR"; then
        if ! as_root mv -f -- "$old_dir" "$DATA_DIR" 2>/dev/null; then
            warn "数据目录切换失败，原数据保留在: $old_dir，请手动恢复"
        fi
        if ! as_root rm -rf -- "$staging_dir" 2>/dev/null; then
            warn "无法清理恢复暂存目录（可能含敏感数据），请手动删除: $staging_dir"
        fi
        return 1
    fi
    # Only the verified replacement is live now. The displaced directory may
    # contain secrets; failing to remove it must not read as a complete
    # restore, so this path returns non-zero and names the residue.
    if ! as_root rm -rf -- "$old_dir" 2>/dev/null; then
        warn "数据已恢复，但旧数据目录残留（可能含敏感数据），请手动删除: $old_dir"
        return 1
    fi
    # Permission normalization is part of the restore contract: a staged copy
    # arrives root:0700, and a restore that leaves the service user locked out
    # is not a successful restore. Its non-zero status propagates.
    restore_data_permissions
}

restore_env_from_snapshot() {
    # A failed full-directory restore must not leave pre-start configuration
    # backfills (for example a newly generated encryption key) in the live
    # environment. Restore just the exact pre-update .env atomically while the
    # full snapshot remains pending for the exit-trap retry/manual recovery.
    # This deliberately does not mark UPDATE_SNAPSHOT_RESTORED: database and
    # other data files may still require the complete snapshot.
    local snapshot_dir="$1" snapshot_env env_file
    snapshot_env="${snapshot_dir}/data/.env"
    env_file=$(env_file_path)
    as_root test -f "$snapshot_env" || return 1
    if as_root test -L "$snapshot_env"; then
        return 1
    fi
    as_root test -d "$DATA_DIR" || return 1
    if as_root test -L "$env_file"; then
        return 1
    fi
    install_env_file "$snapshot_env"
}

restore_update_snapshot() {
    local snapshot_dir="$1"
    if restore_data_snapshot "$snapshot_dir"; then
        UPDATE_SNAPSHOT_RESTORED=1
        return 0
    fi
    if ! restore_env_from_snapshot "$snapshot_dir"; then
        warn "完整数据快照恢复失败，且无法单独恢复更新前的 .env，请使用备份手动恢复: ${LAST_BACKUP_PATH:-<unknown>}"
    fi
    return 1
}

restore_data_permissions() {
    # Reapplies the ownership/mode contract of prepare_data_and_config after a
    # snapshot restore: the staged copy arrives as root:0700, which the
    # systemd service user cannot even traverse. The service user must be able
    # to walk DATA_DIR and write the database (WAL/SHM), while .env stays
    # root:SERVICE_GROUP 0640. Non-systemd installs keep the calling user's
    # ownership so the restored directory remains fully usable. Every required
    # step is attempted; returns non-zero when any of them failed.
    local db_path failed=0
    db_path=$(read_env_value DB_PATH)
    if is_systemd; then
        as_root chown "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR" \
            || { warn "恢复后无法设置数据目录属主 ${SERVICE_USER}:${SERVICE_GROUP}（$DATA_DIR），请手动修复"; failed=1; }
        as_root chmod 0750 "$DATA_DIR" \
            || { warn "恢复后无法设置数据目录权限 0750（$DATA_DIR），请手动修复"; failed=1; }
        as_root chown root:"$SERVICE_GROUP" "$(env_file_path)" \
            || { warn "恢复后无法设置 .env 属主 root:${SERVICE_GROUP}，请手动修复"; failed=1; }
        as_root chmod 0640 "$(env_file_path)" \
            || { warn "恢复后无法设置 .env 权限 0640，请手动修复"; failed=1; }
        fix_database_permissions "$db_path" \
            || { warn "恢复后无法设置数据库文件权限，请手动修复"; failed=1; }
    else
        as_root chown "$(id -u):$(id -g)" "$DATA_DIR" \
            || { warn "恢复后无法设置数据目录属主（$DATA_DIR），请手动修复"; failed=1; }
        as_root chmod 0750 "$DATA_DIR" \
            || { warn "恢复后无法设置数据目录权限 0750（$DATA_DIR），请手动修复"; failed=1; }
    fi
    return "$failed"
}

normalize_domain() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

valid_domain() {
    local domain="$1" label remainder
    [ -n "$domain" ] && [ "${#domain}" -le 253 ] || return 1
    [ "$domain" = "$(normalize_domain "$domain")" ] || return 1
    [[ "$domain" != *"://"* && "$domain" != *"/"* && "$domain" != *":"* && "$domain" != *"*"* ]] || return 1
    [[ "$domain" =~ ^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$ ]] || return 1
    [[ "$domain" == *.* ]] || return 1
    [[ ! "$domain" =~ ^[0-9]+(\.[0-9]+){3}$ ]] || return 1

    remainder="$domain"
    while :; do
        if [[ "$remainder" == *.* ]]; then
            label="${remainder%%.*}"
            remainder="${remainder#*.}"
        else
            label="$remainder"
            remainder=""
        fi
        [ -n "$label" ] && [ "${#label}" -le 63 ] || return 1
        [[ "$label" =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?$ ]] || return 1
        [ -n "$remainder" ] || break
    done
    [[ "$label" =~ [a-z] ]]
}

valid_certbot_email() {
    local email="$1"
    [ -z "$email" ] && return 0
    [[ "$email" =~ ^[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$ ]]
}

download() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --retry 3 --retry-delay 2 --connect-timeout 15 -fsSL "$1" -o "$2"
}

cosign_sha256_for_platform() {
    case "$1" in
        darwin-amd64) printf '%s\n' 'ec648fddfedf1dad59dff9fbab177284a618204e03126ea37a87ab3cec4e7cb1' ;;
        darwin-arm64) printf '%s\n' 'b2987c1b55a1e2735c59ac5c3e140acbf7ba5c1ed0cc07dbbf1b85676595237e' ;;
        linux-amd64) printf '%s\n' '309779b0c4e409186b0a80daba99041fe2cf65a920ce645013901df6211895a9' ;;
        linux-arm64) printf '%s\n' 'df408e5418129306fed7349ec46e27be0445d05c5127c07f435e9a566af67593' ;;
        *) return 1 ;;
    esac
}

ensure_cosign() {
    local tmp_dir="$1" suffix expected actual candidate existing
    if [ -n "$COSIGN_BIN" ] && [ -x "$COSIGN_BIN" ]; then
        return 0
    fi
    existing=$(command -v cosign 2>/dev/null || true)
    if [ -n "$existing" ]; then
        COSIGN_BIN="$existing"
        return 0
    fi

    suffix=$(detect_platform)
    expected=$(cosign_sha256_for_platform "$suffix") \
        || fail "cosign 不支持当前平台: $suffix"
    candidate="${tmp_dir}/cosign-${suffix}"
    info "本机缺少 cosign，正在获取经过固定校验的 Sigstore cosign ${COSIGN_VERSION}..."
    download "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-${suffix}" "$candidate" \
        || fail "cosign 下载失败，无法验证已签名 Release"
    actual=$(sha256_file "$candidate" | tr '[:upper:]' '[:lower:]')
    [ "$actual" = "$expected" ] || fail "cosign 下载文件 SHA-256 校验失败"
    chmod 0755 "$candidate"
    COSIGN_BIN="$candidate"
    ok "cosign ${COSIGN_VERSION} 已准备就绪（仅用于本次校验）"
}

verify_release_signature() {
    local version="$1" checksum_file="$2" bundle_file="$3" identity
    if ! download "https://github.com/${REPO}/releases/download/${version}/SHA256SUMS.bundle" "$bundle_file" 2>/dev/null; then
        warn "该 Release 没有 Sigstore 签名清单，继续执行兼容的 SHA-256 校验"
        return 0
    fi
    ensure_cosign "${bundle_file%/*}"
    identity="https://github.com/${REPO}/.github/workflows/release.yml@refs/tags/${version}"
    "$COSIGN_BIN" verify-blob --bundle "$bundle_file" \
        --certificate-identity "$identity" \
        --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
        "$checksum_file" >/dev/null \
        || fail "SHA256SUMS 的 Sigstore 签名验证失败"
    ok "已验证 Release 的 Sigstore 签名"
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$1" | awk '{print $1}'
    else
        fail "缺少 sha256sum 或 shasum，无法校验下载文件"
    fi
}

generate_secret() {
    if command -v openssl >/dev/null 2>&1; then
        openssl rand -hex 32
    else
        od -An -N32 -tx1 /dev/urandom | tr -d ' \n'
    fi
}

valid_portable_secret_token() {
    local value="$1"
    local LC_ALL=C
    [ -n "$value" ] || return 1
    [[ "$value" =~ ^[[:graph:]]+$ ]] || return 1
    case "$value" in
        *\'*|*\"*|*\\*) return 1 ;;
    esac
    return 0
}

generate_distinct_secret() {
    local candidate forbidden collision attempt
    for ((attempt = 1; attempt <= 32; attempt++)); do
        candidate=$(generate_secret)
        valid_portable_secret_token "$candidate" || continue
        [ "${#candidate}" -ge 32 ] || continue
        collision=0
        for forbidden in "$@"; do
            if [ -n "$forbidden" ] && [ "$candidate" = "$forbidden" ]; then
                collision=1
                break
            fi
        done
        if [ "$collision" = "0" ]; then
            printf '%s\n' "$candidate"
            return 0
        fi
    done
    fail "无法生成互不相同的安全密钥；现有配置未修改"
}

detect_platform() {
    local os arch
    os=$(uname -s | tr '[:upper:]' '[:lower:]')
    arch=$(uname -m)
    case "$os" in
        linux) os="linux" ;;
        darwin) os="darwin" ;;
        *) fail "不支持的操作系统: $os" ;;
    esac
    case "$arch" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail "不支持的架构: $arch" ;;
    esac
    printf '%s-%s\n' "$os" "$arch"
}

get_latest_version() {
    curl --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 \
        --connect-timeout 15 -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//'
}

resolve_latest_version() {
    local version
    info "获取最新 Release..." >&2
    version=$(get_latest_version) || true
    valid_version "$version" || fail "无法获取有效的最新 Release 版本: ${version:-<empty>}"
    printf '%s\n' "$version"
}

get_current_version() {
    if [ -x "${INSTALL_DIR}/${BIN_NAME}" ]; then
        "${INSTALL_DIR}/${BIN_NAME}" --version 2>/dev/null || printf '已安装（版本未知）\n'
    else
        printf '\n'
    fi
}

download_release_binary() {
    local version="$1" tmp_dir="$2" suffix asset binary_file checksum_file bundle_file expected actual
    suffix=$(detect_platform)
    asset="${BIN_NAME}-${suffix}"
    binary_file="${tmp_dir}/${asset}"
    checksum_file="${tmp_dir}/SHA256SUMS"
    bundle_file="${tmp_dir}/SHA256SUMS.bundle"
    info "下载 Meridian ${version} (${suffix})..."
    download "https://github.com/${REPO}/releases/download/${version}/${asset}" "$binary_file" \
        || fail "二进制下载失败，请检查网络和 Release"
    download "https://github.com/${REPO}/releases/download/${version}/SHA256SUMS" "$checksum_file" \
        || fail "SHA256SUMS 下载失败；已停止安装"
    verify_release_signature "$version" "$checksum_file" "$bundle_file"
    expected=$(awk -v file="$asset" '$2 == file || $2 == "*" file { print $1; exit }' "$checksum_file")
    printf '%s' "$expected" | grep -Eq '^[[:xdigit:]]{64}$' \
        || fail "SHA256SUMS 中缺少 ${asset} 的有效校验值"
    actual=$(sha256_file "$binary_file")
    expected=$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')
    actual=$(printf '%s' "$actual" | tr '[:upper:]' '[:lower:]')
    [ "$expected" = "$actual" ] || fail "下载文件 SHA-256 校验失败"
    chmod 0755 "$binary_file"
    DOWNLOADED_BINARY="$binary_file"
    ok "SHA-256 校验通过"
}

env_file_path() {
    printf '%s/.env\n' "$DATA_DIR"
}

read_env_value() {
    local key="$1" env_file value=""
    env_file=$(env_file_path)
    if [ -f "$env_file" ] || as_root test -f "$env_file" 2>/dev/null; then
        # $1 is an awk field reference, not a shell variable.
        # shellcheck disable=SC2016
        value=$(as_root awk -F= -v wanted="$key" '$1 == wanted { sub(/^[^=]*=/, ""); print; exit }' "$env_file" 2>/dev/null || true)
    fi
    printf '%s\n' "$value"
}

read_unique_env_secret_assignment() {
    local key="$1" env_file raw_value status
    env_file=$(env_file_path)
    # shellcheck disable=SC2016
    if raw_value=$(LC_ALL=C as_root awk -v wanted="$key" '
        {
            candidate=$0
            sub(/^[[:space:]]+/, "", candidate)
            if (candidate ~ /^export[[:space:]]+/) {
                sub(/^export[[:space:]]+/, "", candidate)
            }
            if (substr(candidate, 1, length(wanted)) != wanted) next
            remainder=substr(candidate, length(wanted) + 1)
            if (remainder != "" && substr(remainder, 1, 1) != "=" \
                    && remainder !~ /^[[:space:]]/) next
            count++
            if (substr($0, 1, length(wanted) + 1) != wanted "=") malformed=1
            if (count == 1) value=substr($0, length(wanted) + 2)
        }
        END {
            if (count == 0) exit 1
            if (count != 1 || malformed) exit 2
            print value
        }
    ' "$env_file" 2>/dev/null); then
        :
    else
        status=$?
        if [ "$status" -eq 1 ]; then
            printf '\n'
            return 0
        fi
        fail "${key} 的 EnvironmentFile 定义重复或含歧义；请保留唯一的 KEY=value 定义后重试"
    fi
    printf '%s\n' "$raw_value"
}

read_legacy_env_secret() {
    local key="$1" raw_value effective_value
    raw_value=$(read_unique_env_secret_assignment "$key") || return 1
    if [ -z "$raw_value" ]; then
        printf '\n'
        return 0
    fi

    case "$raw_value" in
        \'*\') effective_value=${raw_value:1:${#raw_value}-2} ;;
        \"*\") effective_value=${raw_value:1:${#raw_value}-2} ;;
        *\'*|*\"*)
            fail "${key} 的引号形式不完整或含歧义；现有配置未修改"
            ;;
        *) effective_value="$raw_value" ;;
    esac
    if [ -n "$effective_value" ] && ! valid_portable_secret_token "$effective_value"; then
        fail "${key} 必须是 ASCII token，或仅用一对匹配的单引号/双引号包裹该 token；现有配置未修改"
    fi
    printf '%s\n' "$effective_value"
}

read_strict_dynamic_route_key() {
    local raw_value
    raw_value=$(read_unique_env_secret_assignment DYNAMIC_ROUTE_KEY) || return 1
    if [ -n "$raw_value" ] && ! valid_portable_secret_token "$raw_value"; then
        fail "DYNAMIC_ROUTE_KEY 必须使用不带引号、反斜杠、空白或非 ASCII 字节的单行值；现有配置未修改"
    fi
    printf '%s\n' "$raw_value"
}

validate_existing_secret_configuration() {
    local jwt_secret upstream_header_key dynamic_route_key credential_key
    jwt_secret=$(read_legacy_env_secret JWT_SECRET) || return 1
    upstream_header_key=$(read_legacy_env_secret UPSTREAM_HEADER_KEY) || return 1
    dynamic_route_key=$(read_strict_dynamic_route_key) || return 1
    credential_key=$(read_legacy_env_secret MERIDIAN_SECRET_KEY) || return 1

    if [ -n "$jwt_secret" ] && [ "${#jwt_secret}" -lt 32 ]; then
        fail "现有 JWT_SECRET 少于 32 字节；现有配置未修改"
    fi
    if [ -n "$upstream_header_key" ] && [ "${#upstream_header_key}" -lt 32 ]; then
        fail "现有 UPSTREAM_HEADER_KEY 少于 32 字节；现有配置未修改"
    fi
    if [ -n "$dynamic_route_key" ] && [ "${#dynamic_route_key}" -lt 32 ]; then
        fail "现有 DYNAMIC_ROUTE_KEY 少于 32 字节；现有配置未修改"
    fi
    if [ -n "$credential_key" ] && [ "${#credential_key}" -lt 32 ]; then
        fail "现有 MERIDIAN_SECRET_KEY 少于 32 字节；现有配置未修改"
    fi
    if [ -n "$jwt_secret" ] && [ -n "$upstream_header_key" ] \
        && [ "$jwt_secret" = "$upstream_header_key" ]; then
        fail "UPSTREAM_HEADER_KEY 必须与 JWT_SECRET 使用不同的值；现有配置未修改"
    fi
    if [ -n "$dynamic_route_key" ] && { [ "$dynamic_route_key" = "$jwt_secret" ] \
        || [ "$dynamic_route_key" = "$upstream_header_key" ]; }; then
        fail "DYNAMIC_ROUTE_KEY 必须与 JWT_SECRET 和 UPSTREAM_HEADER_KEY 使用不同的值；现有配置未修改"
    fi
    if [ -n "$credential_key" ] && { [ "$credential_key" = "$jwt_secret" ] \
        || [ "$credential_key" = "$upstream_header_key" ] \
        || [ "$credential_key" = "$dynamic_route_key" ]; }; then
        fail "MERIDIAN_SECRET_KEY 必须与其他长期密钥使用不同的值；现有配置未修改"
    fi
}

env_has_key() {
    local key="$1" env_file
    env_file=$(env_file_path)
    # $1 is an awk field reference, not a shell variable.
    # shellcheck disable=SC2016
    as_root awk -F= -v wanted="$key" '$1 == wanted { found=1; exit } END { exit !found }' "$env_file" 2>/dev/null
}

install_env_file() {
    local source_file="$1" env_file
    env_file=$(env_file_path) || return 1
    if is_systemd; then
        as_root install -o root -g "$SERVICE_GROUP" -m 0640 "$source_file" "${env_file}.new" || return 1
    else
        as_root install -o "$(id -u)" -g "$(id -g)" -m 0600 "$source_file" "${env_file}.new" || return 1
    fi
    as_root mv -f "${env_file}.new" "$env_file" || return 1
}

append_env_default() {
    local key="$1" value="$2" tmp_dir="$3" env_file tmp_file status
    env_file=$(env_file_path) || return 1
    if env_has_key "$key"; then
        return 0
    else
        status=$?
        [ "$status" -eq 1 ] || return 1
    fi
    tmp_file="${tmp_dir}/env-default-${key}"
    as_root cat "$env_file" > "$tmp_file" || return 1
    printf '%s=%s\n' "$key" "$value" >> "$tmp_file" || return 1
    chmod 0600 "$tmp_file" || return 1
    install_env_file "$tmp_file" || return 1
}

normalize_insecure_bind() {
    local tmp_dir="$1" env_file bind tls allow tmp_file
    env_file=$(env_file_path) || return 1
    bind=$(read_env_value PANEL_BIND_ADDR)
    tls=$(printf '%s' "$(read_env_value PANEL_TLS_ENABLED)" | tr '[:upper:]' '[:lower:]')
    allow=$(printf '%s' "$(read_env_value ALLOW_INSECURE_HTTP)" | tr '[:upper:]' '[:lower:]')
    case "$bind" in
        0.0.0.0|::)
            if [ "$tls" = "1" ] || [ "$tls" = "true" ] || [ "$tls" = "yes" ] || [ "$tls" = "on" ]; then
                return 0
            fi
            if [ "$allow" = "1" ] || [ "$allow" = "true" ] || [ "$allow" = "yes" ] || [ "$allow" = "on" ]; then
                return 0
            fi
            tmp_file="${tmp_dir}/env-loopback-bind"
            # shellcheck disable=SC2016
            as_root awk -F= '$1 != "PANEL_BIND_ADDR" { print }' "$env_file" > "$tmp_file" || return 1
            printf 'PANEL_BIND_ADDR=127.0.0.1\n' >> "$tmp_file" || return 1
            chmod 0600 "$tmp_file" || return 1
            install_env_file "$tmp_file" || return 1
            warn "检测到旧版公网面板绑定，已迁移为 127.0.0.1；如确需明文公网访问，请显式设置 ALLOW_INSECURE_HTTP=true"
            ;;
    esac
}

ensure_setup_token() {
    local tmp_dir="$1" env_file tmp_file existing_token
    env_file=$(env_file_path) || return 1
    existing_token=$(read_env_value SETUP_TOKEN) || return 1
    if [ -n "$existing_token" ]; then
        SETUP_TOKEN_ORIGIN="existing"
        return 0
    fi
    INITIAL_SETUP_TOKEN=$(generate_secret) || return 1
    tmp_file="${tmp_dir}/env-setup-token"
    # $1 is an awk field reference, not a shell variable.
    # shellcheck disable=SC2016
    as_root awk -F= '$1 != "SETUP_TOKEN" { print }' "$env_file" > "$tmp_file" || return 1
    printf 'SETUP_TOKEN=%s\n' "$INITIAL_SETUP_TOKEN" >> "$tmp_file" || return 1
    chmod 0600 "$tmp_file" || return 1
    install_env_file "$tmp_file" || return 1
    SETUP_TOKEN_ORIGIN="generated"
}

ensure_upstream_header_key() {
    local tmp_dir="$1" env_file tmp_file key_value key_length new_key jwt_secret dynamic_route_key
    env_file=$(env_file_path) || return 1
    key_value=$(read_legacy_env_secret UPSTREAM_HEADER_KEY) || return 1
    jwt_secret=$(read_legacy_env_secret JWT_SECRET) || return 1
    dynamic_route_key=$(read_strict_dynamic_route_key) || return 1

    if [ -n "$key_value" ]; then
        key_length=${#key_value}
        [ "$key_length" -ge 32 ] \
            || fail "现有 UPSTREAM_HEADER_KEY 少于 32 字节；为避免破坏已加密数据，安装器不会自动替换"
        if { [ -n "$jwt_secret" ] && [ "$key_value" = "$jwt_secret" ]; } \
            || { [ -n "$dynamic_route_key" ] && [ "$key_value" = "$dynamic_route_key" ]; }; then
            fail "UPSTREAM_HEADER_KEY 必须与 JWT_SECRET 和 DYNAMIC_ROUTE_KEY 使用不同的值；现有配置未修改"
        fi
        return 0
    fi

    new_key=$(generate_distinct_secret "$jwt_secret" "$dynamic_route_key") || return 1
    tmp_file="${tmp_dir}/env-upstream-header-key"
    # $1 is an awk field reference, not a shell variable.
    # shellcheck disable=SC2016
    as_root awk -F= '$1 != "UPSTREAM_HEADER_KEY" { print }' "$env_file" > "$tmp_file" || return 1
    printf 'UPSTREAM_HEADER_KEY=%s\n' "$new_key" >> "$tmp_file" || return 1
    chmod 0600 "$tmp_file" || return 1
    install_env_file "$tmp_file" || return 1
}

ensure_dynamic_route_key() {
    local tmp_dir="$1" env_file tmp_file key_value new_key jwt_secret upstream_header_key last_byte status
    env_file=$(env_file_path) || return 1
    validate_existing_secret_configuration || return 1
    key_value=$(read_strict_dynamic_route_key) || return 1
    [ -z "$key_value" ] || return 0

    jwt_secret=$(read_legacy_env_secret JWT_SECRET) || return 1
    upstream_header_key=$(read_legacy_env_secret UPSTREAM_HEADER_KEY) || return 1
    new_key=$(generate_distinct_secret "$jwt_secret" "$upstream_header_key") || return 1
    tmp_file="${tmp_dir}/env-dynamic-route-key"
    if env_has_key DYNAMIC_ROUTE_KEY; then
        # $1 is an awk field reference, not a shell variable.
        # shellcheck disable=SC2016
        as_root awk -F= '$1 != "DYNAMIC_ROUTE_KEY" { print }' "$env_file" > "$tmp_file" || return 1
    else
        status=$?
        [ "$status" -eq 1 ] || return 1
        # Missing-key migration is append-only: retain every existing byte and
        # add a record separator only when the final record lacked one.
        as_root cat "$env_file" > "$tmp_file" || return 1
        if as_root test -s "$env_file"; then
            last_byte=$(as_root tail -c 1 "$env_file") || return 1
            [ -z "$last_byte" ] || printf '\n' >> "$tmp_file" || return 1
        fi
    fi
    printf 'DYNAMIC_ROUTE_KEY=%s\n' "$new_key" >> "$tmp_file" || return 1
    chmod 0600 "$tmp_file" || return 1
    install_env_file "$tmp_file" || return 1
}


set_panel_env() {
    local bind_addr="$1" domain="$2" proxies="$3" allow_insecure="$4" tmp_dir="$5" env_file tmp_file
    env_file=$(env_file_path) || return 1
    tmp_file="${tmp_dir}/panel.env"
    # $1 is an awk field reference, not a shell variable.
    # shellcheck disable=SC2016
    as_root awk -F= '$1 != "PANEL_BIND_ADDR" && $1 != "PANEL_DOMAIN" && $1 != "TRUSTED_PROXY_CIDRS" && $1 != "ALLOW_INSECURE_HTTP" { print }' "$env_file" > "$tmp_file" || return 1
    printf 'PANEL_BIND_ADDR=%s\nPANEL_DOMAIN=%s\nTRUSTED_PROXY_CIDRS=%s\nALLOW_INSECURE_HTTP=%s\n' \
        "$bind_addr" "$domain" "$proxies" "$allow_insecure" >> "$tmp_file" || return 1
    chmod 0600 "$tmp_file" || return 1
    install_env_file "$tmp_file" || return 1
}

write_rotated_env() {
    local secret="$1" output="$2" env_file
    env_file=$(env_file_path) || return 1
    # $1 is an awk field reference, not a shell variable.
    # shellcheck disable=SC2016
    as_root awk -F= '$1 != "JWT_SECRET" { print }' "$env_file" > "$output" || return 1
    printf 'JWT_SECRET=%s\n' "$secret" >> "$output" || return 1
    chmod 0600 "$output" || return 1
}

remove_loopback_proxies() {
    local current="$1" item result="" old_ifs="$IFS"
    IFS=','
    for item in $current; do
        item=$(printf '%s' "$item" | tr -d '[:space:]')
        [ -n "$item" ] || continue
        [ "$item" = "127.0.0.1/32" ] && continue
        [ "$item" = "::1/128" ] && continue
        result="${result:+${result},}${item}"
    done
    IFS="$old_ifs"
    printf '%s\n' "$result"
}

read_config_port() {
    local configured
    configured=$(read_env_value PORT)
    if [[ "$configured" =~ ^[0-9]+$ ]] && [ "$configured" -ge 1 ] && [ "$configured" -le 65535 ]; then
        printf '%s\n' "$configured"
    else
        printf '9090\n'
    fi
}

health_url() {
    printf 'http://127.0.0.1:%s/api/auth/check\n' "$(read_config_port)"
}

wait_for_health() {
    local attempts="${1:-20}" url code i
    command -v curl >/dev/null 2>&1 || return 1
    url=$(health_url)
    for ((i = 1; i <= attempts; i++)); do
        code=$(curl --noproxy '*' --proto '=http' --connect-timeout 1 --max-time 2 \
            -sS -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)
        [ "$code" = "200" ] && return 0
        sleep 1
    done
    return 1
}

ensure_service_user() {
    local nologin_shell
    nologin_shell=$(command -v nologin || true)
    nologin_shell=${nologin_shell:-/usr/sbin/nologin}
    if command -v useradd >/dev/null 2>&1; then
        getent group "$SERVICE_GROUP" >/dev/null 2>&1 || as_root groupadd --system "$SERVICE_GROUP"
        id "$SERVICE_USER" >/dev/null 2>&1 || as_root useradd --system --gid "$SERVICE_GROUP" \
            --home-dir "$DATA_DIR" --shell "$nologin_shell" --no-create-home "$SERVICE_USER"
    elif command -v adduser >/dev/null 2>&1; then
        if ! id "$SERVICE_USER" >/dev/null 2>&1; then
            as_root addgroup -S "$SERVICE_GROUP" 2>/dev/null || true
            as_root adduser -S -H -h "$DATA_DIR" -s "$nologin_shell" -G "$SERVICE_GROUP" "$SERVICE_USER"
        fi
    else
        fail "系统缺少 useradd/adduser，无法创建服务用户"
    fi
}

prepare_data_and_config() {
    local tmp_dir="$1" env_file secret upstream_header_key dynamic_route_key credential_key env_tmp
    validate_data_dir || return 1
    env_file=$(env_file_path) || return 1
    if as_root test -L "$env_file"; then
        fail "拒绝修改符号链接形式的配置文件: $env_file"
    fi
    if as_root test -e "$env_file"; then
        if ! as_root test -f "$env_file"; then
            fail "配置路径不是普通文件: $env_file"
        fi
        validate_existing_secret_configuration || return 1
    fi
    if is_systemd; then
        ensure_service_user || return 1
        as_root install -d -o "$SERVICE_USER" -g "$SERVICE_GROUP" -m 0750 "$DATA_DIR" || return 1
    else
        as_root install -d -o "$(id -u)" -g "$(id -g)" -m 0750 "$DATA_DIR" || return 1
    fi

    if ! as_root test -f "$env_file"; then
        secret=$(generate_distinct_secret) || return 1
        upstream_header_key=$(generate_distinct_secret "$secret") || return 1
        dynamic_route_key=$(generate_distinct_secret "$secret" "$upstream_header_key") || return 1
        credential_key=$(generate_distinct_secret "$secret" "$upstream_header_key" "$dynamic_route_key") || return 1
        INITIAL_SETUP_TOKEN=$(generate_distinct_secret "$secret" "$upstream_header_key" "$dynamic_route_key" "$credential_key") || return 1
        env_tmp="${tmp_dir}/meridian.env"
        printf 'JWT_SECRET=%s\nUPSTREAM_HEADER_KEY=%s\nDYNAMIC_ROUTE_KEY=%s\nMERIDIAN_SECRET_KEY=%s\nSETUP_TOKEN=%s\nPORT=9090\nDB_PATH=%s/meridian.db\nPANEL_BIND_ADDR=127.0.0.1\nPANEL_DOMAIN=\nPANEL_ROUTE_DOMAIN=\nPANEL_TLS_ENABLED=false\nPANEL_TLS_CERT_FILE=\nPANEL_TLS_KEY_FILE=\nTRUSTED_PROXY_CIDRS=\nALLOW_INSECURE_HTTP=false\n' \
            "$secret" "$upstream_header_key" "$dynamic_route_key" "$credential_key" "$INITIAL_SETUP_TOKEN" "$DATA_DIR" > "$env_tmp" || return 1
        chmod 0600 "$env_tmp" || return 1
        install_env_file "$env_tmp" || return 1
        SETUP_TOKEN_ORIGIN="generated"
        ok "已创建安全配置: $env_file"
    else
        ensure_dynamic_route_key "$tmp_dir" || return 1
        append_env_default PANEL_BIND_ADDR 127.0.0.1 "$tmp_dir" || return 1
        append_env_default PANEL_DOMAIN "" "$tmp_dir" || return 1
        append_env_default PANEL_ROUTE_DOMAIN "" "$tmp_dir" || return 1
        append_env_default PANEL_TLS_ENABLED false "$tmp_dir" || return 1
        append_env_default PANEL_TLS_CERT_FILE "" "$tmp_dir" || return 1
        append_env_default PANEL_TLS_KEY_FILE "" "$tmp_dir" || return 1
        append_env_default TRUSTED_PROXY_CIDRS "" "$tmp_dir" || return 1
        append_env_default ALLOW_INSECURE_HTTP false "$tmp_dir" || return 1
        normalize_insecure_bind "$tmp_dir" || return 1
        credential_key=$(generate_distinct_secret "$(read_legacy_env_secret JWT_SECRET)" "$(read_legacy_env_secret UPSTREAM_HEADER_KEY)" "$(read_strict_dynamic_route_key)") || return 1
        append_env_default MERIDIAN_SECRET_KEY "$credential_key" "$tmp_dir" || return 1
        ensure_upstream_header_key "$tmp_dir" || return 1
        ensure_setup_token "$tmp_dir" || return 1
        if is_systemd; then
            as_root chown root:"$SERVICE_GROUP" "$env_file" || return 1
            as_root chmod 0640 "$env_file" || return 1
        fi
        info "保留现有配置: $env_file"
    fi
}

write_systemd_service() {
    local tmp_dir="$1" service_tmp
    is_systemd || return 0
    service_tmp="${tmp_dir}/meridian.service"
    cat > "$service_tmp" <<SVCEOF
[Unit]
Description=Meridian Emby reverse proxy management panel
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
UMask=0077
EnvironmentFile=${DATA_DIR}/.env
ExecStart=${INSTALL_DIR}/${BIN_NAME}
WorkingDirectory=${DATA_DIR}
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictAddressFamilies=${SYSTEMD_RESTRICT_ADDRESS_FAMILIES}
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
ReadWritePaths=${DATA_DIR}
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
SVCEOF
    as_root install -o root -g root -m 0644 "$service_tmp" "$SERVICE_FILE"
    as_root systemctl daemon-reload
    as_root systemctl enable "$SERVICE_NAME" >/dev/null
}

migrate_update_systemd_service() {
    local tmp_dir="$1" service_copy service_new legacy_line current_line configured_line
    is_systemd || return 0
    service_copy="${tmp_dir}/meridian.service.current"
    service_new="${tmp_dir}/meridian.service.new"
    UPDATE_SERVICE_SNAPSHOT="${tmp_dir}/meridian.service.before"
    as_root cp -p -- "$SERVICE_FILE" "$UPDATE_SERVICE_SNAPSHOT"
    as_root cp -p -- "$SERVICE_FILE" "$service_copy"
    configured_line=$(grep '^RestrictAddressFamilies=' "$service_copy" || true)
    legacy_line='RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6'
    current_line="RestrictAddressFamilies=${SYSTEMD_RESTRICT_ADDRESS_FAMILIES}"
    if [ "$configured_line" = "$current_line" ]; then
        return 0
    fi
    if [ "$configured_line" != "$legacy_line" ]; then
        warn "现有 systemd 网络族配置不是安装器管理的旧格式；拒绝自动覆盖: $SERVICE_FILE"
        return 1
    fi
    sed "s/^RestrictAddressFamilies=.*/${current_line}/" "$service_copy" > "$service_new"
    UPDATE_SERVICE_CHANGED=1
    as_root install -o root -g root -m 0644 "$service_new" "$SERVICE_FILE"
    as_root systemctl daemon-reload
}

restore_update_systemd_service() {
    if [ "$UPDATE_SERVICE_CHANGED" != "1" ]; then
        return 0
    fi
    [ -n "$UPDATE_SERVICE_SNAPSHOT" ] && [ -f "$UPDATE_SERVICE_SNAPSHOT" ] || return 1
    as_root cp -p -- "$UPDATE_SERVICE_SNAPSHOT" "${SERVICE_FILE}.restore"
    as_root mv -f -- "${SERVICE_FILE}.restore" "$SERVICE_FILE"
    as_root systemctl daemon-reload
    UPDATE_SERVICE_CHANGED=0
}

ensure_no_manual_process() {
    local binary="${INSTALL_DIR}/${BIN_NAME}"
    if command -v pgrep >/dev/null 2>&1 && pgrep -f -- "$binary" >/dev/null 2>&1; then
        fail "检测到手动运行的 Meridian；请先停止进程再更新，以保证数据库备份一致"
    fi
}

create_backup_archive() {
    local label="$1" stamp safe_label archive archive_tmp data_parent data_base
    validate_data_dir
    validate_backup_dir
    as_root test -d "$DATA_DIR" || return 1
    need_cmd tar
    safe_label=$(printf '%s' "$label" | tr -cd 'A-Za-z0-9._-')
    [ -n "$safe_label" ] || safe_label="internal"
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    archive="${BACKUP_DIR}/${BIN_NAME}-${safe_label}-${stamp}-$$.tar.gz"
    archive_tmp="${archive}.tmp.$$"
    data_parent=$(dirname -- "$DATA_DIR")
    data_base=$(basename -- "$DATA_DIR")
    as_root install -d -o root -g "$ROOT_GROUP" -m 0700 "$BACKUP_DIR"
    if ! as_root tar -C "$data_parent" -czf "$archive_tmp" "$data_base"; then
        as_root rm -f -- "$archive_tmp"
        return 1
    fi
    as_root chmod 0600 "$archive_tmp"
    as_root mv -f "$archive_tmp" "$archive"
    LAST_BACKUP_PATH="$archive"
}

restore_previous_binary() {
    [ -f "$PREVIOUS_BIN" ] || return 1
    as_root install -o root -g "$ROOT_GROUP" -m 0755 "$PREVIOUS_BIN" "${INSTALL_DIR}/${BIN_NAME}.rollback"
    as_root mv -f "${INSTALL_DIR}/${BIN_NAME}.rollback" "${INSTALL_DIR}/${BIN_NAME}"
}

cleanup_update_transaction() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ] && [ "$UPDATE_TRANSACTION" = "1" ]; then
        warn "更新中断，正在自动回滚并恢复更新前的二进制和数据状态..."
        if [ "$UPDATE_BINARY_CHANGED" = "1" ]; then
            restore_previous_binary || true
        fi
        if [ -n "$UPDATE_SNAPSHOT_DIR" ] && [ -d "$UPDATE_SNAPSHOT_DIR" ] \
            && [ "$UPDATE_SNAPSHOT_RESTORED" != "1" ]; then
            if ! restore_update_snapshot "$UPDATE_SNAPSHOT_DIR"; then
                warn "数据快照恢复失败，原数据目录未被删除，请使用备份手动恢复: ${LAST_BACKUP_PATH:-<unknown>}"
            fi
        fi
        if ! restore_update_systemd_service; then
            warn "systemd 服务文件恢复失败，请在重启前手动恢复: $SERVICE_FILE"
        fi
        if is_systemd; then
            if [ "$UPDATE_WAS_ACTIVE" = "1" ]; then
                as_root systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
            else
                as_root systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
            fi
        fi
        UPDATE_TRANSACTION=0
        UPDATE_BINARY_CHANGED=0
    fi
    UPDATE_SERVICE_CHANGED=0
    UPDATE_SERVICE_SNAPSHOT=""
    if [ -n "$UPDATE_TMP_DIR" ] && [ -d "$UPDATE_TMP_DIR" ] && [ "$UPDATE_TMP_DIR" != "/" ]; then
        if ! as_root rm -rf -- "$UPDATE_TMP_DIR"; then
            warn "无法清理更新临时目录（可能残留敏感快照），请手动删除: $UPDATE_TMP_DIR"
        fi
    fi
    return "$exit_code"
}

abort_update_transaction() {
    trap - INT TERM
    exit 130
}

detect_package_manager() {
    local requested="${MERIDIAN_PACKAGE_MANAGER:-}"
    if [ -n "$requested" ]; then
        case "$requested" in apt|dnf|yum|apk|pacman) printf '%s\n' "$requested"; return ;; esac
        return 1
    fi
    if command -v apt-get >/dev/null 2>&1; then printf 'apt\n'
    elif command -v dnf >/dev/null 2>&1; then printf 'dnf\n'
    elif command -v yum >/dev/null 2>&1; then printf 'yum\n'
    elif command -v apk >/dev/null 2>&1; then printf 'apk\n'
    elif command -v pacman >/dev/null 2>&1; then printf 'pacman\n'
    else return 1
    fi
}

install_cli_packages() {
    local manager="$1"
    case "$manager" in
        apt)
            as_root apt-get update
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates coreutils gawk grep sed tar
            ;;
        dnf)
            as_root dnf install -y curl ca-certificates coreutils gawk grep sed tar
            ;;
        yum)
            as_root yum install -y curl ca-certificates coreutils gawk grep sed tar
            ;;
        apk)
            as_root apk add --no-cache bash curl ca-certificates coreutils gawk grep sed tar
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed bash curl ca-certificates coreutils gawk grep sed tar
            ;;
        *) return 1 ;;
    esac
}

ensure_cli_dependencies() {
    local action="$1" manager command_name
    local required=(curl awk grep cmp install mktemp sed tr)
    local missing=()
    if [ "$action" = update ] || [ "$action" = password ]; then
        required+=(tar)
    fi
    for command_name in "${required[@]}"; do
        command -v "$command_name" >/dev/null 2>&1 || missing+=("$command_name")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    if [ "$(uname -s)" = Darwin ]; then
        fail "缺少必要命令: ${missing[*]}；请先安装 Xcode Command Line Tools"
    fi
    manager=$(detect_package_manager) \
        || fail "缺少必要命令 ${missing[*]}，且未找到受支持的包管理器"
    info "正在使用 ${manager} 补齐安装依赖: ${missing[*]}"
    install_cli_packages "$manager" \
        || fail "自动安装基础依赖失败"
    for command_name in "${required[@]}"; do
        need_cmd "$command_name"
    done
}

install_panel_packages() {
    local manager="$1"
    case "$manager" in
        apt)
            as_root apt-get update
            as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx certbot python3-certbot-nginx
            ;;
        dnf)
            as_root dnf install -y nginx certbot python3-certbot-nginx
            ;;
        yum)
            as_root yum install -y nginx certbot python3-certbot-nginx
            ;;
        apk)
            as_root apk add --no-cache nginx certbot certbot-nginx
            ;;
        pacman)
            as_root pacman -S --noconfirm --needed nginx certbot certbot-nginx
            ;;
        *) return 1 ;;
    esac
}

install_panel_dependencies() {
    local manager
    [ "$(uname -s)" != "Darwin" ] || {
        warn "macOS 不支持自动配置面板域名；请自行配置 Nginx/Caddy"
        return 1
    }
    if command -v nginx >/dev/null 2>&1 && command -v certbot >/dev/null 2>&1 \
        && certbot plugins 2>/dev/null | grep -q 'nginx'; then
        info "复用已安装的 Nginx、Certbot 和 Nginx 插件"
        return 0
    fi
    manager=$(detect_package_manager) || {
        warn "未找到受支持的包管理器（apt、dnf/yum、apk、pacman）"
        return 1
    }
    info "使用 ${manager} 安装 Nginx、Certbot 和 Nginx 插件..."
    install_panel_packages "$manager" || return 1
    command -v nginx >/dev/null 2>&1 && command -v certbot >/dev/null 2>&1
}

start_nginx() {
    if is_systemd; then
        as_root systemctl enable --now nginx
    elif command -v rc-service >/dev/null 2>&1; then
        as_root rc-update add nginx default >/dev/null 2>&1 || true
        as_root rc-service nginx start >/dev/null 2>&1 || as_root rc-service nginx restart
    else
        as_root nginx -t
        as_root nginx -s reload >/dev/null 2>&1 || as_root nginx
    fi
}

nginx_test_and_reload() {
    as_root nginx -t || return 1
    if is_systemd; then
        as_root systemctl reload nginx
    elif command -v rc-service >/dev/null 2>&1; then
        as_root rc-service nginx reload
    else
        as_root nginx -s reload
    fi
}

NGINX_CONFLICT_PATH=""
find_domain_conflict() {
    local domain="$1" file status
    NGINX_CONFLICT_PATH=""
    [ -d "$NGINX_ROOT" ] || return 1
    while IFS= read -r file; do
        [ "$file" = "$NGINX_CONFIG" ] && continue
        # AWK field references below must remain literal rather than expand in Shell.
        # shellcheck disable=SC2016
        if as_root awk -v domain="$domain" '
            function matches_server_name(name, suffix, prefix, suffix_len) {
                gsub(/^"+/, "", name)
                gsub(/"+$/, "", name)
                name = tolower(name)
                if (name == "" || name == "_") {
                    return 0
                }
                # Nginx regex names and variable-based names cannot be evaluated
                # safely here, so reject them rather than risk an override.
                if (name ~ /^~/ || index(name, "$") > 0) {
                    return 1
                }
                if (substr(name, 1, 2) == "*.") {
                    suffix = substr(name, 3)
                    suffix_len = length(suffix)
                    return length(domain) > suffix_len && \
                        substr(domain, length(domain) - suffix_len + 1) == suffix && \
                        substr(domain, length(domain) - suffix_len, 1) == "."
                }
                if (substr(name, length(name) - 1) == ".*") {
                    prefix = substr(name, 1, length(name) - 2)
                    return substr(domain, 1, length(prefix) + 1) == prefix "."
                }
                if (substr(name, 1, 1) == ".") {
                    suffix = substr(name, 2)
                    suffix_len = length(suffix)
                    return domain == suffix || (length(domain) > suffix_len && \
                        substr(domain, length(domain) - suffix_len + 1) == suffix && \
                        substr(domain, length(domain) - suffix_len, 1) == ".")
                }
                # Any other wildcard form is invalid or ambiguous in Nginx; keep
                # the installer conservative when one is encountered.
                if (index(name, "*") > 0) {
                    return 1
                }
                return name == domain
            }
            {
                line = $0
                sub(/[[:space:]]*#.*/, "", line)
                if (!collecting) {
                    if (match(line, /(^|[[:space:]])server_name([[:space:]]+|$)/)) {
                        values = substr(line, RSTART + RLENGTH)
                        collecting = 1
                    } else {
                        next
                    }
                } else {
                    values = values " " line
                }
                semicolon = index(values, ";")
                if (!semicolon) {
                    next
                }
                directive = substr(values, 1, semicolon - 1)
                collecting = 0
                count = split(directive, names, /[[:space:]]+/)
                for (name_index = 1; name_index <= count; name_index++) {
                    if (matches_server_name(names[name_index])) {
                        conflict = 1
                        exit
                    }
                }
            }
            END { exit(conflict ? 0 : 1) }
        ' "$file" 2>/dev/null; then
            NGINX_CONFLICT_PATH="$file"
            return 0
        else
            status=$?
            if [ "$status" -ne 1 ]; then
                NGINX_CONFLICT_PATH="$file"
                return 0
            fi
        fi
    done < <(as_root find "$NGINX_ROOT" -type f -print 2>/dev/null)
    return 1
}

canonical_nginx_redacted_log_format() {
    printf '%s\n' "log_format meridian_redacted '\$remote_addr - \$remote_user [\$time_local] \"\$request_method \$meridian_log_path \$server_protocol\" \$status \$body_bytes_sent';"
}

validate_managed_nginx_redaction_components() {
    local log_line
    log_line=$(canonical_nginx_redacted_log_format)
    # Nginx variables in the validator are literal, not Shell expressions.
    # shellcheck disable=SC2016
    LC_ALL=C as_root awk -v redaction_marker="$NGINX_REDACTION_MARKER" \
        -v log_line="$log_line" '
        function trim(value) {
            sub(/^[[:space:]]*/, "", value)
            sub(/[[:space:]]*$/, "", value)
            return value
        }
        function normalize(value) {
            value=trim(value)
            gsub(/[[:space:]]+/, " ", value)
            return value
        }
        BEGIN {
            access_line="access_log /var/log/nginx/meridian_access.log meridian_redacted;"
        }
        {
            raw=$0
            line=trim(raw)
            normalized=normalize(raw)
            if (index(raw, "$meridian_log_path") \
                    || index(raw, "meridian_redacted") \
                    || index(raw, "~^/_meridian/d/") \
                    || index(raw, "/_meridian/d/[REDACTED]") \
                    || line == redaction_marker) {
                component_seen=1
            }

            if (map_state != 0) {
                if (line == "" || line ~ /^#/) next
                if (map_state == 1 && normalized == "default $uri;") {
                    map_state=2
                    next
                }
                if (map_state == 2 \
                        && normalized == "~^/_meridian/d/ /_meridian/d/[REDACTED];") {
                    map_state=3
                    next
                }
                if (map_state == 3 && line == "}") {
                    complete_maps++
                    map_state=0
                    next
                }
                invalid=1
                next
            }

            if (normalized == "map $uri $meridian_log_path {") {
                maps++
                map_state=1
                next
            }
            if (line == log_line) {
                safe_logs++
                next
            }
            if (line == access_line) next
            if (line == redaction_marker) {
                if (raw == redaction_marker) markers++
                else invalid=1
                next
            }
            if (index(raw, "$meridian_log_path") \
                    || index(raw, "meridian_redacted") \
                    || index(raw, "~^/_meridian/d/") \
                    || index(raw, "/_meridian/d/[REDACTED]")) {
                invalid=1
            }
        }
        END {
            if (!component_seen) exit 10
            if (map_state != 0 || maps != 1 || complete_maps != 1 \
                    || safe_logs != 1 || markers > 1 || invalid) exit 1
            exit 0
        }
    ' "$NGINX_CONFIG" 2>/dev/null
}

write_panel_nginx_config() {
    local domain="$1" port="$2" output="$3" log_line
    log_line=$(canonical_nginx_redacted_log_format)
    cat > "$output" <<NGINXEOF
${NGINX_MARKER}
${NGINX_REDACTION_MARKER}
map \$http_upgrade \$meridian_connection_upgrade {
    default upgrade;
    '' close;
}

map \$uri \$meridian_log_path {
    default \$uri;
    ~^/_meridian/d/ /_meridian/d/[REDACTED];
}

${log_line}

server {
    listen 80;
    listen [::]:80;
    server_name ${domain};

    client_max_body_size 1m;
    large_client_header_buffers 4 32k;
    access_log /var/log/nginx/meridian_access.log meridian_redacted;

    location / {
        proxy_pass http://127.0.0.1:${port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection \$meridian_connection_upgrade;
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        send_timeout 3600s;
    }
}
NGINXEOF
}

migrate_managed_nginx_redaction() {
    local work_dir backup migrated log_line redaction_state insert_definitions=0 preserve_backup=0
    log_line=$(canonical_nginx_redacted_log_format)
    validate_nginx_config_path
    as_root test -e "$NGINX_CONFIG" || return 0
    if as_root test -L "$NGINX_CONFIG" \
        || ! as_root grep -Fqx "$NGINX_MARKER" "$NGINX_CONFIG"; then
        info "Nginx 配置不由 Meridian 安装器管理，已原样保留: $NGINX_CONFIG"
        return 0
    fi

    # Only the installer-owned v1.7 panel template is eligible; the marker by
    # itself is not permission to rewrite an unrelated file.
    # shellcheck disable=SC2016
    if { ! as_root grep -Fq 'map $http_upgrade $meridian_connection_upgrade {' "$NGINX_CONFIG" \
            && ! as_root grep -Fq 'map $http_upgrade $connection_upgrade {' "$NGINX_CONFIG"; } \
        || ! as_root grep -Fq 'proxy_pass http://127.0.0.1:' "$NGINX_CONFIG" \
        || ! as_root grep -Fq 'proxy_set_header Host $host;' "$NGINX_CONFIG"; then
        warn "Nginx 配置不匹配可识别的 Meridian v1.7 面板模板，已原样保留"
        return 1
    fi

    # Existing redaction is trusted only when its active map has exactly the
    # canonical ordered rules and its log_format is the exact safe definition.
    # Status 10 means that this recognizable v1.7 file has no redaction state
    # at all and is therefore eligible for a canonical one-time migration.
    if validate_managed_nginx_redaction_components; then
        :
    else
        redaction_state=$?
        if [ "$redaction_state" -eq 10 ]; then
            insert_definitions=1
        else
            warn "Nginx URI 脱敏日志定义不完整、冲突或不安全，已原样保留"
            return 1
        fi
    fi

    # shellcheck disable=SC2016
    if as_root awk '
        /^[[:space:]]*access_log[[:space:]]/ {
            line=$0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (line != "access_log /var/log/nginx/meridian_access.log meridian_redacted;") found=1
        }
        END { exit !found }
    ' "$NGINX_CONFIG"; then
        warn "Nginx 配置含自定义 access_log，无法保证 URI 脱敏且不会覆盖，已原样保留"
        return 1
    fi

    # shellcheck disable=SC2016
    if as_root awk '
        /^[[:space:]]*large_client_header_buffers[[:space:]]/ {
            line=$0
            sub(/^[[:space:]]*/, "", line)
            sub(/[[:space:]]*$/, "", line)
            if (line != "large_client_header_buffers 4 32k;") found=1
        }
        END { exit !found }
    ' "$NGINX_CONFIG"; then
        warn "Nginx 配置含自定义 large_client_header_buffers，无法安全覆盖，已原样保留"
        return 1
    fi

    work_dir=$(mktemp -d)
    chmod 0700 "$work_dir"
    backup="${work_dir}/nginx.before"
    migrated="${work_dir}/nginx.migrated"
    # log_line was also used for exact validation above; migration and trust
    # therefore share a single canonical definition.
    # shellcheck disable=SC2016
    if ! as_root cp -p -- "$NGINX_CONFIG" "$backup" \
        || ! LC_ALL=C as_root awk -v marker="$NGINX_MARKER" \
            -v redaction_marker="$NGINX_REDACTION_MARKER" \
            -v insert_definitions="$insert_definitions" -v log_line="$log_line" '
            BEGIN {
                access_line="access_log /var/log/nginx/meridian_access.log meridian_redacted;"
                capability_line="large_client_header_buffers 4 32k;"
            }
            {
                trimmed=$0
                sub(/^[[:space:]]*/, "", trimmed)
                sub(/[[:space:]]*$/, "", trimmed)
                if (trimmed == access_line) next
                if (trimmed == capability_line) next
                if ($0 == redaction_marker) next

                print
                if ($0 == marker) {
                    print redaction_marker
                    if (insert_definitions == 1) {
                        print "map $uri $meridian_log_path {"
                        print "    default $uri;"
                        print "    ~^/_meridian/d/ /_meridian/d/[REDACTED];"
                        print "}"
                        print ""
                        print log_line
                        print ""
                    }
                    saw_marker=1
                }
                if ($0 ~ /^[[:space:]]*server[[:space:]]*\{[[:space:]]*(#.*)?$/) {
                    match($0, /^[[:space:]]*/)
                    indent=substr($0, RSTART, RLENGTH) "    "
                    print indent access_line
                    print indent capability_line
                    servers++
                }
            }
            END { if (!saw_marker || servers == 0) exit 42 }
        ' "$NGINX_CONFIG" > "$migrated"; then
        as_root rm -rf -- "$work_dir"
        warn "Nginx 配置不是可识别的 Meridian v1.7 面板模板，已原样保留"
        return 1
    fi

    if as_root cmp -s -- "$NGINX_CONFIG" "$migrated"; then
        as_root rm -rf -- "$work_dir"
        return 0
    fi
    if ! as_root cp -p -- "$NGINX_CONFIG" "${NGINX_CONFIG}.new" \
        || ! as_root cp -- "$migrated" "${NGINX_CONFIG}.new" \
        || ! as_root mv -f -- "${NGINX_CONFIG}.new" "$NGINX_CONFIG"; then
        as_root rm -f -- "${NGINX_CONFIG}.new"
        as_root rm -rf -- "$work_dir"
        warn "无法原子写入 Nginx URI 脱敏配置，原配置未修改"
        return 1
    fi

    if ! nginx_test_and_reload; then
        warn "Nginx 配置检查或重载失败，正在恢复原配置"
        if ! as_root cp -p -- "$backup" "${NGINX_CONFIG}.restore" \
            || ! as_root mv -f -- "${NGINX_CONFIG}.restore" "$NGINX_CONFIG"; then
            warn "Nginx 原配置自动恢复失败，请立即从 $backup 手动恢复"
            preserve_backup=1
        else
            nginx_test_and_reload >/dev/null 2>&1 \
                || warn "Nginx 原配置已恢复，但自动重载失败"
        fi
        as_root rm -f -- "${NGINX_CONFIG}.new" "${NGINX_CONFIG}.restore"
        if [ "$preserve_backup" = "0" ]; then
            as_root rm -rf -- "$work_dir"
        fi
        return 1
    fi

    as_root rm -rf -- "$work_dir"
    ok "已将安装器管理的 Nginx 配置迁移为 URI 脱敏日志格式"
}

snapshot_panel_state() {
    local work_dir="$1" env_file
    env_file=$(env_file_path)
    as_root cp -p -- "$env_file" "${work_dir}/env.before"
    if as_root test -f "$NGINX_CONFIG"; then
        as_root cp -p -- "$NGINX_CONFIG" "${work_dir}/nginx.before"
        printf '1\n' > "${work_dir}/had-nginx"
    else
        printf '0\n' > "${work_dir}/had-nginx"
    fi
}

restore_panel_state() {
    local work_dir="$1" had_nginx env_file
    env_file=$(env_file_path)
    had_nginx=$(cat "${work_dir}/had-nginx")
    as_root cp -p -- "${work_dir}/env.before" "${env_file}.restore"
    as_root mv -f "${env_file}.restore" "$env_file"
    if [ "$had_nginx" = "1" ]; then
        as_root install -d -o root -g root -m 0755 "$(dirname -- "$NGINX_CONFIG")"
        as_root cp -p -- "${work_dir}/nginx.before" "${NGINX_CONFIG}.restore"
        as_root mv -f "${NGINX_CONFIG}.restore" "$NGINX_CONFIG"
    else
        as_root rm -f -- "$NGINX_CONFIG"
    fi
    if command -v nginx >/dev/null 2>&1; then
        nginx_test_and_reload >/dev/null 2>&1 || warn "Nginx 原配置已恢复，但自动重载失败"
    fi
    if is_systemd && [ -f "$SERVICE_FILE" ]; then
        as_root systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
    fi
}

cleanup_panel_transaction() {
    local exit_code=$?
    if [ "$PANEL_TRANSACTION" = "1" ] && [ -n "$PANEL_WORK_DIR" ]; then
        warn "面板域名配置中断，正在恢复原配置..."
        restore_panel_state "$PANEL_WORK_DIR" >/dev/null 2>&1 \
            || warn "面板配置自动恢复未完成，请检查 Nginx 和 Meridian 服务"
        PANEL_TRANSACTION=0
    fi
    if [ -n "$PANEL_WORK_DIR" ] && [ -d "$PANEL_WORK_DIR" ] && [ "$PANEL_WORK_DIR" != "/" ]; then
        as_root rm -rf -- "$PANEL_WORK_DIR"
    fi
    PANEL_WORK_DIR=""
    return "$exit_code"
}

abort_panel_transaction() {
    trap - INT TERM
    exit 130
}

begin_panel_transaction() {
    PANEL_WORK_DIR="$1"
    PANEL_TRANSACTION=1
    trap cleanup_panel_transaction EXIT
    trap abort_panel_transaction INT TERM
}

rollback_panel_transaction() {
    restore_panel_state "$PANEL_WORK_DIR" || warn "面板配置自动恢复未完成，请检查 Nginx 和 Meridian 服务"
    PANEL_TRANSACTION=0
    as_root rm -rf -- "$PANEL_WORK_DIR"
    PANEL_WORK_DIR=""
    trap - EXIT INT TERM
}

commit_panel_transaction() {
    PANEL_TRANSACTION=0
    as_root rm -rf -- "$PANEL_WORK_DIR"
    PANEL_WORK_DIR=""
    trap - EXIT INT TERM
}

restart_meridian_and_health() {
    is_systemd || return 1
    as_root systemctl restart "$SERVICE_NAME" || return 1
    wait_for_health 20
}

configure_panel_domain() {
    local domain="$1" email="$2" work_dir port proxies config_tmp
    validate_nginx_config_path
    is_systemd || {
        warn "自动面板域名配置要求 Meridian 由 systemd 管理"
        return 1
    }
    valid_domain "$domain" || {
        warn "域名无效；只能填写单个标准域名，不能含协议、路径、端口、IP 或通配符"
        return 1
    }
    valid_certbot_email "$email" || { warn "证书邮箱格式无效"; return 1; }
    if find_domain_conflict "$domain"; then
        warn "检测到同域名的现有 Nginx 配置，拒绝覆盖: $NGINX_CONFLICT_PATH"
        return 1
    fi
    if as_root test -L "$NGINX_CONFIG"; then
        warn "拒绝覆盖符号链接形式的 Nginx 配置: $NGINX_CONFIG"
        return 1
    fi
    if as_root test -e "$NGINX_CONFIG" \
        && ! as_root grep -Fqx "$NGINX_MARKER" "$NGINX_CONFIG"; then
        warn "Nginx 目标文件不带 Meridian 管理标记，拒绝覆盖: $NGINX_CONFIG"
        return 1
    fi

    work_dir=$(mktemp -d)
    chmod 0700 "$work_dir"
    snapshot_panel_state "$work_dir" || { rm -rf -- "$work_dir"; return 1; }
    begin_panel_transaction "$work_dir"
    if ! install_panel_dependencies || ! start_nginx; then
        warn "Nginx/Certbot 安装或启动失败，Meridian 服务保持可用"
        rollback_panel_transaction
        return 1
    fi

    port=$(read_config_port)
    config_tmp="${work_dir}/meridian-panel.conf"
    if ! write_panel_nginx_config "$domain" "$port" "$config_tmp" \
        || ! as_root install -d -o root -g root -m 0755 "$(dirname -- "$NGINX_CONFIG")" \
        || ! as_root install -o root -g root -m 0644 "$config_tmp" "${NGINX_CONFIG}.new" \
        || ! as_root mv -f "${NGINX_CONFIG}.new" "$NGINX_CONFIG" \
        || ! nginx_test_and_reload; then
        warn "Nginx 配置检查失败，正在恢复原配置"
        rollback_panel_transaction
        return 1
    fi

    local certbot_args=(--nginx -d "$domain" --cert-name "$domain" --non-interactive --agree-tos --redirect --keep-until-expiring)
    if [ -n "$email" ]; then
        certbot_args+=(--email "$email")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    if ! as_root certbot "${certbot_args[@]}" || ! nginx_test_and_reload \
        || ! migrate_managed_nginx_redaction; then
        warn "HTTPS 证书申请或 Nginx 重载失败，正在恢复原配置"
        rollback_panel_transaction
        return 1
    fi

    proxies="127.0.0.1/32,::1/128"
    if ! set_panel_env "127.0.0.1" "$domain" "$proxies" "false" "$work_dir" \
        || ! restart_meridian_and_health; then
        warn "面板切换到回环地址后健康检查失败，正在恢复原配置"
        rollback_panel_transaction
        return 1
    fi

    commit_panel_transaction
    ok "面板 HTTPS 已配置: https://${domain}"
    info "反代目标固定为 127.0.0.1:${port}；未读取或修改任何播放地址和站点端口"
    return 0
}

disable_panel_domain() {
    local work_dir proxies
    validate_nginx_config_path
    # A non-systemd environment (for example a container or a CI install
    # test) cannot safely restart Meridian after changing the panel binding.
    # Treat the no-domain choice as a no-op there instead of failing an
    # otherwise successful installation; operators can apply the choice when
    # the service is managed by systemd.
    is_systemd || {
        warn "未检测到 systemd，跳过自动取消面板域名；请在服务启动方式就绪后重新执行 --no-domain"
        return 0
    }
    work_dir=$(mktemp -d)
    chmod 0700 "$work_dir"
    snapshot_panel_state "$work_dir" || { rm -rf -- "$work_dir"; return 1; }
    begin_panel_transaction "$work_dir"
    if as_root test -f "$NGINX_CONFIG"; then
        if ! as_root grep -Fqx "$NGINX_MARKER" "$NGINX_CONFIG"; then
            warn "Nginx 配置没有 Meridian 管理标记，拒绝删除: $NGINX_CONFIG"
            commit_panel_transaction
            return 1
        fi
        if ! as_root rm -f -- "$NGINX_CONFIG" \
            || { command -v nginx >/dev/null 2>&1 && ! nginx_test_and_reload; }; then
            warn "删除面板反代后 Nginx 检查失败，正在恢复"
            rollback_panel_transaction
            return 1
        fi
    fi
    proxies=$(remove_loopback_proxies "$(read_env_value TRUSTED_PROXY_CIDRS)")
    if ! set_panel_env "0.0.0.0" "" "$proxies" "true" "$work_dir" || ! restart_meridian_and_health; then
        warn "恢复 IP 访问时健康检查失败，正在恢复原配置"
        rollback_panel_transaction
        return 1
    fi
    commit_panel_transaction
    ok "已取消安装器管理的面板域名；已显式启用明文兼容模式，可通过服务器IP:$(read_config_port)访问（建议尽快重新配置 HTTPS）"
}

prompt_domain_choice() {
    local existing_install="$1" answer
    if [ "$DOMAIN_MODE" = "configure" ] || [ "$DOMAIN_MODE" = "disable" ]; then
        return 0
    fi
    if [ "$ASSUME_YES" = "1" ]; then
        if [ "$existing_install" = "1" ]; then
            DOMAIN_MODE="preserve"
        else
            DOMAIN_MODE="disable"
        fi
        return 0
    fi
    if ask_yes_no "是否为管理面板配置域名和 HTTPS？" 0; then
        read -r -p "请输入面板域名（不含 http://、端口或路径）: " answer
        answer=$(normalize_domain "$answer")
        valid_domain "$answer" || fail "域名格式无效"
        REQUESTED_DOMAIN="$answer"
        read -r -p "证书邮箱（可留空）: " CERTBOT_EMAIL
        valid_certbot_email "$CERTBOT_EMAIL" || fail "证书邮箱格式无效"
        DOMAIN_MODE="configure"
    else
        DOMAIN_MODE="disable"
    fi
}

apply_domain_choice() {
    local existing_install="$1"
    prompt_domain_choice "$existing_install"
    case "$DOMAIN_MODE" in
        configure)
            configure_panel_domain "$REQUESTED_DOMAIN" "$CERTBOT_EMAIL" \
                || fail "面板域名配置失败；Meridian 已恢复，重新运行 install 可重试"
            ;;
        disable)
            if [ "$existing_install" = "0" ] \
                && [ -z "$(read_env_value PANEL_DOMAIN)" ] \
                && [ "$(read_env_value PANEL_BIND_ADDR)" != "127.0.0.1" ] \
                && ! as_root test -e "$NGINX_CONFIG"; then
                info "未配置面板域名；面板继续通过服务器IP:$(read_config_port)访问"
            else
                disable_panel_domain || fail "取消面板域名失败；原配置已恢复"
            fi
            ;;
        preserve)
            migrate_managed_nginx_redaction \
                || fail "Nginx URI 脱敏日志迁移失败；原配置已恢复"
            info "未指定域名操作，保留现有面板域名与证书配置"
            ;;
        *) fail "未知域名操作模式" ;;
    esac
}

print_setup_token_notice() {
    case "$SETUP_TOKEN_ORIGIN" in
        generated)
            [ -n "$INITIAL_SETUP_TOKEN" ] || return 1
            printf "  ${YELLOW}初始化令牌（仅显示这一次，请立即保存）:${NC} ${BOLD}%s${NC}\n" "$INITIAL_SETUP_TOKEN"
            ;;
        existing)
            printf "  ${YELLOW}若初始化仍待完成，root 可从 %s 恢复现有 SETUP_TOKEN；安装器不会自动显示现有令牌。${NC}\n" "$(env_file_path)"
            ;;
        "") ;;
        *) return 1 ;;
    esac
}

do_install() {
    local current_binary="${INSTALL_DIR}/${BIN_NAME}" tmp_dir version
    INITIAL_SETUP_TOKEN=""
    SETUP_TOKEN_ORIGIN=""
    init_privilege
    ensure_cli_dependencies install
    validate_install_dir
    validate_data_dir
    validate_backup_dir

    if [ -x "$current_binary" ]; then
        info "检测到已安装的 Meridian $(get_current_version)；install 不会执行更新"
        tmp_dir=$(mktemp -d)
        if ! prepare_data_and_config "$tmp_dir"; then
            rm -rf -- "$tmp_dir"
            return 1
        fi
        rm -rf -- "$tmp_dir"
        print_setup_token_notice || return 1
        apply_domain_choice 1
        return 0
    fi

    version=$(resolve_latest_version)
    tmp_dir=$(mktemp -d)
    chmod 0700 "$tmp_dir"
    download_release_binary "$version" "$tmp_dir"
    if ! prepare_data_and_config "$tmp_dir"; then
        rm -rf -- "$tmp_dir"
        return 1
    fi
    write_systemd_service "$tmp_dir"
    as_root install -d -o root -g "$ROOT_GROUP" -m 0755 "$INSTALL_DIR"
    as_root install -o root -g "$ROOT_GROUP" -m 0755 "$DOWNLOADED_BINARY" "${current_binary}.new"
    as_root mv -f "${current_binary}.new" "$current_binary"

    if is_systemd; then
        if ! as_root systemctl restart "$SERVICE_NAME" || ! wait_for_health 20; then
            as_root rm -f -- "$current_binary"
            as_root systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
            rm -rf -- "$tmp_dir"
            fail "首次启动未通过健康检查；二进制已移除，数据与配置已保留"
        fi
        ok "Meridian 服务健康检查通过"
    else
        warn "未检测到 systemd；已安装二进制，但需要手动加载 ${DATA_DIR}/.env 后启动"
    fi
    rm -rf -- "$tmp_dir"

    apply_domain_choice 0
    printf '\n%s\n' "Meridian ${version} 安装完成"
    if [ -n "$(read_env_value PANEL_DOMAIN)" ]; then
        printf '  面板地址: https://%s\n' "$(read_env_value PANEL_DOMAIN)"
    else
        printf '  面板地址: http://127.0.0.1:%s（默认仅本机；公网请配置 HTTPS 域名）\n' "$(read_config_port)"
    fi
    printf '  数据目录: %s\n' "$DATA_DIR"
    print_setup_token_notice || return 1
}

do_update() {
    local current_binary="${INSTALL_DIR}/${BIN_NAME}" current_version latest_version should_stop_after=0 tmp_dir
    INITIAL_SETUP_TOKEN=""
    SETUP_TOKEN_ORIGIN=""
    validate_install_dir
    validate_data_dir
    UPDATE_SERVICE_SNAPSHOT=""
    UPDATE_SERVICE_CHANGED=0
    [ -x "$current_binary" ] || fail "Meridian 尚未安装，请先运行 install"
    init_privilege
    ensure_cli_dependencies update
    is_systemd && [ ! -f "$SERVICE_FILE" ] \
        && fail "找不到 Meridian systemd 服务，请重新运行 install 修复安装"
    as_root test -L "$(env_file_path)" \
        && fail "拒绝修改符号链接形式的配置文件: $(env_file_path)"
    validate_existing_secret_configuration || return 1
    migrate_managed_nginx_redaction \
        || fail "Nginx URI 脱敏日志迁移失败；原配置已恢复"
    current_version=$(get_current_version)
    latest_version=$(resolve_latest_version)
    if [ "$current_version" = "$latest_version" ]; then
        ok "当前已是最新版本: $latest_version"
        return 0
    fi
    if valid_version "$current_version" && version_gt "$current_version" "$latest_version"; then
        fail "已安装版本 ${current_version} 高于最新 Release ${latest_version}；拒绝降级"
    fi

    tmp_dir=$(mktemp -d)
    chmod 0700 "$tmp_dir"
    UPDATE_TMP_DIR="$tmp_dir"
    download_release_binary "$latest_version" "$tmp_dir"

    UPDATE_TRANSACTION=1
    trap cleanup_update_transaction EXIT
    trap abort_update_transaction INT TERM

    if is_systemd; then
        if service_is_active; then
            UPDATE_WAS_ACTIVE=1
        else
            should_stop_after=1
        fi
        as_root systemctl stop "$SERVICE_NAME"
    else
        ensure_no_manual_process
    fi
    if ! create_backup_archive "pre-${latest_version}"; then
        fail "升级前一致性备份失败，现有程序未被替换"
    fi
    ok "升级前备份已创建: $LAST_BACKUP_PATH"

    # Byte-level snapshot for automatic rollback, taken while the service is
    # stopped and before any configuration key is added.
    UPDATE_SNAPSHOT_DIR="${tmp_dir}/data-snapshot"
    if ! snapshot_data_dir "$UPDATE_SNAPSHOT_DIR"; then
        fail "升级前数据快照失败，现有程序未被替换"
    fi

    prepare_data_and_config "$tmp_dir" || return 1
    if is_systemd; then
        migrate_update_systemd_service "$tmp_dir" || return 1
    fi

    as_root install -o root -g "$ROOT_GROUP" -m 0755 "$current_binary" "${PREVIOUS_BIN}.new"
    as_root mv -f "${PREVIOUS_BIN}.new" "$PREVIOUS_BIN"
    as_root install -o root -g "$ROOT_GROUP" -m 0755 "$DOWNLOADED_BINARY" "${current_binary}.new"
    as_root mv -f "${current_binary}.new" "$current_binary"
    UPDATE_BINARY_CHANGED=1

    if is_systemd; then
        as_root systemctl restart "$SERVICE_NAME"
        if ! wait_for_health 20; then
            warn "新版本健康检查失败，正在自动回滚..."
            restore_previous_binary || fail "回滚失败：缺少上一版本二进制，请手动恢复 ${LAST_BACKUP_PATH:-备份归档}"
            UPDATE_BINARY_CHANGED=0
            if ! restore_update_snapshot "$UPDATE_SNAPSHOT_DIR"; then
                warn "数据快照恢复失败，原数据目录未被删除，请使用备份手动恢复: $LAST_BACKUP_PATH"
            fi
            restore_update_systemd_service || fail "systemd 服务文件回滚失败，请手动恢复 ${UPDATE_SERVICE_SNAPSHOT:-原服务文件快照}"
            as_root systemctl restart "$SERVICE_NAME"
            wait_for_health 20 || fail "新版本与回滚版本均未通过健康检查"
            fail "新版本启动失败，已恢复上一版本及原数据配置"
        fi
        if [ "$should_stop_after" = "1" ]; then
            as_root systemctl stop "$SERVICE_NAME"
        fi
    else
        if ! "$current_binary" --version >/dev/null 2>&1; then
            warn "新版本二进制无法执行，正在自动回滚..."
            restore_previous_binary || true
            UPDATE_BINARY_CHANGED=0
            if ! restore_update_snapshot "$UPDATE_SNAPSHOT_DIR"; then
                warn "数据快照恢复失败，原数据目录未被删除，请使用备份手动恢复: $LAST_BACKUP_PATH"
            fi
            fail "新版本无法执行，已恢复上一版本及原数据配置"
        fi
        warn "未检测到 systemd：已跳过自动健康检查，请手动加载 ${DATA_DIR}/.env 后启动"
    fi

    UPDATE_TRANSACTION=0
    UPDATE_BINARY_CHANGED=0
    UPDATE_SERVICE_CHANGED=0
    UPDATE_SERVICE_SNAPSHOT=""
    UPDATE_TMP_DIR=""
    UPDATE_SNAPSHOT_DIR=""
    UPDATE_SNAPSHOT_RESTORED=0
    if ! as_root rm -rf -- "$tmp_dir"; then
        warn "无法清理更新临时目录（可能残留敏感快照），请手动删除: $tmp_dir"
    fi
    trap - EXIT INT TERM
    ok "已更新到最新版本: $latest_version"
    info "现有 .env、面板域名和证书均已保留；安装器管理的 Nginx 配置已按需完成 URI 日志脱敏迁移"
    print_setup_token_notice || return 1
}

password_byte_length() {
    LC_ALL=C printf '%s' "$1" | wc -c | tr -d '[:space:]'
}

snapshot_auth_files() {
    local snapshot_dir="$1" db_path="$2" source suffix name
    as_root install -d -o root -g "$ROOT_GROUP" -m 0700 "$snapshot_dir"
    as_root cp -p -- "$(env_file_path)" "${snapshot_dir}/env"
    for suffix in "" "-wal" "-shm" "-journal"; do
        source="${db_path}${suffix}"
        name="db${suffix}"
        if as_root test -e "$source"; then
            as_root cp -p -- "$source" "${snapshot_dir}/${name}"
        fi
    done
}

archive_auth_snapshot() {
    local snapshot_dir="$1" stamp archive archive_tmp
    validate_backup_dir
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    archive="${BACKUP_DIR}/${BIN_NAME}-pre-password-${stamp}-$$.tar.gz"
    archive_tmp="${archive}.tmp.$$"
    as_root install -d -o root -g "$ROOT_GROUP" -m 0700 "$BACKUP_DIR"
    as_root tar -C "$snapshot_dir" -czf "$archive_tmp" . || { as_root rm -f -- "$archive_tmp"; return 1; }
    as_root chmod 0600 "$archive_tmp"
    as_root mv -f "$archive_tmp" "$archive"
    LAST_BACKUP_PATH="$archive"
}

restore_auth_snapshot() {
    local snapshot_dir="$1" db_path="$2" suffix name source
    as_root rm -f -- "$db_path" "${db_path}-wal" "${db_path}-shm" "${db_path}-journal"
    for suffix in "" "-wal" "-shm" "-journal"; do
        name="db${suffix}"
        source="${snapshot_dir}/${name}"
        if as_root test -e "$source"; then
            as_root cp -p -- "$source" "${db_path}${suffix}"
        fi
    done
    as_root cp -p -- "${snapshot_dir}/env" "$(env_file_path)"
}

fix_database_permissions() {
    local db_path="$1" suffix file failed=0
    for suffix in "" "-wal" "-shm" "-journal"; do
        file="${db_path}${suffix}"
        if as_root test -e "$file"; then
            as_root chown "$SERVICE_USER:$SERVICE_GROUP" "$file" || failed=1
            as_root chmod 0600 "$file" || failed=1
        fi
    done
    return "$failed"
}

cleanup_password_transaction() {
    local exit_code=$?
    if [ "$exit_code" -ne 0 ] && [ "$PASSWORD_TRANSACTION" = "1" ] \
        && [ -n "$PASSWORD_SNAPSHOT_DIR" ] && [ -n "$PASSWORD_DB_PATH" ]; then
        warn "密码修改中断，正在恢复旧密码和 JWT 配置..."
        as_root systemctl stop "$SERVICE_NAME" >/dev/null 2>&1 || true
        if ! restore_auth_snapshot "$PASSWORD_SNAPSHOT_DIR" "$PASSWORD_DB_PATH" >/dev/null 2>&1; then
            warn "自动恢复凭据失败，请使用备份手动恢复: ${LAST_BACKUP_PATH:-<unknown>}"
        fi
        fix_database_permissions "$PASSWORD_DB_PATH" >/dev/null 2>&1 || true
        if ! as_root systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 \
            || ! wait_for_health 20 >/dev/null 2>&1; then
            warn "凭据已尝试恢复，但 Meridian 未通过健康检查，请检查服务日志"
        fi
        PASSWORD_TRANSACTION=0
    fi
    if [ -n "$PASSWORD_TMP_DIR" ] && [ -d "$PASSWORD_TMP_DIR" ] && [ "$PASSWORD_TMP_DIR" != "/" ]; then
        as_root rm -rf -- "$PASSWORD_TMP_DIR"
    fi
    unset password password_again new_secret 2>/dev/null || true
    return "$exit_code"
}

abort_password_transaction() {
    trap - INT TERM
    exit 130
}

do_password() {
    local password password_again length db_path tmp_dir snapshot_dir rotated_env new_secret mutated=0
    local current_binary="${INSTALL_DIR}/${BIN_NAME}"
    validate_install_dir
    [ -x "$current_binary" ] || fail "Meridian 尚未安装"
    is_systemd || fail "自动修改密码要求 Meridian 由 systemd 管理"
    init_privilege
    ensure_cli_dependencies password
    [ -f "$SERVICE_FILE" ] || fail "找不到 Meridian systemd 服务，请重新运行 install 修复安装"
    IFS= read -r -s -p "请输入新管理员密码（12-72 字节）: " password
    printf '\n'
    IFS= read -r -s -p "请再次输入新密码: " password_again
    printf '\n'
    [ "$password" = "$password_again" ] || { unset password password_again; fail "两次输入的密码不一致"; }
    length=$(password_byte_length "$password")
    if [ "$length" -lt 12 ] || [ "$length" -gt 72 ]; then
        unset password password_again
        fail "密码必须为 12-72 字节"
    fi

    db_path=$(read_env_value DB_PATH)
    [ -n "$db_path" ] || db_path="${DATA_DIR}/meridian.db"
    validate_db_path "$db_path" || fail "DB_PATH 不是安全的绝对数据库路径"
    as_root test -L "$db_path" && fail "拒绝修改符号链接形式的数据库"
    as_root test -f "$db_path" || fail "数据库不存在: $db_path"

    tmp_dir=$(mktemp -d)
    chmod 0700 "$tmp_dir"
    snapshot_dir="${tmp_dir}/snapshot"
    rotated_env="${tmp_dir}/env.rotated"
    PASSWORD_TMP_DIR="$tmp_dir"
    PASSWORD_SNAPSHOT_DIR="$snapshot_dir"
    PASSWORD_DB_PATH="$db_path"
    as_root systemctl stop "$SERVICE_NAME"
    if ! snapshot_auth_files "$snapshot_dir" "$db_path" || ! archive_auth_snapshot "$snapshot_dir"; then
        as_root systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
        as_root rm -rf -- "$tmp_dir"
        unset password password_again
        fail "密码修改前备份失败，未修改任何凭据"
    fi
    ok "凭据备份已创建: $LAST_BACKUP_PATH"
    PASSWORD_TRANSACTION=1
    trap cleanup_password_transaction EXIT
    trap abort_password_transaction INT TERM

    new_secret=$(generate_secret)
    write_rotated_env "$new_secret" "$rotated_env"
    if printf '%s\n' "$password" | as_root "$current_binary" admin reset-password --db "$db_path" --password-stdin; then
        mutated=1
    fi
    unset password password_again
    if [ "$mutated" != "1" ]; then
        fail "管理员密码修改失败，将自动恢复旧密码与 JWT 配置"
    fi

    if ! install_env_file "$rotated_env" || ! fix_database_permissions "$db_path" \
        || ! as_root systemctl restart "$SERVICE_NAME" || ! wait_for_health 20; then
        warn "重启或健康检查失败，正在恢复旧密码与 JWT 配置..."
        fail "密码修改失败，将自动执行凭据回滚"
    fi

    PASSWORD_TRANSACTION=0
    PASSWORD_TMP_DIR=""
    PASSWORD_SNAPSHOT_DIR=""
    PASSWORD_DB_PATH=""
    as_root rm -rf -- "$tmp_dir"
    trap - EXIT INT TERM
    unset new_secret
    ok "管理员密码已修改，所有旧登录令牌已失效"
}

remove_managed_nginx_config() {
    local tmp_dir backup
    validate_nginx_config_path
    as_root test -e "$NGINX_CONFIG" || return 0
    if as_root test -L "$NGINX_CONFIG" || ! as_root grep -Fqx "$NGINX_MARKER" "$NGINX_CONFIG"; then
        warn "Nginx 文件不是安装器管理的普通配置，已保留: $NGINX_CONFIG"
        return 0
    fi
    command -v nginx >/dev/null 2>&1 || {
        warn "找不到 nginx，无法安全验证删除操作；配置已保留"
        return 1
    }
    tmp_dir=$(mktemp -d)
    chmod 0700 "$tmp_dir"
    backup="${tmp_dir}/nginx.before"
    as_root cp -p -- "$NGINX_CONFIG" "$backup"
    as_root rm -f -- "$NGINX_CONFIG"
    if ! nginx_test_and_reload; then
        as_root cp -p -- "$backup" "$NGINX_CONFIG"
        nginx_test_and_reload >/dev/null 2>&1 || true
        as_root rm -rf -- "$tmp_dir"
        return 1
    fi
    as_root rm -rf -- "$tmp_dir"
    ok "已移除安装器管理的面板 Nginx 配置"
}

do_uninstall() {
    local remove_data="$PURGE_DATA"
    init_privilege
    validate_install_dir
    warn "即将卸载 Meridian；Nginx、Certbot、证书和备份不会删除"
    if [ "$ASSUME_YES" != "1" ]; then
        if [ "$PURGE_DATA" = "1" ]; then
            warn "已指定 --purge，数据目录将在确认卸载后删除: $DATA_DIR"
        else
            if ask_yes_no "是否同时删除数据目录 ${DATA_DIR}（数据库和密钥）？" 0; then
                remove_data=1
            fi
        fi
        ask_yes_no "确认卸载 Meridian？" 0 || { info "已取消"; return 0; }
    fi

    [ "$remove_data" = "0" ] || validate_data_dir

    remove_managed_nginx_config || fail "Nginx 配置无法安全移除，已中止卸载"
    if is_systemd && [ -f "$SERVICE_FILE" ]; then
        as_root systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        as_root systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        as_root rm -f -- "$SERVICE_FILE"
        as_root systemctl daemon-reload
    fi
    as_root rm -f -- "${INSTALL_DIR}/${BIN_NAME}" "$PREVIOUS_BIN" \
        "${INSTALL_DIR}/${BIN_NAME}.new" "${INSTALL_DIR}/${BIN_NAME}.rollback"

    if [ "$remove_data" = "1" ]; then
        as_root rm -rf -- "$DATA_DIR"
        if id "$SERVICE_USER" >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1; then
            as_root userdel "$SERVICE_USER" 2>/dev/null || true
        fi
        ok "数据目录已删除；备份目录仍保留: $BACKUP_DIR"
    else
        info "数据目录已保留: $DATA_DIR"
    fi
    ok "Meridian 已卸载"
}

usage() {
    cat <<'USAGE'
Meridian 一键安装工具

用法:
  install.sh install [--domain example.com] [--email EMAIL] [--no-domain] [-y]
      首次安装最新版本；已安装时只补充或重新配置管理面板域名。
  install.sh update [-y]
      更新到最新 Release，自动备份、健康检查并在失败时回滚。
  install.sh password
      隐藏输入并修改唯一管理员密码，同时轮换 JWT 密钥。
  install.sh uninstall [-y] [--purge]
      卸载程序；默认保留数据与备份，--purge 才删除数据。
  install.sh help
      显示本帮助。

选项:
  --domain DOMAIN  仅为管理面板配置 HTTPS 域名，固定代理到 127.0.0.1:9090（或 PORT）
  --email EMAIL    Certbot 证书邮箱，可留空
  --no-domain      不配置或取消安装器管理的面板域名
  -y, --yes        非交互确认；安装未指定域名时保留现有配置，首次安装则使用 IP
  --purge          卸载时删除数据目录；不会删除备份、Nginx、Certbot 或证书

不带参数运行时进入四项菜单。
USAGE
}

main_menu() {
    local current choice
    current=$(get_current_version)
    printf '\n%s\n' "Meridian 一键安装工具"
    printf '  当前版本: %s\n\n' "${current:-未安装}"
    printf '  1) 安装\n'
    printf '  2) 更新到最新版\n'
    printf '  3) 修改管理员密码\n'
    printf '  4) 卸载\n'
    printf '  0) 退出\n\n'
    read -r -p "请选择 [0-4]: " choice
    case "$choice" in
        1) do_install ;;
        2) do_update ;;
        3) do_password ;;
        4) do_uninstall ;;
        0) exit 0 ;;
        *) fail "无效选项" ;;
    esac
}

run_cli() {
    local action="${1:-menu}"
    [ "$#" -eq 0 ] || shift
    case "$action" in -h|--help) action="help" ;; esac

    while [ "$#" -gt 0 ]; do
        case "$1" in
            -y|--yes) ASSUME_YES=1 ;;
            --purge)
                [ "$action" = "uninstall" ] || fail "--purge 仅用于 uninstall"
                PURGE_DATA=1
                ;;
            --domain)
                [ "$action" = "install" ] || fail "--domain 仅用于 install"
                [ "$#" -ge 2 ] || fail "--domain 需要一个域名"
                [ "$DOMAIN_MODE" = "ask" ] || fail "域名选项不能重复"
                REQUESTED_DOMAIN=$(normalize_domain "$2")
                valid_domain "$REQUESTED_DOMAIN" || fail "域名格式无效"
                DOMAIN_MODE="configure"
                shift
                ;;
            --email)
                [ "$action" = "install" ] || fail "--email 仅用于 install"
                [ "$#" -ge 2 ] || fail "--email 需要一个邮箱；留空时请省略该选项"
                CERTBOT_EMAIL="$2"
                valid_certbot_email "$CERTBOT_EMAIL" || fail "证书邮箱格式无效"
                shift
                ;;
            --no-domain)
                [ "$action" = "install" ] || fail "--no-domain 仅用于 install"
                [ "$DOMAIN_MODE" = "ask" ] || fail "域名选项不能重复"
                DOMAIN_MODE="disable"
                ;;
            -h|--help) action="help" ;;
            *) fail "未知参数: $1" ;;
        esac
        shift
    done

    [ -z "$CERTBOT_EMAIL" ] || [ "$DOMAIN_MODE" = "configure" ] \
        || fail "--email 必须与 --domain 一起使用"
    case "$action" in
        install) do_install ;;
        update) do_update ;;
        password) do_password ;;
        uninstall) do_uninstall ;;
        help) usage ;;
        menu) main_menu ;;
        *) fail "未知操作: $action（仅支持 install、update、password、uninstall、help）" ;;
    esac
}

if [[ "${BASH_SOURCE[0]-}" == "$0" || -z "${BASH_SOURCE[0]-}" ]]; then
    # curl | bash consumes standard input while Bash reads the script. Keep the
    # complete interactive flow attached to the controlling terminal instead.
    if [ ! -t 0 ] && { : </dev/tty; } 2>/dev/null; then
        run_cli "$@" </dev/tty
    else
        run_cli "$@"
    fi
fi
