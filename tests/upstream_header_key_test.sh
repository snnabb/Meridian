#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
TEST_ROOT=$(mktemp -d)
trap 'rm -rf -- "$TEST_ROOT"' EXIT

export MERIDIAN_DATA_DIR="${TEST_ROOT}/data"
mkdir -p "$MERIDIAN_DATA_DIR"

# shellcheck disable=SC1091
source "${REPO_ROOT}/install.sh"

as_root() { command "$@"; }
is_systemd() { return 1; }
install_env_file() {
    cp "$1" "$(env_file_path)"
    chmod 0600 "$(env_file_path)"
}

work_dir="${TEST_ROOT}/work"
mkdir -p "$work_dir"
valid_key=$(printf 'a%.0s' {1..64})
printf 'JWT_SECRET=test\nUPSTREAM_HEADER_KEY=%s\nPORT=9090\n' "$valid_key" > "${MERIDIAN_DATA_DIR}/.env"

ensure_upstream_header_key "$work_dir"
[ "$(read_env_value UPSTREAM_HEADER_KEY)" = "$valid_key" ] || {
    echo 'FAIL: valid UPSTREAM_HEADER_KEY changed' >&2
    exit 1
}

printf 'JWT_SECRET=test\nUPSTREAM_HEADER_KEY=\nPORT=9090\n' > "${MERIDIAN_DATA_DIR}/.env"
ensure_upstream_header_key "$work_dir"
repaired_key=$(read_env_value UPSTREAM_HEADER_KEY)
[ "${#repaired_key}" -ge 32 ] || {
    echo 'FAIL: empty UPSTREAM_HEADER_KEY was not repaired' >&2
    exit 1
}

printf 'JWT_SECRET=test\nUPSTREAM_HEADER_KEY=too-short\nPORT=9090\n' > "${MERIDIAN_DATA_DIR}/.env"
before=$(sha256_file "${MERIDIAN_DATA_DIR}/.env")
if (ensure_upstream_header_key "$work_dir") >/dev/null 2>&1; then
    echo 'FAIL: short UPSTREAM_HEADER_KEY was accepted' >&2
    exit 1
fi
[ "$(sha256_file "${MERIDIAN_DATA_DIR}/.env")" = "$before" ] || {
    echo 'FAIL: rejected short key changed .env' >&2
    exit 1
}

printf 'JWT_SECRET=test\nUPSTREAM_HEADER_KEY=%s  \nPORT=9090\n' "$valid_key" > "${MERIDIAN_DATA_DIR}/.env"
before=$(sha256_file "${MERIDIAN_DATA_DIR}/.env")
if (ensure_upstream_header_key "$work_dir") >/dev/null 2>&1; then
    echo 'FAIL: whitespace-containing UPSTREAM_HEADER_KEY was accepted' >&2
    exit 1
fi
[ "$(sha256_file "${MERIDIAN_DATA_DIR}/.env")" = "$before" ] || {
    echo 'FAIL: rejected whitespace-containing key changed .env' >&2
    exit 1
}

printf 'JWT_SECRET=test\nUPSTREAM_HEADER_KEY=%s\nUPSTREAM_HEADER_KEY=%s\nPORT=9090\n' "$valid_key" "$valid_key" > "${MERIDIAN_DATA_DIR}/.env"
before=$(sha256_file "${MERIDIAN_DATA_DIR}/.env")
if (ensure_upstream_header_key "$work_dir") >/dev/null 2>&1; then
    echo 'FAIL: duplicate UPSTREAM_HEADER_KEY was accepted' >&2
    exit 1
fi
[ "$(sha256_file "${MERIDIAN_DATA_DIR}/.env")" = "$before" ] || {
    echo 'FAIL: rejected duplicate key changed .env' >&2
    exit 1
}

echo 'upstream header key tests passed'
