#!/bin/sh
set -eu

data_dir=/app/data
secrets_file="${data_dir}/.meridian-secrets"
meridian_user=meridian
meridian_group=meridian
meridian_binary=/app/meridian

fail() {
    printf 'meridian-entrypoint: %s\n' "$*" >&2
    exit 1
}

is_meridian_command=0
if [ "$#" -eq 0 ]; then
    set -- "$meridian_binary"
    is_meridian_command=1
else
    case "$1" in
        ./meridian|meridian|/app/meridian)
            shift
            set -- "$meridian_binary" "$@"
            is_meridian_command=1
            ;;
        -*|admin)
            set -- "$meridian_binary" "$@"
            is_meridian_command=1
            ;;
    esac
fi

# Explicit shell/debug commands keep normal Docker ENTRYPOINT semantics and do
# not create or change application data merely by opening a shell.
if [ "$is_meridian_command" -ne 1 ]; then
    exec "$@"
fi

generate_secret() {
    secret=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    [ "${#secret}" -eq 64 ] || fail "failed to generate a secure random secret"
    printf '%s' "$secret"
}

validate_secret() {
    name=$1
    value=$2
    [ "${#value}" -ge 32 ] || fail "$name must be at least 32 bytes"
    case "$value" in
        *[[:space:]]*) fail "$name must not contain whitespace" ;;
    esac
}

saved_jwt=
saved_upstream=
saved_dynamic=
saved_setup=
saved_credential=
if [ -e "$secrets_file" ]; then
    if [ ! -f "$secrets_file" ] || [ -L "$secrets_file" ]; then
        fail "$secrets_file must be a regular file"
    fi
    while IFS='=' read -r name value || [ -n "$name$value" ]; do
        case "$name" in
            ''|'#'*) ;;
            JWT_SECRET) saved_jwt=$value ;;
            UPSTREAM_HEADER_KEY) saved_upstream=$value ;;
            DYNAMIC_ROUTE_KEY) saved_dynamic=$value ;;
            SETUP_TOKEN) saved_setup=$value ;;
            MERIDIAN_SECRET_KEY) saved_credential=$value ;;
            *) fail "unexpected entry in $secrets_file: $name" ;;
        esac
    done < "$secrets_file"
fi

setup_generated=0
if [ -n "${JWT_SECRET:-}" ]; then jwt=$JWT_SECRET
elif [ -n "$saved_jwt" ]; then jwt=$saved_jwt
else jwt=$(generate_secret)
fi

if [ -n "${UPSTREAM_HEADER_KEY:-}" ]; then upstream=$UPSTREAM_HEADER_KEY
elif [ -n "$saved_upstream" ]; then upstream=$saved_upstream
else upstream=$(generate_secret)
fi

if [ -n "${DYNAMIC_ROUTE_KEY:-}" ]; then dynamic=$DYNAMIC_ROUTE_KEY
elif [ -n "$saved_dynamic" ]; then dynamic=$saved_dynamic
else dynamic=$(generate_secret)
fi

if [ -n "${SETUP_TOKEN:-}" ]; then setup=$SETUP_TOKEN
elif [ -n "$saved_setup" ]; then setup=$saved_setup
else
    setup=$(generate_secret)
    setup_generated=1
fi

if [ -n "${MERIDIAN_SECRET_KEY:-}" ]; then credential=$MERIDIAN_SECRET_KEY
elif [ -n "$saved_credential" ]; then credential=$saved_credential
else credential=$(generate_secret)
fi

validate_secret UPSTREAM_HEADER_KEY "$upstream"
validate_secret JWT_SECRET "$jwt"
validate_secret DYNAMIC_ROUTE_KEY "$dynamic"
validate_secret MERIDIAN_SECRET_KEY "$credential"
validate_secret SETUP_TOKEN "$setup"

[ "$jwt" != "$upstream" ] || fail "UPSTREAM_HEADER_KEY must differ from JWT_SECRET"
[ "$dynamic" != "$jwt" ] || fail "DYNAMIC_ROUTE_KEY must differ from JWT_SECRET"
[ "$dynamic" != "$upstream" ] || fail "DYNAMIC_ROUTE_KEY must differ from UPSTREAM_HEADER_KEY"
[ "$setup" != "$jwt" ] || fail "SETUP_TOKEN must differ from JWT_SECRET"
[ "$setup" != "$upstream" ] || fail "SETUP_TOKEN must differ from UPSTREAM_HEADER_KEY"
[ "$setup" != "$dynamic" ] || fail "SETUP_TOKEN must differ from DYNAMIC_ROUTE_KEY"
[ "$credential" != "$jwt" ] || fail "MERIDIAN_SECRET_KEY must differ from JWT_SECRET"
[ "$credential" != "$upstream" ] || fail "MERIDIAN_SECRET_KEY must differ from UPSTREAM_HEADER_KEY"
[ "$credential" != "$dynamic" ] || fail "MERIDIAN_SECRET_KEY must differ from DYNAMIC_ROUTE_KEY"

umask 077
mkdir -p "$data_dir"
tmp_file=$(mktemp "${secrets_file}.tmp.XXXXXX") \
    || fail "failed to create a temporary secrets file"
trap 'rm -f -- "$tmp_file"' EXIT HUP INT TERM
{
    printf '# Generated and managed by the Meridian Docker entrypoint.\n'
    printf 'JWT_SECRET=%s\n' "$jwt"
    printf 'UPSTREAM_HEADER_KEY=%s\n' "$upstream"
    printf 'DYNAMIC_ROUTE_KEY=%s\n' "$dynamic"
    printf 'MERIDIAN_SECRET_KEY=%s\n' "$credential"
    printf 'SETUP_TOKEN=%s\n' "$setup"
} > "$tmp_file"
chmod 0600 "$tmp_file"
mv -f "$tmp_file" "$secrets_file"
trap - EXIT HUP INT TERM

export "JWT_SECRET=$jwt"
export "UPSTREAM_HEADER_KEY=$upstream"
export "DYNAMIC_ROUTE_KEY=$dynamic"
export "MERIDIAN_SECRET_KEY=$credential"
export "SETUP_TOKEN=$setup"

if [ "$(id -u)" -eq 0 ]; then
    # Only the fixed application data directory is normalized. This makes a
    # fresh bind mount writable without broadening the ownership scope.
    chown -R "$meridian_user:$meridian_group" "$data_dir"
    chmod 0700 "$data_dir"
    chmod 0600 "$secrets_file"
fi

if [ "$setup_generated" -eq 1 ]; then
    printf '\nMeridian 首次初始化令牌: %s\n' "$setup"
    printf '请打开面板创建管理员；以后可用 docker compose logs meridian 查找此令牌。\n\n'
fi

if [ "$(id -u)" -eq 0 ]; then
    exec su-exec "$meridian_user:$meridian_group" "$@"
fi
exec "$@"
