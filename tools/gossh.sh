#!/bin/sh
# Builds tools/gossh (Go's x/crypto/ssh as the other side) offline from the
# module cache and runs it with these arguments; see tools/gossh/main.go.
#
#	tools/gossh.sh server 2223 host_key authorized_keys
#	tools/gossh.sh client 2222 "$USER" ~/.ssh/id_ed25519 "$(cat host_key.pub)" uname
set -e
dir=$(cd "$(dirname "$0")/gossh" && pwd)
bin=${TMPDIR:-/tmp}/gossh.$(id -u)
(cd "$dir" && GOFLAGS=-mod=mod GOPROXY=off GOSUMDB=off go build -o "$bin" .)
exec "$bin" "$@"
