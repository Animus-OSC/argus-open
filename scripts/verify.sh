#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
go_bin="${ARGUS_GO_BIN:-$(command -v go)}"
gofmt_bin="$(dirname -- "$go_bin")/gofmt"
if [[ ! -x "$go_bin" || "$("$go_bin" version)" != *"go1.26.10 "* ]]; then
  echo 'Go 1.26.10 is required for the recorded verification.' >&2
  exit 2
fi
if [[ "$(id -u)" == 0 ]]; then
  echo 'The synthetic worker refuses root execution.' >&2
  exit 2
fi
work="$(mktemp -d /tmp/argus-verify-XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
cache="${ARGUS_GOCACHE:-$work/cache}"
race="${ARGUS_RACE:-0}"
if [[ "$race" != 0 && "$race" != 1 ]]; then
  echo 'ARGUS_RACE must be 0 or 1.' >&2
  exit 2
fi
mkdir -p -- "$cache"

# A new network namespace has no egress or working loopback. Use an empty
# environment so tests do not inherit production credentials or sockets.
unshare --user --map-current-user --net -- /usr/bin/env -i \
  PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" GOCACHE="$cache" GOMODCACHE="$work/modcache" \
  GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 ARGUS_REQUIRE_SANDBOX=1 ARGUS_RACE="$race" \
  /bin/bash -euo pipefail -c '
    cd "$1"
    unformatted="$("$3" -l api cmd internal pkg adapters examples)"
    if [[ -n "$unformatted" ]]; then printf "unformatted Go files:\n%s\n" "$unformatted" >&2; exit 1; fi
    /bin/bash -n scripts/verify.sh scripts/verify-offline.sh scripts/verify-temporal.sh
    /usr/bin/python3 -B -m unittest discover -s scripts -p "test_*.py"
    "$2" test -mod=vendor -p 2 -count=1 ./...
    if [[ "$ARGUS_RACE" == 1 ]]; then "$2" test -mod=vendor -race -p 2 -count=1 ./...; fi
    "$2" vet -mod=vendor -p 2 ./...
    (cd examples/external-adapter && "$2" test -mod=mod -p 2 ./...)
  ' _ "$root" "$go_bin" "$gofmt_bin"
