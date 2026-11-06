#!/usr/bin/env bash
# Full synthetic offline verification / CI entrypoint. Requires a disposable,
# non-root Linux environment with unprivileged user/network namespaces.
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
go_bin="${ARGUS_GO_BIN:-$(command -v go)}"
if [[ ! "$go_bin" = /* || ! -x "$go_bin" || "$("$go_bin" version)" != *"go1.26.10 "* ]]; then
  echo 'An absolute ARGUS_GO_BIN for Go 1.26.10 is required.' >&2
  exit 2
fi
if [[ "$(id -u)" == 0 ]]; then
  echo 'The synthetic worker refuses root execution.' >&2
  exit 2
fi
work="$(mktemp -d /tmp/argus-full-offline-XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$work/cache" "$work/modcache"

echo '== verify.sh (including regression suite and race detector) =='
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" \
  ARGUS_GO_BIN="$go_bin" ARGUS_GOCACHE="$work/cache" ARGUS_RACE=1 \
  /bin/bash "$root/scripts/verify.sh"

echo '== parent loopback isolation probe =='
# Bring up only loopback in a new private network namespace. The test opens a
# parent listener and requires the nested worker sandbox not to reach it.
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" \
  /usr/bin/unshare --user --map-current-user --net --keep-caps -- \
  /bin/bash -euo pipefail -c '
    /usr/sbin/ip link set lo up
    exec /usr/bin/setpriv --nnp --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
      /usr/bin/env -i PATH=/usr/bin:/bin HOME="$1" TMPDIR="$1" GOCACHE="$1/cache" GOMODCACHE="$1/modcache" \
      GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 ARGUS_REQUIRE_SANDBOX=1 ARGUS_REQUIRE_LOOPBACK_ISOLATION=1 \
      /bin/bash -euo pipefail -c '\''cd "$1"; "$2" test -mod=vendor -p 2 -count=1 -v -run "^TestSandboxCannotReachParentLoopback$" ./internal/worker'\'' _ "$2" "$3"
  ' _ "$work" "$root" "$go_bin" | /usr/bin/tee "$work/loopback.log"
/usr/bin/grep -F -- '--- PASS: TestSandboxCannotReachParentLoopback ' "$work/loopback.log" >/dev/null
if /usr/bin/grep -F -- '--- SKIP:' "$work/loopback.log" >/dev/null; then
  echo 'Required loopback probe skipped.' >&2
  exit 1
fi

echo '== wall-timeout probe =='
/usr/bin/env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" \
  /usr/bin/unshare --user --map-current-user --net -- \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" GOCACHE="$work/cache" GOMODCACHE="$work/modcache" \
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 ARGUS_REQUIRE_SANDBOX=1 ARGUS_REQUIRE_WALL_TIMEOUT=1 \
    /bin/bash -euo pipefail -c 'cd "$1"; "$2" test -mod=vendor -p 2 -count=1 -v -run "^TestSandboxWallTimeoutIsUncertain$" ./internal/worker' \
    _ "$root" "$go_bin" | /usr/bin/tee "$work/wall-timeout.log"
/usr/bin/grep -F -- '--- PASS: TestSandboxWallTimeoutIsUncertain ' "$work/wall-timeout.log" >/dev/null
if /usr/bin/grep -F -- '--- SKIP:' "$work/wall-timeout.log" >/dev/null; then
  echo 'Required wall-timeout probe skipped.' >&2
  exit 1
fi

echo 'Full synthetic offline verification passed.'
