#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
go_bin="${ARGUS_GO_BIN:-$(command -v go)}"
temporal_bin="${ARGUS_TEMPORAL_BIN:-}"
if [[ ! -x "$go_bin" || "$("$go_bin" version)" != *"go1.26.10 "* || ! -x "$temporal_bin" ]]; then
  echo 'Go 1.26.10 and ARGUS_TEMPORAL_BIN (Temporal CLI 1.10.0) are required.' >&2
  exit 2
fi
temporal_sha256="6968c86c97d91d4b49e19c0c9b0842bfb5eb2d356f22b989006d1e09164eab5b"
if [[ "$(/usr/bin/sha256sum -- "$temporal_bin" | /usr/bin/cut -d ' ' -f1)" != "$temporal_sha256" ]]; then
  echo 'Temporal CLI digest does not match the pinned 1.10.0 binary.' >&2
  exit 2
fi
if [[ "$(id -u)" == 0 ]]; then
  echo 'The synthetic worker refuses root execution.' >&2
  exit 2
fi
work="$(mktemp -d /tmp/argus-temporal-verify-XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
cache="${ARGUS_GOCACHE:-$work/cache}"
mkdir -p -- "$cache"

# Bring up loopback only in a private network namespace, then drop all
# capabilities before starting the temporary server and synthetic worker.
unshare --user --map-current-user --net --keep-caps -- /bin/bash -euo pipefail -c '
  /usr/sbin/ip link set lo up
  exec setpriv --nnp --bounding-set=-all --inh-caps=-all --ambient-caps=-all \
    /usr/bin/env -i PATH=/usr/bin:/bin HOME="$1" TMPDIR="$1" GOCACHE="$2" GOMODCACHE="$1/modcache" \
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 ARGUS_REQUIRE_SANDBOX=1 \
    ARGUS_REQUIRE_TEMPORAL=1 ARGUS_TEMPORAL_BIN="$3" \
    /bin/bash -euo pipefail -c '\''cd "$1"; exec "$2" test -mod=vendor -p 1 -count=1 -tags temporal_integration -run TestTemporalDevServerRestartsWithPendingWorkflow -v ./adapters/temporal'\'' _ "$4" "$5"
' _ "$work" "$cache" "$temporal_bin" "$root" "$go_bin"
