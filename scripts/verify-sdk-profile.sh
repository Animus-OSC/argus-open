#!/usr/bin/env bash
# Explicit real-project acceptance; no source fetch, installation or Cloud access.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
go_bin="${ARGUS_GO_BIN:-}"
sdk_repo="${ARGUS_PROFILE_SDK_REPO:-}"
if [[ "$go_bin" != /* || ! -x "$go_bin" || "$("$go_bin" version)" != *"go1.26.10 "* || "$sdk_repo" != /* || ! -d "$sdk_repo/.git/objects" ]]; then
  echo 'Absolute ARGUS_GO_BIN (Go1.26.10) and ARGUS_PROFILE_SDK_REPO (prepared ordinary clone) are required.' >&2
  exit 2
fi
if [[ "$(id -u)" == 0 ]]; then
  echo 'The SDK profile refuses root execution.' >&2
  exit 2
fi
work="$(mktemp -d /tmp/argus-sdk-acceptance-XXXXXXXX)"
trap 'rm -rf -- "$work"' EXIT
mkdir -p -- "$work/cache" "$work/modcache"
/usr/bin/unshare --user --map-current-user --net -- \
  /usr/bin/env -i PATH=/usr/bin:/bin HOME="$work" TMPDIR="$work" GOCACHE="$work/cache" GOMODCACHE="$work/modcache" \
  GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOMAXPROCS=2 ARGUS_REQUIRE_SANDBOX=1 ARGUS_PROFILE_SDK_REPO="$sdk_repo" \
  /bin/bash -euo pipefail -c 'cd "$1"; "$2" test -mod=vendor -tags profile_integration -p 2 -count=1 -v -run "^TestSDKProfileIntegration$" ./internal/profile' \
  _ "$root" "$go_bin" | /usr/bin/tee "$work/profile.log"
/usr/bin/grep -F -- '--- PASS: TestSDKProfileIntegration ' "$work/profile.log" >/dev/null
if /usr/bin/grep -F -- '--- SKIP:' "$work/profile.log" >/dev/null; then
  echo 'Required SDK profile acceptance skipped.' >&2
  exit 1
fi
echo 'Pinned SDK profile integration acceptance passed.'