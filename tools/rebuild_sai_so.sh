#!/bin/bash
# rebuild_sai_so.sh -- lightweight libsai.so iteration loop (edit SAI source -> rebuild .so -> deploy to DUT syncd)
#
# Background: after editing SAI you don't need a full SONiC .deb build (the dpkg-buildpackage layer brings a
# pile of pitfalls: dh build-stamp skipping compilation, wildcard-archive not rebuilding new files, etc.).
# libsai.so itself is a link product of `make all` (output/<plat>/bin/libsai.so.1.0), generated before deb packaging.
# This script: run `make all` directly in the slave container (incremental; first full build ~1hr, then editing one .c takes just minutes)
# -> grab the .so -> docker cp into syncd -> restart swss. Bypasses deb entirely.
#
# Usage:
#   tools/rebuild_sai_so.sh build      # only build the .so (no deploy)
#   tools/rebuild_sai_so.sh deploy     # only deploy the already-built .so to the DUT
#   tools/rebuild_sai_so.sh all        # build + deploy (default)
#   tools/rebuild_sai_so.sh verify <symbol or string>  # check that libsai.so on the device contains a given string
set -euo pipefail

# ---- Paths and parameters (fixed for this environment, editable) ----
BUILDIMAGE=${BUILDIMAGE:-/build/sonic-buildimage}
SAI_REL=platform/vendor-x/vendor-x-sai/vendor-x-sai-odp
SAI_SRC="$BUILDIMAGE/$SAI_REL"
PLAT=x86-xgsall-deb
KVER=${KVER:-6.1.0-29-2}                 # DUT kernel version KVERSION_SHORT
ARCH=amd64
SO_REL="output/$PLAT/bin/libsai.so.1.0"
SO_HOST="$SAI_SRC/$SO_REL"
HERE="$(cd "$(dirname "$0")" && pwd)"
DUTSSH="python3 $HERE/dutssh.py"
SYNCD_LIB=/usr/lib/libsai.so.1.0

slave_img() { docker images | awk '/sonic-slave-bookworm-SONiC/{print $3; exit}'; }

do_build() {
  local IMG; IMG="$(slave_img)"
  [ -n "$IMG" ] || { echo "ERROR: cannot find sonic-slave-bookworm-SONiC image"; exit 1; }
  echo "=== [build] make all inside container $IMG (incremental libsai.so build) ==="
  docker run --rm -v "$BUILDIMAGE":/sonic -w "/sonic/$SAI_REL" "$IMG" bash -c '
    set -e
    KVER="'"$KVER"'"; ARCH="'"$ARCH"'"; PLAT="'"$PLAT"'"
    # 1) Install DUT kernel headers (needed for the KERNEL_SRC check; libsai.so itself doesn'"'"'t use kernel headers, but the top-level make validates it)
    if [ ! -d /usr/src/linux-headers-$KVER-common ]; then
      dpkg -i /sonic/target/debs/bookworm/linux-headers-$KVER-common_*.deb \
              /sonic/target/debs/bookworm/linux-headers-$KVER-$ARCH'"'"'_'"'"'*.deb 2>/dev/null \
        || echo "WARN: kernel-header deb install had warnings (continuing)"
    fi
    # 2) Same symlinks as vendor-x_SAI_SETUP (common <- arch generated/config + module.lds)
    if [ -d /usr/src/linux-headers-$KVER-common ] && [ ! -L /usr/src/linux-headers-$KVER-common/include/generated ]; then
      ln -sf /usr/src/linux-headers-$KVER-$ARCH/include/generated      /usr/src/linux-headers-$KVER-common/include/generated || true
      ln -sf /usr/src/linux-headers-$KVER-$ARCH/include/config         /usr/src/linux-headers-$KVER-common/include/config || true
      cp -n /usr/src/linux-headers-$KVER-$ARCH/arch/x86/include/generated/* \
            /usr/src/linux-headers-$KVER-common/arch/x86/include/generated/ 2>/dev/null || true
    fi
    # 3) Compile (incremental; first full build including the SDK ~1hr, then editing one .c only recompiles + relinks ~minutes)
    export KERNEL_SRC=/usr/src/linux-headers-$KVER-common
    export L7_TARGETOS_VERSION=$KVER SAI_PLATFORM=$PLAT SAI_SRV6_SUPPORT=0 SAI_TELEMETRY_SUPPORT=1
    make all SAI_PLATFORM=$PLAT DEFAULT_SAI_PROCURE_METHOD=build
  '
  [ -f "$SO_HOST" ] || { echo "ERROR: $SO_REL was not generated"; exit 1; }
  echo "=== [build] OK: $(ls -la "$SO_HOST" | awk '{print $5" bytes"}') ==="
}

do_deploy() {
  [ -f "$SO_HOST" ] || { echo "ERROR: $SO_REL does not exist, build first"; exit 1; }
  echo "=== [deploy] push .so to DUT /tmp ==="
  $DUTSSH --put "$SO_HOST" /tmp/libsai.so.1.0.new
  echo "=== [deploy] back up the original lib + docker cp into syncd + restart swss ==="
  $DUTSSH --sudo '
    docker exec syncd test -f '"$SYNCD_LIB"'.orig.bak || docker exec syncd cp '"$SYNCD_LIB"' '"$SYNCD_LIB"'.orig.bak
    docker cp /tmp/libsai.so.1.0.new syncd:'"$SYNCD_LIB"'
    systemctl restart swss
  '
  echo "=== [deploy] wait for syncd/swss to come up ==="
  $DUTSSH --sudo '
    for i in $(seq 1 24); do
      st=$(docker inspect -f "{{.State.Status}}" syncd 2>/dev/null)
      n=$(sonic-db-cli ASIC_DB KEYS "ASIC_STATE:SAI_OBJECT_TYPE_HOSTIF_TRAP_GROUP:*" 2>/dev/null | wc -l)
      crash=$(docker logs syncd 2>&1 | grep -ac "entered FATAL state\|symbol lookup error")
      [ "$crash" -gt 0 ] && { echo "FATAL: syncd crashed (see docker logs syncd)"; exit 1; }
      [ "$n" -ge 6 ] && { echo "OK: syncd=$st trap_group=$n (attempt ${i})"; exit 0; }
      sleep 5
    done
    echo "WARN: wait timed out, manually check docker ps / docker logs syncd"'
}

do_rollback() {
  echo "=== [rollback] restore the original lib + restart ==="
  $DUTSSH --sudo 'docker exec syncd cp '"$SYNCD_LIB"'.orig.bak '"$SYNCD_LIB"' && systemctl restart swss && echo rollback done'
}

do_verify() {
  local s="${1:?usage: verify <string>}"
  $DUTSSH --sudo 'docker exec syncd grep -ac "'"$s"'" '"$SYNCD_LIB"' | xargs echo "hits:"'
}

case "${1:-all}" in
  build)    do_build ;;
  deploy)   do_deploy ;;
  all)      do_build; do_deploy ;;
  rollback) do_rollback ;;
  verify)   do_verify "${2:-}";;
  *) echo "usage: $0 {build|deploy|all|rollback|verify <string>}"; exit 1 ;;
esac
