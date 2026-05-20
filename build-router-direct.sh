#!/bin/bash
# SNode.C Direct SDK Cross-Compilation Script
# This script completely bypasses the broken OpenWrt Feed system and uses the toolchain directly.
set -e

# Configuration
OPENWRT_VERSION="24.10.2"
TARGET_ARCH="aarch64_cortex-a53"
SDK_DIR="/build_root/openwrt-sdk-${OPENWRT_VERSION}-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64"
STAGING_DIR="${SDK_DIR}/staging_dir/target-${TARGET_ARCH}_musl"

# URLs for binary dependencies
BASE_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/packages/${TARGET_ARCH}/base"
PKG_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/packages/${TARGET_ARCH}/packages"

echo "==== SNode.C Direct Cross-Compilation ===="

docker run --rm \
    --platform linux/amd64 \
    -v "snodec_sdk_volume:/build_root" \
    -v "$(pwd):/snodec_source" \
    debian:bookworm /bin/bash -c "
    set -e
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential cmake git curl wget unzip tar zstd xz-utils gawk
    
    # Force gawk as the default awk (needed by OpenWrt scan.awk)
    update-alternatives --set awk /usr/bin/gawk
    mkdir -p /tmp/deps && cd /tmp/deps
    
    # List of binary packages needed for linking
    pkgs=(
        \"libopenssl\" 
        \"libmariadb\" 
        \"libmagic\"
        \"zlib\"
        \"libstdcpp\"
    )
    
    # We also need the developer versions (headers) if available in the IPK
    # In OpenWrt, -dev packages are often not separate, headers are in the main .ipk for some, or not present.
    # Actually, it is better to use the ones from the FEEDS directory if we can.
    
    # Wait! If we use the SDK's staging_dir, it should already have some headers.
    # But because our build failed, it might be empty.
    
    echo 'Checking if dependencies are already in staging_dir...'
    if [ ! -f \"${STAGING_DIR}/usr/include/openssl/ssl.h\" ]; then
         echo 'Downloading OpenSSL binary package...'
         # Find the exact filename (it has a hash/version)
         wget -q -r -l1 -nd -A \"libopenssl*.ipk\" ${BASE_URL}/
         for f in libopenssl*.ipk; do tar -xOf \"\$f\" data.tar.gz | tar -xz -C ${STAGING_DIR}/; done
         
         # Also need the headers! headers are often in a separate dev package or the SDK include dir.
    fi

    # TRICK: Instead of downloading IPKs, we will use the 'make package/X/install' command
    # for ONLY the essential dependencies. This is more reliable than manual extraction.
    cd ${SDK_DIR}
    echo 'Installing essential dependencies into staging_dir...'
    ./scripts/feeds update base packages
    ./scripts/feeds install libopenssl libmariadb nlohmannjson easyloggingpp libmagic
    
    # Now we only build those 5 dependencies. This is much safer than the whole universe.
    make package/libs/openssl/compile -j\$(nproc)
    make package/feeds/packages/mariadb/compile -j\$(nproc)
    make package/feeds/packages/nlohmannjson/compile -j\$(nproc)
    make package/feeds/packages/easyloggingpp/compile -j\$(nproc)
    make package/feeds/packages/file/compile -j\$(nproc)
    
    echo '==== Compiling SNode.C Directly via CMake ===='
    mkdir -p /snodec_source/build-openwrt-direct
    cd /snodec_source/build-openwrt-direct
    cmake .. -DCMAKE_TOOLCHAIN_FILE=/snodec_source/toolchain-openwrt.cmake
    make -j\$(nproc)
    
    echo 'Build Complete! Binaries are in build-openwrt-direct/'
"
