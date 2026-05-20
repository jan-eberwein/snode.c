#!/bin/bash
# SNode.C High-Performance OpenWrt Build Script
# This script uses a Docker volume for persistent SDK storage to avoid slow 20min builds.

set -e

# Configuration
OPENWRT_VERSION="24.10.2"
TARGET="mediatek"
SUBTARGET="filogic"
SDK_TAR="openwrt-sdk-${OPENWRT_VERSION}-${TARGET}-${SUBTARGET}_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${TARGET}/${SUBTARGET}/${SDK_TAR}"
SDK_DIR="openwrt-sdk-${OPENWRT_VERSION}-${TARGET}-${SUBTARGET}_gcc-13.3.0_musl.Linux-x86_64"
VOLUME_NAME="snodec_sdk_volume"

echo "==== SNode.C Persistent OpenWrt Build ===="

# Ensure the build-openwrt/packages directory exists on host for artifact collection
mkdir -p build-openwrt/packages

# Run the build inside the persistent Docker volume
docker run --rm \
    --platform linux/amd64 \
    -v "${VOLUME_NAME}:/build_root" \
    -v "$(pwd):/snodec_source:ro" \
    -v "$(pwd)/build-openwrt:/snodec_build" \
    debian:bookworm /bin/bash -c "
    set -e
    echo 'Installing build dependencies (if missing)...'
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential curl wget git subversion file unzip python3 python3-distutils \
        zlib1g-dev libncurses5-dev gawk flex gettext libssl-dev xz-utils zstd time rsync

    cd /build_root
    
    if [ ! -d \"${SDK_DIR}\" ]; then
        echo 'First time setup: Downloading and extracting OpenWrt SDK...'
        wget -qO- \"${SDK_URL}\" | tar --zstd -xf -
    else
        echo 'Reusing existing SDK from Docker Volume...'
    fi
    
    cd \"${SDK_DIR}\"
    
    # 1. Setup/Update the feeds
    # We need base and packages for dependencies!
    if [ ! -f feeds.conf ]; then
        cp feeds.conf.default feeds.conf
        if ! grep -q 'snodec' feeds.conf; then
            echo 'src-link snodec /snodec_source/openwrt_feed' >> feeds.conf
        fi
    fi
    
    echo 'Updating all feeds (Base, Packages, SnodeC)...'
    ./scripts/feeds update base packages snodec
    ./scripts/feeds install -p snodec -f snode.c
    ./scripts/feeds install nlohmannjson easyloggingpp libopenssl libmariadb libmagic
    
    # 2. Configure (only once or on changes)
    if [ ! -f .config ]; then
        echo 'Initializing minimal SDK config...'
        # Start with a clean slate to avoid building the whole world
        rm -f .config
        echo 'CONFIG_PACKAGE_snode.c=y' >> .config
        echo 'CONFIG_PACKAGE_snode.c-apps=y' >> .config
        echo 'CONFIG_PACKAGE_snode.c-full=y' >> .config
        
        # Disable LTO to prevent emulation crashes
        echo 'CONFIG_USE_LTO=n' >> .config
        
        # Fix ncurses cchar_t error by enabling wide char support
        echo 'CONFIG_PACKAGE_libncurses=y' >> .config
        echo 'CONFIG_PACKAGE_libncursesw=y' >> .config
        
        # Disable recommended/default packages to speed up and stabilize build
        echo 'CONFIG_ALL_KMODS=n' >> .config
        echo 'CONFIG_ALL_NONSHARED=n' >> .config
        
        make defconfig
    else
        echo 'Using existing .config...'
        # Ensure wide char is enabled even in existing config
        if ! grep -q 'CONFIG_PACKAGE_libncursesw=y' .config; then
            echo 'CONFIG_PACKAGE_libncursesw=y' >> .config
            make defconfig
        fi
    fi
    
    echo '==== Starting Compilation of snode.c ===='
    # Build only our package. This is incremental and FAST.
    # Parallel jobs logic
    NPROC=$(grep -c ^processor /proc/cpuinfo 2>/dev/null || echo 4)
    make package/snode.c/compile -j$NPROC V=s
    
    echo '==== Collecting Build Artifacts ===='
    mkdir -p /snodec_build/packages
    find bin/packages -name "*snode.c*.ipk" -exec cp -v {} /snodec_build/packages/ \;
    
    echo 'Build Complete!'
"

echo "==== Artifacts available in ./build-openwrt/packages/ ===="
ls -lh build-openwrt/packages/
