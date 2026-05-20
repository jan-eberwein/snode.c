#!/bin/bash
set -e

# Configuration
SDK_URL="https://downloads.openwrt.org/releases/24.10.2/targets/mediatek/filogic/openwrt-sdk-24.10.2-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
SDK_FILE="sdk.tar.zst"
PROJECT_DIR="$(pwd)"
OUTPUT_DIR="${PROJECT_DIR}/router_build_output"

echo "=== Starting Router Deployment Build ==="
mkdir -p "$OUTPUT_DIR"

# Docker Build Command
docker run --platform linux/amd64 -v "$PROJECT_DIR":/local/snode.c -v "$OUTPUT_DIR":/output debian:bookworm bash -c "
    set -e
    echo '>> Installing dependencies...'
    apt-get update -qq
    apt-get install -y -qq build-essential git gawk gettext libncurses5-dev libssl-dev python3-distutils rsync unzip zlib1g-dev file wget zstd cmake > /dev/null

    echo '>> Downloading SDK...'
    for i in {1..5}; do
        if wget -O $SDK_FILE \"$SDK_URL\"; then break; fi
        echo '>> SDK download failed. Retrying in 5s...'
        sleep 5
    done

    if [ ! -f $SDK_FILE ]; then
        echo 'Error: Failed to download SDK'
        exit 1
    fi
    
    echo '>> Extracting SDK...'
    tar --zstd -xf $SDK_FILE
    cd openwrt-sdk-*
    
    echo '>> Configuring Feeds...'
    # Use GitHub mirrors for reliability
    sed -i 's|https://git.openwrt.org/openwrt/openwrt.git|https://github.com/openwrt/openwrt.git|g' feeds.conf.default
    sed -i 's|https://git.openwrt.org/feed/packages.git|https://github.com/openwrt/packages.git|g' feeds.conf.default
    
    # Git config for stability
    git config --global http.version HTTP/1.1
    git config --global http.lowSpeedLimit 0
    git config --global http.lowSpeedTime 999999
    
    # Add SNodeC feed
    echo 'src-link snodec /local/snode.c/openwrt_feed' >> feeds.conf.default

    # Update feeds with retries
    for i in {1..5}; do
        echo '>> Updating feed base...'
        if ./scripts/feeds update base; then break; fi
        echo '>> base update failed. Retrying in 5s...'
        sleep 5
    done

    for i in {1..5}; do
        echo '>> Updating feed packages...'
        if ./scripts/feeds update packages; then break; fi
        echo '>> packages update failed. Retrying in 5s...'
        sleep 5
    done
    
    ./scripts/feeds update snodec
    ./scripts/feeds install snode.c mqttsuite

    echo '>> Configuring .config...'
    make defconfig
    # Explicitly enable the apps package
    echo "CONFIG_PACKAGE_snode.c-apps=y" >> .config
    # Refresh config to ensure dependencies are picked up
    make oldconfig

    echo '>> Preparing snode.c source...'
    # Prepare dependencies and snode.c source tree
    make package/snode.c/prepare V=s

    echo '>> Overwriting with local source...'
    # Find the build directory for snode.c (it will be in build_dir/target-*/snode.c-*)
    BUILD_DIR=\$(find build_dir/target-* -maxdepth 1 -name 'snode.c-*' -type d | head -n 1)
    
    if [ -z \"\$BUILD_DIR\" ]; then
        echo 'Error: Could not find snode.c build directory'
        exit 1
    fi
    
    echo \"Found build dir: \$BUILD_DIR\"
    # Sync src folder from local mount to build dir
    rsync -av --delete /local/snode.c/src/ \$BUILD_DIR/src/
    rsync -av --delete /local/snode.c/CMakeLists.txt \$BUILD_DIR/
    
    echo '>> Compiling snode.c...'
    # Use V=sc for maximum verbosity to catch compiler errors
    # Reduced threads to -j2 to avoid OOM/ICE under Rosetta
    make package/snode.c/compile V=sc -j2

    echo '>> Collecting IPK files...'
    PKG_DIR=bin/packages/aarch64_cortex-a53/snodec
    if [ -d \"\$PKG_DIR\" ]; then
        cp \$PKG_DIR/*.ipk /output/
        echo '>> Build Successful! IPKs copied to output.'
        ls -l /output/
    else
        echo 'Error: Package directory not found'
        exit 1
    fi
"

echo "=== Build Complete ==="
echo "Artifacts are in $OUTPUT_DIR"
