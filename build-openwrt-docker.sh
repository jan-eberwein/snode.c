#!/bin/bash
set -e

# SNode.C OpenWrt Docker Build Wrapper
# For GL.iNet GL-MT3000 (mediatek/filogic)

OPENWRT_VERSION="24.10.2"
TARGET="mediatek"
SUBTARGET="filogic"
SDK_TAR="openwrt-sdk-${OPENWRT_VERSION}-${TARGET}-${SUBTARGET}_gcc-13.3.0_musl.Linux-x86_64.tar.zst"
SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${TARGET}/${SUBTARGET}/${SDK_TAR}"
SDK_DIR="${SDK_TAR%.tar.zst}"

echo "Starting OpenWrt Cross-Compilation in Docker for ${TARGET}/${SUBTARGET}..."

# Start a Debian Docker container and build internally to keep the host clean and avoid permission errors
docker run --rm -v "$(pwd):/snodec_source:ro" -v "$(pwd)/build-openwrt:/snodec_build" debian:bookworm /bin/bash -c "
    echo 'Installing build dependencies...'
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        build-essential curl wget git subversion file unzip python3 python3-distutils \
        zlib1g-dev libncurses5-dev gawk flex gettext libssl-dev xz-utils zstd time rsync

    # Working in Docker's internal filesystem to avoid 10k host changes
    mkdir -p /build_root
    cd /build_root
    
    echo 'Downloading SDK inside container...'
    wget -qO- \"${SDK_URL}\" | tar --zstd -xf -
    cd ${SDK_DIR}
    
    # Patch the SDK
    echo 'src-git snodec https://github.com/SNodeC/OpenWRT' >> feeds.conf.default
    ./scripts/feeds update base packages snodec
    ./scripts/feeds install snode.c
    
    # We need to overlay our CURRENT local changes (from /snodec_source) 
    # instead of just using the remote github snodec feed version
    # The feed's Makefile usually points to a URI. We'll override it to the local mount.
    mkdir -p feeds/snodec/snode.c
    cp -r /snodec_source/* feeds/snodec/snode.c/

    echo 'Configuring SDK...'
    make defconfig
    
    echo 'Compiling SNode.C IPKs...'
    make package/snode.c/compile -j\$(nproc) V=s
    
    echo 'Copying IPK files to host output folder...'
    mkdir -p /snodec_build/packages
    find bin/packages -name \"*snode.c*.ipk\" -exec cp {} /snodec_build/packages/ \;
    echo 'Build successful. Check the \"build-openwrt/packages\" directory.'
"

echo "Done! The IPK packages have been built and are located in ${SDK_DIR}/bin/packages/... (mapped outside docker to this repository)."
echo "You can now SCP and OPKG Install them to the router."
