# CMake Toolchain File for OpenWRT (MediaTek Filogic / Cortex-A53)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(SDK_ROOT "/build_root/openwrt-sdk-24.10.2-mediatek-filogic_gcc-13.3.0_musl.Linux-x86_64")
set(TOOLCHAIN_DIR "${SDK_ROOT}/staging_dir/toolchain-aarch64_cortex-a53_gcc-13.3.0_musl")
set(TARGET_DIR "${SDK_ROOT}/staging_dir/target-aarch64_cortex-a53_musl")

# Compilers
set(CMAKE_C_COMPILER "${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-gcc")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-g++")
set(CMAKE_STRIP "${TOOLCHAIN_DIR}/bin/aarch64-openwrt-linux-strip")

# Flags
set(CMAKE_C_FLAGS "-Os -pipe -mcpu=cortex-a53 -fno-caller-saves -fno-plt -Wformat -Werror=format-security -fstack-protector -D_FORTIFY_SOURCE=1 -Wl,-z,now -Wl,-z,relro")
set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

# Search paths
set(CMAKE_FIND_ROOT_PATH "${TARGET_DIR}" "${TOOLCHAIN_DIR}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# SNode.C specific: Skip building tests and examples to save time
set(SNODEC_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SNODEC_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(SNODEC_SSO_MFA ON CACHE BOOL "" FORCE)
