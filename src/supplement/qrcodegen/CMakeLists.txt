add_library(nayuki-qrcodegen STATIC qrcodegen.cpp qrcodegen.hpp)
add_library(snodec::nayuki-qrcodegen ALIAS nayuki-qrcodegen)

target_include_directories(
    nayuki-qrcodegen PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
                            "$<INSTALL_INTERFACE:include/snode.c/supplement/qrcodegen>"
)

target_compile_features(nayuki-qrcodegen PUBLIC cxx_std_17)
