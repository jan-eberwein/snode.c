cmake_minimum_required(VERSION 3.18)

find_package(OpenSSL REQUIRED)

add_library(auth STATIC
    JwtVerifier.cpp
    JwtSigner.cpp
    UserContext.cpp
    AuthMiddleware.cpp
    Totp.cpp
    QrCodeGenerator.cpp
)

target_link_libraries(auth PUBLIC
    http-server-express
    snodec::logger
    snodec::utils
    snodec::nayuki-qrcodegen
    ${OPENSSL_LIBRARIES}
)

target_include_directories(auth PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
    "$<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIRS}>"
    "$<INSTALL_INTERFACE:include/snode.c>"
)
