cmake_minimum_required(VERSION 3.18)

find_package(OpenSSL REQUIRED)

add_library(auth SHARED
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
    ${OPENSSL_LIBRARIES}
    PRIVATE
    snodec::nayuki-qrcodegen
)

target_include_directories(auth PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/..>"
    "$<BUILD_INTERFACE:${OPENSSL_INCLUDE_DIRS}>"
    "$<INSTALL_INTERFACE:include/snode.c>"
)

add_library(snodec::auth ALIAS auth)

set_target_properties(
    auth
    PROPERTIES VERSION ${SNode.C_VERSION}
               SOVERSION ${SNODEC_SOVERSION}
               OUTPUT_NAME snodec-net-auth
)

install(TARGETS auth EXPORT snodec_net-auth_Targets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}/snode.c/net/auth COMPONENT net-auth
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/snode.c/net/auth COMPONENT net-auth
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT net-auth
)

install(EXPORT snodec_net-auth_Targets
    FILE snodec_net-auth_Targets.cmake
    NAMESPACE snodec::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/snodec
    COMPONENT net-auth
)

# Public headers consumed by relying parties (e.g. mqttsuite) must be installed
# into include/snode.c/auth so that #include "auth/<Header>.h" resolves against
# the staged snode.c include tree.
install(
    FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/AuthMiddleware.h
        ${CMAKE_CURRENT_SOURCE_DIR}/FederatedLoginProvider.h
        ${CMAKE_CURRENT_SOURCE_DIR}/JwtAuthMiddleware.h
        ${CMAKE_CURRENT_SOURCE_DIR}/JwtSigner.h
        ${CMAKE_CURRENT_SOURCE_DIR}/JwtVerifier.h
        ${CMAKE_CURRENT_SOURCE_DIR}/MqttSuiteAuthIntegration.h
        ${CMAKE_CURRENT_SOURCE_DIR}/OAuth2CallbackHandler.h
        ${CMAKE_CURRENT_SOURCE_DIR}/PasswordHasher.h
        ${CMAKE_CURRENT_SOURCE_DIR}/QrCodeGenerator.h
        ${CMAKE_CURRENT_SOURCE_DIR}/RateLimiter.h
        ${CMAKE_CURRENT_SOURCE_DIR}/SecretEncryptor.h
        ${CMAKE_CURRENT_SOURCE_DIR}/Totp.h
        ${CMAKE_CURRENT_SOURCE_DIR}/UserContext.h
    DESTINATION include/snode.c/auth
    COMPONENT net-auth
)
