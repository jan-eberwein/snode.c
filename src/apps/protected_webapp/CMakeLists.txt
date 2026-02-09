cmake_minimum_required(VERSION 3.18)

if(NOT SNODEC_SSO_MFA)
    return()
endif()

add_executable(protected_webapp ProtectedWebApp.cpp)

target_link_libraries(protected_webapp PRIVATE
    auth
    http-server-express
    snodec::logger
)


# Copy public key from auth_idp to protected_webapp build dir
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/keys)
file(COPY ${CMAKE_SOURCE_DIR}/src/apps/auth_idp/keys/public_key.pem DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/keys)

install(TARGETS protected_webapp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT apps)
