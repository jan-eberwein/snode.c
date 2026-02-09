cmake_minimum_required(VERSION 3.18)

if(NOT SNODEC_SSO_MFA)
    return()
endif()

add_executable(auth_idp IdpServer.cpp)

target_link_libraries(auth_idp PRIVATE
    auth
    http-server-express
    db-mariadb
    snodec::logger
)

target_include_directories(auth_idp PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)


# Copy keys directory to build directory
file(COPY ${CMAKE_CURRENT_SOURCE_DIR}/keys DESTINATION ${CMAKE_CURRENT_BINARY_DIR})

install(TARGETS auth_idp RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT apps)
