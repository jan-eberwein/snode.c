cmake_minimum_required(VERSION 3.18)

# SQLite3::SQLite3 target is provided by the parent (src/database/CMakeLists.txt)

add_library(db-sqlite STATIC
    SqliteDatabase.cpp
)

target_link_libraries(db-sqlite PUBLIC
    SQLite3::SQLite3
)

target_include_directories(db-sqlite PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/src>"
    "$<INSTALL_INTERFACE:include/snode.c>"
)

install(TARGETS db-sqlite
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT db-sqlite
)
install(FILES SqliteDatabase.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/snode.c/database/sqlite
        COMPONENT db-sqlite
)
