cmake_minimum_required(VERSION 3.13)

include(FetchContent)

FetchContent_Declare(
    Corrosion
    GIT_REPOSITORY https://github.com/corrosion-rs/corrosion.git
    GIT_TAG v0.3.2 # Optionally specify a commit hash, version tag or branch here
)
# Set any global configuration variables such as `Rust_TOOLCHAIN` before this line!
FetchContent_MakeAvailable(Corrosion)

corrosion_import_crate(MANIFEST_PATH quiche/Cargo.toml)
#quiche
execute_process(COMMAND git submodule init
                WORKING_DIRECTORY .)

set(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)
SET(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include_directories(include)

#set(quiche-dir deps/quiche )

 
project(DTPoverQuic
        VERSION 1.0.0.1
        DESCRIPTION "dtp layer over quiche"
        LANGUAGES C )


find_package(Threads REQUIRED)
find_package(PkgConfig REQUIRED)


 

#find_package(OpenSSL REQUIRED)
#message(STATUS "root: ${OPENSSL_ROOT_DIR}")
#message(STATUS "OpenSSL_VERSION: ${OPENSSL_VERSION}")
#message(STATUS "OpenSSL_INCLUDE_DIR: ${OPENSSL_INCLUDE_DIR}")
#message(STATUS "OpenSSL_LIBRARIES: ${OPENSSL_LIBRARIES}")
#option(BUILD_SHARED_LIBS "Build using shared libraries" ON)

add_library(dtplayer-core
    lib/dtp_assemb.c
    lib/dtp_scheduler.c
    lib/dtp_tc.c
    lib/dtplayer.c
)
#?
target_link_libraries(dtplayer-core quiche)
target_include_directories(dtplayer-core PUBLIC include)
set_target_properties(dtplayer-core
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS YES)
target_compile_options(dtplayer-core PRIVATE
    $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>: -Wpedantic -Wextra -Wall>
    $<$<C_COMPILER_ID:MSVC>: >)


 
add_executable(dtplayer-examples examples/server.c examples/client.c)
target_include_directories(dtplayer-examples
    PUBLIC
        include
    PUBLIC
        lib
)


target_link_libraries(dtplayer-examples
    quiche
    dtplayer-core
    Threads::Threads
)
set_target_properties(dtplayer-examples
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS YES)
target_compile_options(dtplayer-examples PRIVATE
    $<$<OR:$<C_COMPILER_ID:Clang>,$<C_COMPILER_ID:GNU>>: -Wpedantic -Wextra -Wall>
    $<$<C_COMPILER_ID:MSVC>: >)

 


#
# Adds clangformat as target that formats all source files
#
# get all project files for formatting
file(GLOB_RECURSE CLANG_FORMAT_SOURCE_FILES *.c *.h)
 