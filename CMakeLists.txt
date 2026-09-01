# mod_dims, an Apache httpd module that resizes, crops, and reformats images.
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#   ctest --test-dir build -L http
#
# The module installs to the directory apxs reports, so an existing
# LoadModule line keeps working.

cmake_minimum_required(VERSION 3.16)

# The version comes from the git tag, so a tag push is the whole bump. The
# module reports it and the release names it. -DDIMS_VERSION wins for a
# container build, which excludes .git, the same way -DDIMS_COMMIT does. A
# checkout with no tag reads the short commit, which is honest and does not fail.
if(NOT DIMS_VERSION)
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" describe --tags --always --dirty
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            OUTPUT_VARIABLE DIMS_VERSION
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
    endif()
endif()
if(NOT DIMS_VERSION)
    set(DIMS_VERSION "0.0.0-unknown")
endif()
string(REGEX REPLACE "^v" "" DIMS_VERSION "${DIMS_VERSION}")

# project() takes numeric components only, so read them from the version.
string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" DIMS_VERSION_NUMERIC "${DIMS_VERSION}")
if(NOT DIMS_VERSION_NUMERIC)
    set(DIMS_VERSION_NUMERIC "0.0.0")
endif()

project(mod_dims
    VERSION ${DIMS_VERSION_NUMERIC}
    DESCRIPTION "Dynamic image manipulation for Apache httpd"
    LANGUAGES C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

include(GNUInstallDirs)
include(CTest)
include(DimsWarnings)

# -- Dependencies

find_package(PkgConfig REQUIRED)
find_package(APXS REQUIRED)

pkg_check_modules(APR REQUIRED IMPORTED_TARGET apr-1)
pkg_check_modules(APRUTIL REQUIRED IMPORTED_TARGET apr-util-1)
pkg_check_modules(CURL REQUIRED IMPORTED_TARGET libcurl)
pkg_check_modules(CRYPTO REQUIRED IMPORTED_TARGET libcrypto)

# ImageMagick 7. Version 6 is refused: it does not provide the headers the
# module includes.
find_package(MagickWand7 REQUIRED)
# -- The module

add_library(mod_dims MODULE
    src/configuration.c
    src/curl.c
    src/encryption.c
    src/error.c
    src/handler.c
    src/netguard.c
    src/overlay_cache.c
    src/profile.c
    src/dims5.c
    src/signature.c
    src/svgguard.c
    src/url.c
    src/metrics.c
    src/metrics_report.c
    src/status.c
    src/mod_dims.c
    src/module.c
    src/operations/autolevel.c
    src/operations/brightness.c
    src/operations/crop.c
    src/operations/flip-flop.c
    src/operations/format.c
    src/operations/geometry.c
    src/operations/grayscale.c
    src/operations/invert.c
    src/operations/legacy.c
    src/operations/quality.c
    src/operations/resize.c
    src/operations/rotate.c
    src/operations/sepia.c
    src/operations/sharpen.c
    src/operations/strip.c
    src/operations/thumbnail.c
    src/operations/watermark.c)

# The artifact keeps the name the autotools build produced. Every shipped
# configuration and every deployed httpd.conf carries
# "LoadModule dims_module modules/libmod_dims.so", and rule 4 of the
# compatibility contract says that line keeps working.
#
# CMake would otherwise add its own lib prefix to a target named
# libmod_dims, so the prefix is cleared and the name given in full.
set_target_properties(mod_dims PROPERTIES
    PREFIX ""
    OUTPUT_NAME "libmod_dims")

target_include_directories(mod_dims PRIVATE
    ${APXS_INCLUDE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_link_libraries(mod_dims PRIVATE
    PkgConfig::APR
    PkgConfig::APRUTIL
    PkgConfig::CURL
    PkgConfig::CRYPTO
    Dims::MagickWand
    Dims::MagickCore)

# httpd resolves its own symbols at load time.
target_link_options(mod_dims PRIVATE "LINKER:--allow-shlib-undefined")

dims_set_warnings(mod_dims)
dims_set_hardening(mod_dims)
dims_set_sanitizers(mod_dims)

# -- Install
#
# CMake's own rules, so DESTDIR works and packaging can use this. The old
# build called "apxs -i -a", which appended a LoadModule line to the running
# server's httpd.conf. A build step must not edit an installed configuration.

# The commit this build came from, for the status page.
#
# -DDIMS_COMMIT wins, because a container build has no git history: the build
# context excludes .git, so the commit has to come in as an argument. Failing
# that, read it here. A tarball with neither reports "unknown", which is
# honest and does not fail the build.
if(NOT DIMS_COMMIT)
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_SOURCE_DIR}/.git")
        execute_process(
            COMMAND "${GIT_EXECUTABLE}" rev-parse --short HEAD
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            OUTPUT_VARIABLE DIMS_COMMIT
            OUTPUT_STRIP_TRAILING_WHITESPACE
            ERROR_QUIET)
    endif()
endif()
if(NOT DIMS_COMMIT)
    set(DIMS_COMMIT "unknown")
endif()

configure_file(src/version.h.in "${CMAKE_BINARY_DIR}/generated/version.h" @ONLY)

# Directory wide, so the test targets see it too. They compile the operations,
# which reach mod_dims.h.
include_directories("${CMAKE_BINARY_DIR}/generated")

# Where the profiles are installed, and where the module looks for them.
set(DIMS_PROFILE_DIR "${CMAKE_INSTALL_PREFIX}/share/mod_dims/profiles"
    CACHE PATH "Where the ICC colour profiles are installed")
target_compile_definitions(mod_dims PRIVATE
    DIMS_PROFILE_DIR="${DIMS_PROFILE_DIR}")

install(TARGETS mod_dims LIBRARY DESTINATION "${APXS_LIBEXEC_DIR}")
install(DIRECTORY profiles/ DESTINATION "${DIMS_PROFILE_DIR}"
    FILES_MATCHING PATTERN "*.icc")
install(FILES conf/mod_dims.conf.example
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mod_dims"
    RENAME mod_dims.conf.example)

# -- Tests

if(BUILD_TESTING)
    add_subdirectory(test)
endif()

message(STATUS "mod_dims ${DIMS_VERSION}")
message(STATUS "  apxs          ${APXS_EXECUTABLE}")
message(STATUS "  httpd headers ${APXS_INCLUDE_DIR}")
message(STATUS "  module dir    ${APXS_LIBEXEC_DIR}")
message(STATUS "  ImageMagick   ${DIMS_MAGICKWAND_VERSION} (${DIMS_MAGICKWAND_MODULE})")
