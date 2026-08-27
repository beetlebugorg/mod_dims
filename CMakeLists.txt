# mod_dims, an Apache httpd module that resizes, crops, and reformats images.
#
#   cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
#   cmake --build build
#   ctest --test-dir build -L http
#
# The module installs to the directory apxs reports, so an existing
# LoadModule line keeps working.

cmake_minimum_required(VERSION 3.16)

project(mod_dims
    VERSION 3.3.31
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

# ImageMagick 6 names its pkg-config file after the quantum depth. Version 7
# is not usable yet: the source includes <wand/magick-wand.h>, which only
# version 6 provides. PR 6 moves to version 7.
find_package(MagickWand6 REQUIRED)
# -- The module

add_library(mod_dims MODULE
    src/mod_dims.c
    src/mod_dims_ops.c)

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

# -- Install
#
# CMake's own rules, so DESTDIR works and packaging can use this. The old
# build called "apxs -i -a", which appended a LoadModule line to the running
# server's httpd.conf. A build step must not edit an installed configuration.

install(TARGETS mod_dims LIBRARY DESTINATION "${APXS_LIBEXEC_DIR}")
install(FILES conf/mod_dims.conf.example
    DESTINATION "${CMAKE_INSTALL_SYSCONFDIR}/mod_dims"
    RENAME mod_dims.conf.example)

# -- Tests

if(BUILD_TESTING)
    add_subdirectory(test)
endif()

message(STATUS "mod_dims ${PROJECT_VERSION}")
message(STATUS "  apxs          ${APXS_EXECUTABLE}")
message(STATUS "  httpd headers ${APXS_INCLUDE_DIR}")
message(STATUS "  module dir    ${APXS_LIBEXEC_DIR}")
message(STATUS "  ImageMagick   ${DIMS_MAGICKWAND_VERSION} (${DIMS_MAGICKWAND_MODULE})")
