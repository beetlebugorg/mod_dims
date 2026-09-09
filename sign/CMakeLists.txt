# The signing rules, as a library every client can check itself against.
#
# It links libcrypto. A caller outside the module builds it without APR and
# without an httpd development package.
#
# One object library compiles the source once. The archive and the shared
# object are built from those objects, so the two hold the same code. The
# module links the archive, so libmod_dims.so gains no run time dependency.

add_library(moddims_sign_objects OBJECT src/sign.c src/eurl.c)

set_target_properties(moddims_sign_objects PROPERTIES
    POSITION_INDEPENDENT_CODE ON)

target_include_directories(moddims_sign_objects PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")

target_link_libraries(moddims_sign_objects PUBLIC PkgConfig::CRYPTO)

dims_set_warnings(moddims_sign_objects)
dims_set_hardening(moddims_sign_objects)
dims_set_sanitizers(moddims_sign_objects)

add_library(moddims_sign STATIC $<TARGET_OBJECTS:moddims_sign_objects>)
add_library(moddims_sign_shared SHARED $<TARGET_OBJECTS:moddims_sign_objects>)

set_target_properties(moddims_sign_shared PROPERTIES
    OUTPUT_NAME "moddims_sign"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR})

foreach(target moddims_sign moddims_sign_shared)
    target_include_directories(${target} PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>")
    target_link_libraries(${target} PUBLIC PkgConfig::CRYPTO)
    dims_set_hardening(${target})
    dims_set_sanitizers(${target})
endforeach()

# The command. It signs a URL, prints the message behind one, and compares the
# signature a URL holds against the one the key produces. The module logs
# "Key mismatch" without the digests. This prints both.

add_executable(dims-sign src/dims_sign_cli.c)

target_include_directories(dims-sign PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(dims-sign PRIVATE moddims_sign)

dims_set_warnings(dims-sign)
dims_set_hardening(dims-sign)
dims_set_sanitizers(dims-sign)

# -- Install
#
# A caller outside the module builds against this:
#
#   cc app.c $(pkg-config --cflags --libs dims-sign)
#
# dims_sign_internal.h is not installed. It offers the /dims4/ message, which
# holds the client secret.

configure_file(dims-sign.pc.in "${CMAKE_CURRENT_BINARY_DIR}/dims-sign.pc" @ONLY)

install(FILES include/dims_sign.h
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/dims")
install(TARGETS moddims_sign moddims_sign_shared
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(TARGETS dims-sign
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/dims-sign.pc"
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
