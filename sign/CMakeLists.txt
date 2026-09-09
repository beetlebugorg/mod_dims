# The signing rules, as a library every client can check itself against.
#
# It links libcrypto. A caller outside the module builds it without APR and
# without an httpd development package.
#
# One object library compiles the source once. The archive and the shared
# object are built from those objects, so the two hold the same code. The
# module links the archive, so libmod_dims.so gains no run time dependency.

add_library(moddims_sign_objects OBJECT src/sign.c)

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
