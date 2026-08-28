# The test harness. One binary, registered with CTest one case at a time so a
# failure names the case.
#
# The HTTP layer needs the services from test/compose.yaml. It carries the
# label "http" so a developer can select or skip it:
#
#   ctest --test-dir build -L http
#   ctest --test-dir build -LE http

add_executable(dims_test
    http/main.c
    http/test_adjustments.c
    http/test_allowlist.c
    http/test_cache_headers.c
    http/test_crop.c
    http/test_errors.c
    http/test_origin_status.c
    http/test_output.c
    http/test_resize.c
    http/test_rotate.c
    http/test_signing.c
    http/test_sources.c
    http/test_no_error_image.c
    http/test_source_limit.c
    http/test_status.c
    http/test_thumbnail.c
    http/test_watermark.c
    lib/common.c
    lib/environment.c
    lib/golden.c
    lib/imagesize.c
    lib/request.c
    lib/signing.c
    lib/test.c)

target_link_libraries(dims_test PRIVATE
    PkgConfig::CURL
    PkgConfig::CRYPTO)

target_compile_definitions(dims_test PRIVATE _GNU_SOURCE)

dims_set_warnings(dims_test)
dims_set_hardening(dims_test)
dims_set_sanitizers(dims_test)

# Ask the binary which cases it carries and register each one. The list comes
# from the binary itself, so a case cannot be added to a file and silently
# never run.
add_test(NAME dims_test_list COMMAND dims_test --list)
set_tests_properties(dims_test_list PROPERTIES LABELS "http")

file(GLOB DIMS_TEST_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/http/test_*.c")
foreach(source IN LISTS DIMS_TEST_SOURCES)
    file(STRINGS "${source}" entries REGEX "^    \\{ \"Test[A-Za-z0-9]+\",")
    foreach(entry IN LISTS entries)
        string(REGEX MATCH "\"(Test[A-Za-z0-9]+)\"" _ "${entry}")
        set(case "${CMAKE_MATCH_1}")
        add_test(NAME ${case} COMMAND dims_test --run=${case})
        set_tests_properties(${case} PROPERTIES LABELS "http")
    endforeach()
endforeach()

# Rule 4 of the compatibility contract: the module name and the LoadModule line
# do not change. Every deployed httpd.conf names libmod_dims.so, so a rename is
# a silent break that only shows up when a server fails to start.
#
# This case does not carry the http label: it needs no services.
add_test(NAME ModuleKeepsItsName
    COMMAND ${CMAKE_COMMAND}
        -E compare_files
        "$<TARGET_FILE:mod_dims>"
        "$<TARGET_FILE_DIR:mod_dims>/libmod_dims.so")
set_tests_properties(ModuleKeepsItsName PROPERTIES LABELS "contract")

# The shipped configurations must name the same file.
add_test(NAME ShippedConfigLoadsTheModule
    COMMAND ${CMAKE_COMMAND}
        -DDIMS_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckLoadModule.cmake)
set_tests_properties(ShippedConfigLoadsTheModule PROPERTIES LABELS "contract")

# -- The in-process layer
#
# dims_unit_test links the operation sources and calls each one directly.
# It needs no httpd and no network: stub_httpd.c supplies the three symbols
# the operations reach for, and the overlay comes from the fixture directory.
#
# These cases carry the label "unit", so they run without the compose
# services:
#
#   ctest --test-dir build -L unit

add_executable(dims_unit_test
    unit/main.c
    unit/fixture.c
    unit/operation.c
    unit/stub_httpd.c
    unit/test_adjustments.c
    unit/test_crop.c
    unit/test_output.c
    unit/test_resize.c
    unit/test_rotate.c
    unit/test_encryption.c
    unit/test_netguard.c
    unit/test_param.c
    unit/test_url.c
    unit/test_thumbnail.c
    unit/test_watermark.c
    lib/environment.c
    lib/golden.c
    lib/test.c
    ${CMAKE_SOURCE_DIR}/src/encryption.c
    ${CMAKE_SOURCE_DIR}/src/netguard.c
    ${CMAKE_SOURCE_DIR}/src/url.c
    ${CMAKE_SOURCE_DIR}/src/operations/autolevel.c
    ${CMAKE_SOURCE_DIR}/src/operations/brightness.c
    ${CMAKE_SOURCE_DIR}/src/operations/crop.c
    ${CMAKE_SOURCE_DIR}/src/operations/flip-flop.c
    ${CMAKE_SOURCE_DIR}/src/operations/format.c
    ${CMAKE_SOURCE_DIR}/src/operations/geometry.c
    ${CMAKE_SOURCE_DIR}/src/operations/grayscale.c
    ${CMAKE_SOURCE_DIR}/src/operations/invert.c
    ${CMAKE_SOURCE_DIR}/src/operations/legacy.c
    ${CMAKE_SOURCE_DIR}/src/operations/quality.c
    ${CMAKE_SOURCE_DIR}/src/operations/resize.c
    ${CMAKE_SOURCE_DIR}/src/operations/rotate.c
    ${CMAKE_SOURCE_DIR}/src/operations/sepia.c
    ${CMAKE_SOURCE_DIR}/src/operations/sharpen.c
    ${CMAKE_SOURCE_DIR}/src/operations/strip.c
    ${CMAKE_SOURCE_DIR}/src/operations/thumbnail.c
    ${CMAKE_SOURCE_DIR}/src/operations/watermark.c)

target_include_directories(dims_unit_test PRIVATE
    ${APXS_INCLUDE_DIR}
    ${CMAKE_SOURCE_DIR}/src)

target_link_libraries(dims_unit_test PRIVATE
    PkgConfig::APR
    PkgConfig::APRUTIL
    PkgConfig::CURL
    PkgConfig::CRYPTO
    Dims::MagickWand
    Dims::MagickCore)

target_compile_definitions(dims_unit_test PRIVATE _GNU_SOURCE)

dims_set_warnings(dims_unit_test)
dims_set_hardening(dims_unit_test)
dims_set_sanitizers(dims_unit_test)

file(GLOB DIMS_UNIT_SOURCES CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/unit/test_*.c")
foreach(source IN LISTS DIMS_UNIT_SOURCES)
    file(STRINGS "${source}" entries REGEX "^    \\{ \"Test[A-Za-z0-9]+\",")
    foreach(entry IN LISTS entries)
        string(REGEX MATCH "\"(Test[A-Za-z0-9]+)\"" _ "${entry}")
        set(case "${CMAKE_MATCH_1}")
        add_test(NAME unit.${case} COMMAND dims_unit_test --run=${case})
        set_tests_properties(unit.${case} PROPERTIES LABELS "unit")
    endforeach()
endforeach()

# -- The module loads
#
# The request cases prove the module works, but only once httpd is already
# serving. When the module fails to load, httpd never starts, and every one of
# them reports the same thing: the service did not answer. That is the least
# useful failure the suite can produce.
#
# The shared memory defect found during the ImageMagick 7 port was exactly
# this shape. The module was correct, the configuration was correct, and httpd
# refused to start. These cases name that directly.
#
# They need httpd, not the compose services, so they carry the contract label.

add_test(NAME ModuleLoadsIntoHttpd
    COMMAND ${CMAKE_COMMAND}
        -DHTTPD=/usr/local/apache2/bin/httpd
        -DMODE=loads
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckModuleLoads.cmake)
set_tests_properties(ModuleLoadsIntoHttpd PROPERTIES LABELS "contract")

add_test(NAME ExampleConfigIsValid
    COMMAND ${CMAKE_COMMAND}
        -DHTTPD=/usr/local/apache2/bin/httpd
        -DMODE=example
        -DDIMS_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DDIMS_MODULE=$<TARGET_FILE:mod_dims>
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/CheckModuleLoads.cmake)
set_tests_properties(ExampleConfigIsValid PROPERTIES LABELS "contract")
