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
    http/test_output.c
    http/test_resize.c
    http/test_rotate.c
    http/test_signing.c
    http/test_sources.c
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
