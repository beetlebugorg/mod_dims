# Asserts every shipped configuration loads the module by the name the build
# produces. Rule 4 of the compatibility contract in specs/plan.md.

set(EXPECTED "modules/libmod_dims.so")

set(CONFIGS
    "${DIMS_SOURCE_DIR}/conf/mod_dims.conf.example"
    "${DIMS_SOURCE_DIR}/test/conf/dims-test.conf"
    "${DIMS_SOURCE_DIR}/docker/dims.conf"
    "${DIMS_SOURCE_DIR}/examples/dims.conf")

foreach(config IN LISTS CONFIGS)
    if(NOT EXISTS "${config}")
        continue()
    endif()

    file(STRINGS "${config}" lines REGEX "LoadModule +dims_module")
    if(NOT lines)
        message(FATAL_ERROR "${config} does not load the module at all")
    endif()

    foreach(line IN LISTS lines)
        if(NOT line MATCHES "${EXPECTED}")
            message(FATAL_ERROR
                "${config} loads the wrong file.\n"
                "  want: ${EXPECTED}\n"
                "  got:  ${line}\n"
                "Rule 4 of the compatibility contract: a deployed httpd.conf "
                "names libmod_dims.so and must keep working.")
        endif()
    endforeach()
endforeach()

message(STATUS "every shipped configuration loads ${EXPECTED}")
