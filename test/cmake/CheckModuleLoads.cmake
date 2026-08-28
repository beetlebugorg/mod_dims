# Checks that httpd accepts the module and the configuration it ships with.
#
# MODE=loads    the running configuration names the module and httpd accepts it
# MODE=example  conf/mod_dims.conf.example parses, and every directive in it
#               is one the module registers

if(MODE STREQUAL "loads")
    execute_process(
        COMMAND ${HTTPD} -M
        OUTPUT_VARIABLE modules
        ERROR_VARIABLE modules_err
        RESULT_VARIABLE status)
    if(NOT status EQUAL 0)
        message(FATAL_ERROR "httpd -M failed:\n${modules}${modules_err}")
    endif()
    if(NOT "${modules}${modules_err}" MATCHES "dims_module")
        message(FATAL_ERROR
            "httpd loaded, but dims_module is not among its modules.\n"
            "${modules}${modules_err}")
    endif()

    execute_process(
        COMMAND ${HTTPD} -t
        OUTPUT_VARIABLE check
        ERROR_VARIABLE check_err
        RESULT_VARIABLE status)
    if(NOT status EQUAL 0)
        message(FATAL_ERROR "httpd rejected its configuration:\n${check}${check_err}")
    endif()

    message(STATUS "dims_module loads and httpd accepts the configuration")

elseif(MODE STREQUAL "example")
    # The example is what an operator copies. It has been wrong before: it
    # named a module path no build has ever produced. Run httpd against it.
    set(work "${CMAKE_CURRENT_BINARY_DIR}/example-config")
    file(MAKE_DIRECTORY "${work}")

    file(READ "${DIMS_SOURCE_DIR}/conf/mod_dims.conf.example" example)

    # The example loads the module from the server root. Point that at the
    # module this build produced, so the check is about the directives rather
    # than about where a package installed things.
    string(REPLACE "modules/libmod_dims.so" "${DIMS_MODULE}" example "${example}")

    file(WRITE "${work}/httpd.conf"
        "ServerName check\n"
        "PidFile ${work}/httpd.pid\n"
        "ErrorLog ${work}/error.log\n"
        "LoadModule mpm_event_module modules/mod_mpm_event.so\n"
        "LoadModule unixd_module modules/mod_unixd.so\n"
        "LoadModule authz_core_module modules/mod_authz_core.so\n"
        "Listen 18000\n"
        "${example}")

    execute_process(
        COMMAND ${HTTPD} -t -f "${work}/httpd.conf"
        OUTPUT_VARIABLE check
        ERROR_VARIABLE check_err
        RESULT_VARIABLE status)

    if(NOT status EQUAL 0)
        message(FATAL_ERROR
            "httpd rejected conf/mod_dims.conf.example.\n"
            "An operator copying it would get the same error.\n"
            "${check}${check_err}")
    endif()

    message(STATUS "conf/mod_dims.conf.example is accepted by httpd")

else()
    message(FATAL_ERROR "MODE must be loads or example")
endif()
