# The warning and hardening flags every target shares.
#
# The old build set neither. Four findings in specs/code-review.md are things
# the compiler reports as soon as these are on: H10, M15, M20, and Q13.
#
# PR 4 fixes what these report and then turns on -Werror.

option(DIMS_WERROR "Treat warnings as errors" OFF)

function(dims_set_warnings target)
    target_compile_options(${target} PRIVATE
        -Wall
        -Wextra
        -Wstrict-prototypes
        -Wwrite-strings
        -Wformat-security
        # The module's callbacks take arguments the httpd and libcurl
        # signatures require and the body does not read.
        -Wno-unused-parameter)

    if(DIMS_WERROR)
        target_compile_options(${target} PRIVATE -Werror)
    endif()
endfunction()

function(dims_set_hardening target)
    target_compile_options(${target} PRIVATE
        -fstack-protector-strong
        -fno-strict-aliasing)

    # _FORTIFY_SOURCE needs an optimizing build. Setting it without one is a
    # warning on every file.
    target_compile_definitions(${target} PRIVATE
        $<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=2>)

    if(NOT APPLE)
        target_link_options(${target} PRIVATE
            "LINKER:-z,relro"
            "LINKER:-z,now")
    endif()
endfunction()
