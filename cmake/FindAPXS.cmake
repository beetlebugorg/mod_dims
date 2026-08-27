# Finds apxs, the Apache httpd extension tool, and reads the paths it reports.
#
# Sets:
#   APXS_FOUND
#   APXS_EXECUTABLE   the tool
#   APXS_INCLUDE_DIR  the httpd headers
#   APXS_LIBEXEC_DIR  where a module installs
#   APXS_SYSCONF_DIR  where the server configuration lives
#
# Set APXS_EXECUTABLE on the command line to choose a specific httpd:
#   cmake -B build -DAPXS_EXECUTABLE=/usr/local/apache2/bin/apxs

find_program(APXS_EXECUTABLE
    NAMES apxs apxs2
    HINTS
        /usr/local/apache2/bin
        /usr/sbin
        /usr/bin
    DOC "The Apache httpd extension tool")

# apxs -q writes the value with no newline on some builds and with one on
# others. Strip whitespace either way.
function(_apxs_query variable name)
    execute_process(
        COMMAND "${APXS_EXECUTABLE}" -q "${name}"
        OUTPUT_VARIABLE value
        ERROR_QUIET
        RESULT_VARIABLE status)
    if(NOT status EQUAL 0)
        set(${variable} "" PARENT_SCOPE)
        return()
    endif()
    string(STRIP "${value}" value)
    set(${variable} "${value}" PARENT_SCOPE)
endfunction()

if(APXS_EXECUTABLE)
    _apxs_query(APXS_INCLUDE_DIR INCLUDEDIR)
    _apxs_query(APXS_LIBEXEC_DIR LIBEXECDIR)
    _apxs_query(APXS_SYSCONF_DIR SYSCONFDIR)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(APXS
    REQUIRED_VARS APXS_EXECUTABLE APXS_INCLUDE_DIR APXS_LIBEXEC_DIR
    FAIL_MESSAGE
        "apxs was not found. Install the Apache httpd development package, or pass -DAPXS_EXECUTABLE=/path/to/apxs.")

mark_as_advanced(APXS_EXECUTABLE APXS_INCLUDE_DIR APXS_LIBEXEC_DIR APXS_SYSCONF_DIR)
