# Finds ImageMagick 7 through pkg-config.
#
# Distributions name the file after the quantum depth, so try each in turn.
# Version 6 is refused: the module includes <MagickWand/MagickWand.h>, which
# only version 7 provides.
#
# Defines the imported targets Dims::MagickWand and Dims::MagickCore.

find_package(PkgConfig REQUIRED)

function(_dims_find_magick component out_prefix)
    foreach(candidate
            "${component}-7.Q16HDRI"
            "${component}-7.Q16"
            "${component}-7.Q8"
            "${component}")
        pkg_check_modules(${out_prefix} QUIET IMPORTED_TARGET "${candidate}")
        if(${out_prefix}_FOUND)
            if(${out_prefix}_VERSION VERSION_LESS 7.0)
                # A plain name often points at version 6. Keep looking.
                unset(${out_prefix}_FOUND CACHE)
                continue()
            endif()
            set(${out_prefix}_FOUND TRUE PARENT_SCOPE)
            set(${out_prefix}_VERSION "${${out_prefix}_VERSION}" PARENT_SCOPE)
            set(${out_prefix}_MODULE "${candidate}" PARENT_SCOPE)
            return()
        endif()
    endforeach()

    set(${out_prefix}_FOUND FALSE PARENT_SCOPE)
endfunction()

_dims_find_magick(MagickWand DIMS_MAGICKWAND)
_dims_find_magick(MagickCore DIMS_MAGICKCORE)

if(DIMS_MAGICKWAND_FOUND AND DIMS_MAGICKCORE_FOUND)
    add_library(Dims::MagickWand ALIAS PkgConfig::DIMS_MAGICKWAND)
    add_library(Dims::MagickCore ALIAS PkgConfig::DIMS_MAGICKCORE)
endif()

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(MagickWand7
    REQUIRED_VARS DIMS_MAGICKWAND_FOUND DIMS_MAGICKCORE_FOUND
    VERSION_VAR DIMS_MAGICKWAND_VERSION
    FAIL_MESSAGE
        "ImageMagick 7 development files were not found. mod_dims no longer builds against version 6.")
