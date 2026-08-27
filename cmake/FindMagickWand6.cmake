# Finds ImageMagick 6 through pkg-config.
#
# Distributions name the file differently: MagickWand-6.Q16, MagickWand-im6,
# or plain MagickWand. Try each until one answers, and refuse version 7,
# because the source includes <wand/magick-wand.h>, which version 7 removed.
# PR 6 moves to version 7.
#
# Defines the imported targets Dims::MagickWand and Dims::MagickCore.

find_package(PkgConfig REQUIRED)

function(_dims_find_magick component out_prefix)
    foreach(candidate
            "${component}-6.Q16HDRI"
            "${component}-6.Q16"
            "${component}-6.Q8"
            "${component}-im6.q16"
            "${component}-im6"
            "${component}")
        pkg_check_modules(${out_prefix} QUIET IMPORTED_TARGET "${candidate}")
        if(${out_prefix}_FOUND)
            if(${out_prefix}_VERSION VERSION_GREATER_EQUAL 7.0)
                # Keep looking. A plain name often points at version 7.
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
find_package_handle_standard_args(MagickWand6
    REQUIRED_VARS DIMS_MAGICKWAND_FOUND DIMS_MAGICKCORE_FOUND
    VERSION_VAR DIMS_MAGICKWAND_VERSION
    FAIL_MESSAGE
        "ImageMagick 6 development files were not found. mod_dims does not build against version 7 yet.")
