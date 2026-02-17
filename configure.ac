AC_PREREQ(2.60)
AC_INIT(mod_dims, 3.3.31, [jeremy.collins@beetlebug.org])
AM_INIT_AUTOMAKE([no-define])
AC_CONFIG_SRCDIR([src/mod_dims.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Check for ImageMagick (support both IM6 and IM7 pkg-config names)
PKG_CHECK_MODULES([MagickCore], [MagickCore], [], [
  PKG_CHECK_MODULES([MagickCore], [MagickCore-7.Q16HDRI], [], [
    PKG_CHECK_MODULES([MagickCore], [MagickCore-7.Q16], [], [
      PKG_CHECK_MODULES([MagickCore], [MagickCore-7.Q8HDRI], [], [
        PKG_CHECK_MODULES([MagickCore], [MagickCore-7.Q8], [], [
          PKG_CHECK_MODULES([MagickCore], [MagickCore-6.Q16HDRI], [], [
            PKG_CHECK_MODULES([MagickCore], [MagickCore-6.Q16], [], [
              PKG_CHECK_MODULES([MagickCore], [MagickCore-6.Q8HDRI], [], [
                PKG_CHECK_MODULES([MagickCore], [MagickCore-6.Q8], [], [
                  AC_MSG_ERROR([*** Could not find a supported MagickCore pkg-config package!])
                ])
              ])
            ])
          ])
        ])
      ])
    ])
  ])
])

PKG_CHECK_MODULES([MagickWand], [MagickWand], [], [
  PKG_CHECK_MODULES([MagickWand], [MagickWand-7.Q16HDRI], [], [
    PKG_CHECK_MODULES([MagickWand], [MagickWand-7.Q16], [], [
      PKG_CHECK_MODULES([MagickWand], [MagickWand-7.Q8HDRI], [], [
        PKG_CHECK_MODULES([MagickWand], [MagickWand-7.Q8], [], [
          PKG_CHECK_MODULES([MagickWand], [MagickWand-6.Q16HDRI], [], [
            PKG_CHECK_MODULES([MagickWand], [MagickWand-6.Q16], [], [
              PKG_CHECK_MODULES([MagickWand], [MagickWand-6.Q8HDRI], [], [
                PKG_CHECK_MODULES([MagickWand], [MagickWand-6.Q8], [], [
                  AC_MSG_ERROR([*** Could not find a supported MagickWand pkg-config package!])
                ])
              ])
            ])
          ])
        ])
      ])
    ])
  ])
])
PKG_CHECK_MODULES(libcurl, libcurl)

AC_CONFIG_MACRO_DIRS([m4])
AC_CONFIG_HEADERS([src/config.h])

AP_VERSION=2.4.0
AP_CHECK_APACHE([$AP_VERSION], [
  LIBTOOL="`$APR_CONFIG --apr-libtool`"
  AC_SUBST([LIBTOOL])

  MODULE_CFLAGS="$AP_CFLAGS"
  AC_SUBST([MODULE_CFLAGS])

  MODULE_LDFLAGS="`$APR_CONFIG --link-libtool` `$APU_CONFIG --link-libtool`"
  AC_SUBST([MODULE_LDFLAGS])

  BIN_LDFLAGS="`$APR_CONFIG --link-libtool` `$APU_CONFIG --link-libtool` `$APR_CONFIG --ldflags --libs` `$APU_CONFIG --ldflags --libs`"
  AC_SUBST([BIN_LDFLAGS])

  prefix="$AP_PREFIX"
], AC_MSG_ERROR([*** Apache version $AP_VERSION not found!]))

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset sqrt strstr])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
