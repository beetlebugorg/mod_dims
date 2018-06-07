AC_PREREQ(2.60)
AC_INIT(mod_dims, 3.3.13, [jeremy.collins@beetlebug.org])
AM_INIT_AUTOMAKE([no-define])
AC_CONFIG_SRCDIR([src/mod_dims.c])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LIBTOOL

# Check for ImageMagic
PKG_CHECK_MODULES(MagickCore, MagickCore)
PKG_CHECK_MODULES(MagickWand, MagickWand)
PKG_CHECK_MODULES(libcurl, libcurl)

AP_VERSION=2.2.4
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

AC_CHECK_LIB(curl, curl_global_init,, [AC_MSG_ERROR(curl not found.)])
AC_CHECK_HEADER(curl/curl.h)

# Checks for header files.
AC_CHECK_HEADERS([stdlib.h sys/time.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset sqrt strstr])

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT

