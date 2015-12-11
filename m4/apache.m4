dnl -------------------------------------------------------- -*- autoconf -*-
dnl Licensed to the Apache Software Foundation (ASF) under one or more
dnl contributor license agreements.  See the NOTICE file distributed with
dnl this work for additional information regarding copyright ownership.
dnl The ASF licenses this file to You under the Apache License, Version 2.0
dnl (the "License"); you may not use this file except in compliance with
dnl the License.  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl Unless required by applicable law or agreed to in writing, software
dnl distributed under the License is distributed on an "AS IS" BASIS,
dnl WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl See the License for the specific language governing permissions and
dnl limitations under the License.

dnl
dnl AP_TEST_APACHE_VERSION([MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl

AC_DEFUN([AP_TEST_APACHE_VERSION], [
  min_apache_version="$1"
  no_apache=""
  ac_save_CFLAGS="$CFLAGS"
  CFLAGS="$CFLAGS $AP_CFLAGS $APR_INCLUDES $APU_INCLUDES"
  AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "httpd.h"

#ifndef AP_SERVER_BASEREVISION
    #define AP_SERVER_BASEREVISION SERVER_BASEREVISION
#endif

char* my_strdup (char *str)
{
    char *new_str;

    if (str) {
        new_str = (char *)malloc ((strlen (str) + 1) * sizeof(char));
        strcpy (new_str, str);
    } else
        new_str = NULL;

    return new_str;
}

int main (int argc, char *argv[])
{
    int major1, minor1, micro1;
    int major2, minor2, micro2;
    char *tmp_version;

    { FILE *fp = fopen("conf.apachetest", "a"); if ( fp ) fclose(fp); }

    // TODO: Support abbreviated versions, e.g. 2.2 instead of 2.2.0
    tmp_version = my_strdup("$min_apache_version");
    if (sscanf(tmp_version, "%d.%d.%d", &major1, &minor1, &micro1) != 3) {
        printf("%s, bad version string\n", "$min_apache_version");
        exit(1);
    }
    tmp_version = my_strdup(AP_SERVER_BASEREVISION);
    if (sscanf(tmp_version, "%d.%d.%d", &major2, &minor2, &micro2) != 3) {
        printf("%s, bad version string\n", AP_SERVER_BASEREVISION);
        exit(1);
    }

    if (major2 == major1 &&
        (minor2 > minor1 ||
            (minor2 == minor1 && micro2 >= micro1))) {
        exit(0);
    } else
        exit(1);
}
  ], [], [no_apache=yes], [echo $ac_n "cross compiling; assumed OK... $ac_c"])
  CFLAGS="$ac_save_CFLAGS"

  if test "x$no_apache" = x ; then
    ifelse([$2], [], [:], [$2])
  else
    if test -f conf.apachetest; then
      :
    else
      AC_MSG_WARN([*** Could not run Apache test program, checking why...])
      CFLAGS="$CFLAGS $AP_CFLAGS $APR_INCLUDES $APU_INCLUDES"
      AC_TRY_LINK([
#include <stdio.h>
#include "httpd.h"

int main(int argc, char *argv[])
{ return 0; }
#undef main
#define main K_and_R_C_main
      ], [ return 0; ],
        [AC_MSG_ERROR([*** The test program compiled, but failed to run. Check config.log])],
        [AC_MSG_ERROR([*** The test program failed to compile or link. Check config.log])])
      CFLAGS="$ac_save_CFLAGS"
    fi
    ifelse([$3], [], :, [$3])
  fi
  rm -f conf.apachetest
])

dnl
dnl AP_CHECK_APACHE([MINIMUM-VERSION [, ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl

AC_DEFUN([AP_CHECK_APACHE], [
  AC_ARG_WITH([apxs],
    [AC_HELP_STRING([--with-apxs=PATH], [Path to apxs])],
    [apxs_prefix="$withval"],
    [apxs_prefix="/usr"])

  AC_ARG_ENABLE([apachetest],
    [AC_HELP_STRING([--disable-apachetest], [Do not try to compile and run Apache version test program])],
    [],
    [enable_apachetest=yes])

  # Find apxs
  if test -x $apxs_prefix -a ! -d $apxs_prefix; then
    APXS_BIN=$apxs_prefix
  else
    test_paths="/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/local/apache2/bin"

    if test -d $apxs_prefix; then
      test_paths="$apxs_prefix:$apxs_prefix/bin:$apxs_prefix/sbin:$test_paths"
      apxs_prefix="apxs"
    fi
    
    AC_PATH_PROG([APXS_BIN], [$apxs_prefix], [no], [$test_paths])
  fi

  if test "$APXS_BIN" = "no"; then
    AC_MSG_ERROR([*** The apxs binary installed by Apache could not be found!])
    AC_MSG_ERROR([*** Use the --with-apxs option with the full path to apxs])
  else
    # Set AP_ variables from apxs

    AP_INCLUDEDIR="`$APXS_BIN -q INCLUDEDIR 2>/dev/null`"
    AP_INCLUDES="-I$AP_INCLUDEDIR"

    AP_PREFIX="`$APXS_BIN -q prefix 2>/dev/null`"

    AP_BINDIR="`$APXS_BIN -q bindir 2>/dev/null`"
    AP_SBINDIR="`$APXS_BIN -q sbindir 2>/dev/null`"

    APXS_CFLAGS=""
    for flag in CFLAGS EXTRA_CFLAGS NOTEST_CFLAGS; do
      APXS_CFLAGS="$APXS_CFLAGS `$APXS_BIN -q $flag 2>/dev/null`"
    done

    AP_CFLAGS="$APXS_CFLAGS $AP_INCLUDES"

    AP_LIBEXECDIR=`$APXS_BIN -q LIBEXECDIR 2>/dev/null`

    # Set APR_ variables from apr-config
    APR_CONFIG="`$APXS_BIN -q APR_BINDIR 2>/dev/null`/apr-1-config"
    if test ! -x $APR_CONFIG; then
      APR_CONFIG="`$APXS_BIN -q APR_BINDIR 2>/dev/null`/apr-config"
    fi
    APR_INCLUDES=`$APR_CONFIG --includes 2>/dev/null`
    APR_VERSION=`$APR_CONFIG --version 2>/dev/null`

    # Set APU_ variables from apu-config
    APU_CONFIG="`$APXS_BIN -q APU_BINDIR 2>/dev/null`/apu-1-config"
    if test ! -x $APU_CONFIG; then
      APU_CONFIG="`$APXS_BIN -q APU_BINDIR 2>/dev/null`/apu-config"
    fi
    APU_INCLUDES=`$APU_CONFIG --includes 2>/dev/null`
    APU_VERSION=`$APU_CONFIG --version 2>/dev/null`

    min_apache_version=ifelse([$1], [], [no], [$1])
    if test "x$enable_apachetest" = "xyes" -a "$min_apache_version" != "no"; then
      AC_MSG_CHECKING([for Apache 2.0 version >= $min_apache_version])
      AP_TEST_APACHE_VERSION([$min_apache_version],
        AC_MSG_RESULT([yes])
        AP_CFLAGS="$AP_CFLAGS $APU_INCLUDES $APR_INCLUDES"
        AP_CPPFLAGS="$AP_CPPFLAGS $APU_INCLUDES $APR_INCLUDES"
        ifelse([$2], [], [], [$2]),
        AC_MSG_RESULT([no])
        ifelse([$3], [], [], [$3])
      )
    fi
    AC_SUBST(AP_INCLUDEDIR)
    AC_SUBST(AP_INCLUDES)
    AC_SUBST(AP_PREFIX)
    AC_SUBST(AP_BINDIR)
    AC_SUBST(AP_SBINDIR)
    AC_SUBST(AP_CFLAGS)
    AC_SUBST(AP_LIBEXECDIR)
    AC_SUBST(APR_CONFIG)
    AC_SUBST(APR_INCLUDES)
    AC_SUBST(APU_CONFIG)
    AC_SUBST(APU_INCLUDES)
    AC_SUBST(APXS_BIN)
    AC_SUBST(APXS_CFLAGS)
  fi
])
