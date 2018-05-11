moddir = ${AP_LIBEXECDIR}
lib_LTLIBRARIES = libmod_dims.la

libmod_dims_la_SOURCES = mod_dims.c mod_dims_ops.c mod_dims.h
libmod_dims_la_LDFLAGS = -module -avoid-version $(MagickCore_LIBS) $(MagickWand_LIBS) $(libcurl_LIBS) ${MODULE_LDFLAGS}
libmod_dims_la_CFLAGS = -std=c99 -D_LARGEFILE64_SOURCE $(MagickCore_CFLAGS) $(MagickWand_CFLAGS) $(libcurl_CFLAGS) ${MODULE_CFLAGS}

install:
	$(APXS_BIN) -i -a -n dims libmod_dims.la
