moddir = ${AP_LIBEXECDIR}
lib_LTLIBRARIES = libmod_dims.la

libmod_dims_la_SOURCES = \
	curl.c curl.h \
	configuration.c configuration.h \
	encryption.c encryption.h \
	handler.c handler.h \
	mod_dims.c mod_dims.h \
	mod_dims_ops.c mod_dims_ops.h \
	module.c module.h \
	request.h
libmod_dims_la_LDFLAGS = -module -avoid-version $(MagickCore_LIBS) $(MagickWand_LIBS) $(libcurl_LIBS) ${MODULE_LDFLAGS}
libmod_dims_la_CFLAGS = -std=c99 -D_LARGEFILE64_SOURCE $(MagickCore_CFLAGS) $(MagickWand_CFLAGS) $(libcurl_CFLAGS) ${MODULE_CFLAGS}

install: libmod_dims.la
	$(APXS_BIN) -i -a -n dims libmod_dims.la
