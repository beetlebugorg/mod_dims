lib_LTLIBRARIES = libmod_dims.la

libmod_dims_la_SOURCES = mod_dims.c mod_dims_ops.c smartcrop.c mod_dims.h
libmod_dims_la_LDFLAGS = -module -avoid-version
libmod_dims_la_CFLAGS = -D_LARGEFILE64_SOURCE

install:
	$(APXS) -i -a -n dims libmod_dims.la
