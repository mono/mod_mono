CLEANFILES = .libs/libmod_mono.so .libs/libmod_mono_unix.so *~

EXTRA_DIST = ApacheApplicationHost.cs \
             IApplicationHost.cs \
	     Request.cs \
	     makedll.mak \
	     ApacheWorkerRequest.cs \
	     MonoWorkerRequest.cs

libmod_mono_la_SOURCES = mod_mono.c
libmod_mono_la_LIBADD = $(MONO_LIBS)

libmod_mono_unix_la_SOURCES = mod_mono_unix.c

INCLUDES=$(MONO_CFLAGS)

lib_LTLIBRARIES = libmod_mono.la \
		  libmod_mono_unix.la


make_so:
	@if test ! -L mod_mono.so ; then ln -s .libs/libmod_mono.so mod_mono.so ; fi
	@if test ! -L mod_mono_unix.so ; then ln -s .libs/libmod_mono_unix.so mod_mono_unix.so ; fi

install:
	$(INSTALL) -m 644 .libs/libmod_mono.so $(LIBEXECDIR)/mod_mono.so
	$(INSTALL) -m 644 .libs/libmod_mono_unix.so $(LIBEXECDIR)/mod_mono_unix.so
