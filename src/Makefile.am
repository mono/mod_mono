CLEANFILES = .libs/libmod_mono.so *~

EXTRA_DIST = ApacheApplicationHost.cs \
             IApplicationHost.cs \
	     Request.cs \
	     makedll.mak \
	     ApacheWorkerRequest.cs \
	     MonoWorkerRequest.cs

libmod_mono_la_SOURCES = mod_mono.c 
libmod_mono_la_LIBADD = $(MONO_LIBS)

INCLUDES=$(MONO_CFLAGS)

lib_LTLIBRARIES = libmod_mono.la


make_so:
	@if test ! -L libmod_mono.so ; then ln -s .libs/libmod_mono.so . ; fi

install:
	$(INSTALL) -m 644 .libs/libmod_mono.so $(LIBEXECDIR)/mod_mono.so
