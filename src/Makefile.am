MKINSTALLDIRS=@top_builddir@mkinstalldirs
CLEANFILES = .libs/libmod_mono.so .libs/libmod_mono_old.so *~

EXTRA_DIST = ApacheApplicationHost.cs \
             IApplicationHost.cs \
	     Request.cs \
	     makedll.mak \
	     ApacheWorkerRequest.cs \
	     MonoWorkerRequest.cs

libmod_mono_la_SOURCES = mod_mono.c

libmod_mono_old_la_SOURCES = mod_mono_old.c
libmod_mono_old_la_LIBADD = $(MONO_LIBS)

INCLUDES=$(MONO_CFLAGS)
lib_LTLIBRARIES = libmod_mono.la libmod_mono_old.la

make_so:
	@if test ! -L mod_mono.so ; then ln -s .libs/libmod_mono.so mod_mono.so ; fi
	@if test ! -L mod_mono_old.so ; then ln -s .libs/libmod_mono_old.so mod_mono_old.so ; fi

install:
	$(MKINSTALLDIRS) $(DESTDIR)$(LIBEXECDIR)
	$(INSTALL) -m 644 .libs/libmod_mono.so $(DESTDIR)$(LIBEXECDIR)/mod_mono.so
	$(INSTALL) -m 644 .libs/libmod_mono_old.so $(DESTDIR)$(LIBEXECDIR)/mod_mono_old.so

