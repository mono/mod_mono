CLEANFILES = .libs/libmod_mono.so .libs/libmod_mono_old.so *~

EXTRA_DIST = ApacheApplicationHost.cs \
             IApplicationHost.cs \
	     Request.cs \
	     makedll.mak \
	     ApacheWorkerRequest.cs \
	     MonoWorkerRequest.cs \
	     mod_mono_old.c

#/usr/sbin/apxs -c -I../include -I. -D HAVE_CONFIG_H mod_mono.c

#if BUILD_OLD_MODULE
#lib_LTLIBRARIES = libmod_mono.la libmod_mono_old.la
#libmod_mono_old_la_SOURCES = $(EXTRA_libmod_mono_old_la_SOURCES)
#else
lib_LTLIBRARIES = libmod_mono.la
#libmod_mono_old_la_SOURCES =
#endif

libmod_mono_la_SOURCES = mod_mono.c mod_mono.h
libmod_mono_la_LDFLAGS = -module

#libmod_mono_old_la_LIBADD = $(MONO_LIBS)
#libmod_mono_old_la_LDFLAGS = -module

INCLUDES = $(MONO_CFLAGS)


install: $(lib_LTLIBRARIES)
	$(mkinstalldirs) "$(DESTDIR)$(APXS_LIBEXECDIR)"
if APACHE2
	$(APXS) -S LIBEXECDIR="$(DESTDIR)$(APXS_LIBEXECDIR)" -S PREFIX="$(prefix)" -i -n mono libmod_mono.la
#if BUILD_OLD_MODULE
#	$(APXS) -S PREFIX="$(prefix)" -i -a -n mono_old libmod_mono_old.la
#endif
else
	$(APXS) -S LIBEXECDIR="$(DESTDIR)$(APXS_LIBEXECDIR)" -S PREFIX="$(prefix)" -i -n mono .libs/libmod_mono.so
#if BUILD_OLD_MODULE
#	$(APXS) -S PREFIX="$(prefix)" -i -a -n mono_old .libs/libmod_mono_old.so
#endif
endif

