CLEANFILES = .libs/libmod_mono.so .libs/libmod_mono_old.so *~

EXTRA_DIST = ApacheApplicationHost.cs \
             IApplicationHost.cs \
	     Request.cs \
	     makedll.mak \
	     ApacheWorkerRequest.cs \
	     MonoWorkerRequest.cs

EXTRA_libmod_mono_old_la_SOURCES = mod_mono_old.c

if BUILD_OLD_MODULE
lib_LTLIBRARIES = libmod_mono.la libmod_mono_old.la
libmod_mono_old_la_SOURCES = $(EXTRA_libmod_mono_old_la_SOURCES)
else
lib_LTLIBRARIES = libmod_mono.la
libmod_mono_old_la_SOURCES =
endif

libmod_mono_la_SOURCES = mod_mono.c
libmod_mono_old_la_LIBADD = $(MONO_LIBS)

INCLUDES = $(MONO_CFLAGS)


install: $(lib_LTLIBRARIES)
if APACHE2
	$(APXS) -i -a -n mono libmod_mono.la
if BUILD_OLD_MODULE
	$(APXS) -i -a -n mono_old libmod_mono_old.la
endif
else
	$(APXS) -i -a -n mono .libs/libmod_mono.so
if BUILD_OLD_MODULE
	$(APXS) -i -a -n mono_old .libs/libmod_mono_old.so
endif
endif

