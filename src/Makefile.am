CLEANFILES = .libs/libmod_mono.so *~

EXTRA_DIST = ModMono.cs

libmod_mono_la_SOURCES = mod_mono.c 
libmod_mono_la_LIBADD = $(MONO_LIBS)

lib_LTLIBRARIES = libmod_mono.la


make_so:
	@if test ! -L libmod_mono.so ; then ln -s .libs/libmod_mono.so . ; fi


