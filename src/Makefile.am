CLEANFILES = .libs/libmod_mono.so .libs/libmod_mono_old.so *~

lib_LTLIBRARIES = mod_mono.la
mod_mono_la_SOURCES = mod_mono.c mod_mono.h mono-io-portability.c mono-io-portability.h glib_compat.h glib_compat.c
mod_mono_la_LDFLAGS = -module
mod_mono_la_DEPENDENCIES = ../include/mod_mono_config.h
#/usr/sbin/apxs -c -I../include -I. -D HAVE_CONFIG_H mod_mono.c
mod_mono_la_CFLAGS = -Wall -DDFLT_MONO_CONFIG_DIR=\"$(DFLT_MONO_CONFIG_DIR)\"

install: $(lib_LTLIBRARIES)
	$(mkinstalldirs) "$(DESTDIR)$(APXS_LIBEXECDIR)"
	$(APXS) -S LIBEXECDIR="$(DESTDIR)$(APXS_LIBEXECDIR)" -i -n mono mod_mono.la

