#ifndef __MONO_IO_PORTABILITY_H
#define __MONO_IO_PORTABILITY_H

#include "mod_mono.h"
#include "glib_compat.h"

enum {
        PORTABILITY_NONE        = 0x00,
        PORTABILITY_UNKNOWN     = 0x01,
        PORTABILITY_DRIVE       = 0x02,
        PORTABILITY_CASE        = 0x04,
	PORTABILITY_MAX         = 0x07
};

void mono_portability_helpers_init (int *portability_level, char *env);
gchar *mono_portability_find_file (int portability_level, const gchar *pathname, gboolean last_exists);

#endif
