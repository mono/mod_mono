#ifdef HAVE_CONFIG_H
#include "mod_mono_config.h"
#endif

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "mono-io-portability.h"

#include <dirent.h>

#define IS_PORTABILITY_NONE (portability_level & PORTABILITY_NONE)
#define IS_PORTABILITY_UNKNOWN (portability_level & PORTABILITY_UNKNOWN)
#define IS_PORTABILITY_DRIVE (portability_level & PORTABILITY_DRIVE)
#define IS_PORTABILITY_CASE (portability_level & PORTABILITY_CASE)
#define IS_PORTABILITY_SET (portability_level > 0)

void mono_portability_helpers_init (int *portability_level, char *env)
{
	if (!portability_level || *portability_level != PORTABILITY_UNKNOWN || !env || !*env)
		return;

	*portability_level = PORTABILITY_NONE;

	if (env != NULL) {
		/* parse the environment setting and set up some vars
		 * here
		 */
		gchar **options = g_strsplit (env, ":", 0);
		int i;

		if (options == NULL) {
			/* This shouldn't happen */
			return;
		}

		for (i = 0; options[i] != NULL; i++) {
			if (!strncasecmp (options[i], "drive", 5)) {
				*portability_level |= PORTABILITY_DRIVE;
			} else if (!strncasecmp (options[i], "case", 4)) {
				*portability_level |= PORTABILITY_CASE;
			} else if (!strncasecmp (options[i], "all", 3)) {
				*portability_level |= (PORTABILITY_DRIVE |
						       PORTABILITY_CASE);
			}
		}
	}
}

/* Returns newly allocated string, or NULL on failure */
static gchar *find_in_dir (DIR *current, const gchar *name)
{
	struct dirent *entry;

	while((entry = readdir (current)) != NULL) {
		if (!g_ascii_strcasecmp (name, entry->d_name)) {
			char *ret;

			ret = g_strdup (entry->d_name);
			closedir (current);
			return ret;
		}
	}

	closedir (current);

	return(NULL);
}

/* Returns newly-allocated string or NULL on failure */
gchar *mono_portability_find_file (int portability_level, const gchar *pathname, gboolean last_exists)
{
	gchar *new_pathname, **components, **new_components;
	int num_components = 0, component = 0;
	DIR *scanning = NULL;
	size_t len;

	if (IS_PORTABILITY_NONE) {
		return(NULL);
	}

	new_pathname = g_strdup (pathname);

	if (last_exists &&
	    access (new_pathname, F_OK) == 0) {
		return(new_pathname);
	}

	/* First turn '\' into '/' and strip any drive letters */
	g_strdelimit (new_pathname, "\\", '/');

	if (IS_PORTABILITY_DRIVE &&
	    g_ascii_isalpha (new_pathname[0]) &&
	    (new_pathname[1] == ':')) {
		int len = strlen (new_pathname);

		g_memmove (new_pathname, new_pathname+2, len - 2);
		new_pathname[len - 2] = '\0';

	}

	len = strlen (new_pathname);
	if (len > 1 && new_pathname [len - 1] == '/') {
		new_pathname [len - 1] = 0;
	}

	if (last_exists &&
	    access (new_pathname, F_OK) == 0) {
		return(new_pathname);
	}

	/* OK, have to work harder.  Take each path component in turn
	 * and do a case-insensitive directory scan for it
	 */

	if (!(IS_PORTABILITY_CASE)) {
		g_free (new_pathname);
		return(NULL);
	}

	components = g_strsplit (new_pathname, "/", 0);
	if (components == NULL) {
		/* This shouldn't happen */
		g_free (new_pathname);
		return(NULL);
	}

	while(components[num_components] != NULL) {
		num_components++;
	}
	g_free (new_pathname);

	if (num_components == 0){
		return NULL;
	}


	new_components = (gchar **)g_new0 (gchar **, num_components + 1);

	if (num_components > 1) {
		if (strcmp (components[0], "") == 0) {
			/* first component blank, so start at / */
			scanning = opendir ("/");
			if (scanning == NULL) {
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}

			new_components[component++] = g_strdup ("");
		} else {
			DIR *current;
			gchar *entry;

			current = opendir (".");
			if (current == NULL) {
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}

			entry = find_in_dir (current, components[0]);
			if (entry == NULL) {
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}

			scanning = opendir (entry);
			if (scanning == NULL) {
				g_free (entry);
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}

			new_components[component++] = entry;
		}
	} else {
		if (last_exists) {
			if (strcmp (components[0], "") == 0) {
				/* First and only component blank */
				new_components[component++] = g_strdup ("");
			} else {
				DIR *current;
				gchar *entry;

				current = opendir (".");
				if (current == NULL) {
					g_strfreev (new_components);
					g_strfreev (components);
					return(NULL);
				}

				entry = find_in_dir (current, components[0]);
				if (entry == NULL) {
					g_strfreev (new_components);
					g_strfreev (components);
					return(NULL);
				}

				new_components[component++] = entry;
			}
		} else {
			new_components[component++] = g_strdup (components[0]);
		}
	}

	g_assert (component == 1);

	for(; component < num_components; component++) {
		gchar *entry;
		gchar *path_so_far;

		if (!last_exists &&
		    component == num_components -1) {
			entry = g_strdup (components[component]);
			closedir (scanning);
		} else {
			entry = find_in_dir (scanning, components[component]);
			if (entry == NULL) {
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}
		}

		new_components[component] = entry;

		if (component < num_components -1) {
			path_so_far = g_strjoinv ("/", new_components);

			scanning = opendir (path_so_far);
			g_free (path_so_far);
			if (scanning == NULL) {
				g_strfreev (new_components);
				g_strfreev (components);
				return(NULL);
			}
		}
	}

	g_strfreev (components);

	new_pathname = g_strjoinv ("/", new_components);

	g_strfreev (new_components);

	if ((last_exists &&
	     access (new_pathname, F_OK) == 0) ||
	    (!last_exists)) {
		return(new_pathname);
	}

	g_free (new_pathname);
	return(NULL);
}

