#ifndef GLIB_COMPAT_H_
#define GLIB_COMPAT_H_

#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>

typedef char gboolean;
typedef char gchar;
typedef int gint;
typedef void* gpointer;

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#ifndef G_STR_DELIMITERS
#define G_STR_DELIMITERS "_-|> <."
#endif

#ifndef g_memmove
#define g_memmove memmove
#endif

#ifndef g_new0
#define g_new0(struct_type, n_structs) ((struct_type*)calloc (sizeof (struct_type), n_structs))
#endif

#ifndef g_assert
#define g_assert(expr)
#endif

gchar **g_strsplit (const gchar *string, const gchar *delimiter, int max_tokens);
gint g_ascii_strcasecmp (const gchar *s1, const gchar *s2);
gchar* g_strdup (const gchar *str);
void g_free (gpointer mem);
gchar* g_strdelimit (gchar *string, const gchar *delimiters, gchar new_delimiter);
gboolean g_ascii_isalpha (gchar c);
void g_strfreev (gchar **str_array);
gchar *g_strjoinv (const gchar *separator, gchar **str_array);

#endif /* !GLIB_COMPAT_H_ */
