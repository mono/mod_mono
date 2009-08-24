#ifdef HAVE_CONFIG_H
#include "mod_mono_config.h"
#endif

#include <ctype.h>

#include "glib_compat.h"

#define ASCII_TOLOWER(_ch_) (isascii ((int)(_ch_)) && isalpha ((int)(_ch_))) ? tolower ((_ch_)) : (_ch_)

static void add_to_vector (gchar ***vector, int size, gchar *token)
{
        *vector = *vector == NULL ? 
                (gchar **) malloc (2 * sizeof (*vector)) :
                (gchar **) realloc (*vector, (size + 1) * sizeof (*vector));
                
        (*vector)[size - 1] = token;
}

static gchar **make_empty_vector ()
{
	gchar **vector = (gchar**)malloc (2 * sizeof (vector));
	vector [0] = NULL;

	return vector;
}

gchar **g_strsplit (const gchar *string, const gchar *delimiter, int max_tokens)
{
	gchar **vector = NULL;
	int delimiter_len = strlen (delimiter);
	int size = 1;
	const gchar *c;
	gchar *token;
	
	if (!string || !*string)
		return make_empty_vector ();
	
	if (!delimiter || !*delimiter) {
		add_to_vector (&vector, size, strdup (string));
		return vector;
	}
	
	if (strncmp (string, delimiter, delimiter_len) == 0) {
		add_to_vector (&vector, size, strdup (""));
		size++;
		string += delimiter_len;
	} else
		vector = NULL;

	while (*string && !(max_tokens > 0 && size >= max_tokens)) {
		c = string;

		if (*string == *delimiter && strncmp (string, delimiter, delimiter_len) == 0) {
			token = strdup ("");
			string += delimiter_len;
		} else {
			while (*string && (*string != *delimiter || strncmp (string, delimiter, delimiter_len) != 0))
				string++;

			if (*string) {
				size_t toklen = (size_t)(string - c);
				token = strndup (c, toklen);

				if (strcmp (string, delimiter) != 0)
					string += delimiter_len;
			} else
				token = strdup (c);
		}

		add_to_vector (&vector, size, token);
		size++;
	}

	if (*string) {
		add_to_vector (&vector, size, strdup (string));
		size++;
	}
	
	if (!vector)
		return make_empty_vector ();
	else if (size > 0)
		vector [size - 1] = NULL;
	
	return vector;
}

gint g_ascii_strcasecmp (const gchar *s1, const gchar *s2)
{
	gchar ch1, ch2;
	
	if (s1 == s2)
		return 0;

	do {
		ch1 = ASCII_TOLOWER (*s1);
		ch2 = ASCII_TOLOWER (*s2);

		if (ch1 == 0)
			break;

		s1++;
		s2++;
	} while (ch1 == ch2);

	return (ch1 > ch2 ? 1 : ch1 < ch2 ? -1 : 0);
}

gchar* g_strdelimit (gchar *string, const gchar *delimiters, gchar new_delimiter)
{
        gchar *ptr;

	if (!string)
		return NULL;

        if (delimiters == NULL)
                delimiters = G_STR_DELIMITERS;

        for (ptr = string; *ptr; ptr++) {
                if (strchr (delimiters, *ptr))
                        *ptr = new_delimiter;
        }
        
        return string;
}

gchar* g_strdup (const gchar *str)
{
	if (!str)
		return NULL;
	
	return (gchar*) strdup (str);
}

void g_free (gpointer mem)
{
	if (!mem)
		return;

	free (mem);
}

gboolean g_ascii_isalpha (gchar c)
{
	return (isascii ((int)c) && isalpha ((int)c));
}

void g_strfreev (gchar **str_array)
{
        gchar **orig = str_array;
        if (str_array == NULL)
                return;
        while (*str_array != NULL){
                g_free (*str_array);
                str_array++;
        }
        g_free (orig);
}

gchar *g_strjoinv (const gchar *separator, gchar **str_array)
{
        char *res;
        size_t slen, len, i;
        
        if (separator != NULL)
                slen = strlen (separator);
        else
                slen = 0;
        
        len = 0;
        for (i = 0; str_array [i] != NULL; i++){
                len += strlen (str_array [i]);
                len += slen;
        }
        if (len == 0)
                return g_strdup ("");
        if (slen > 0 && len > 0)
                len -= slen;
        len++;
        res = (char*)malloc (len);
        strcpy (res, str_array [0]);
        for (i = 1; str_array [i] != NULL; i++){
                if (separator != NULL)
                        strcat (res, separator);
                strcat (res, str_array [i]);
        }
        return res;
}
