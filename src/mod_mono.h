/*
 * mod_mono.h
 * 
 * Authors:
 * 	Daniel Lopez Ridruejo
 * 	Gonzalo Paniagua Javier
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo
 *           (c) 2002-2004 Novell, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __MOD_MONO_H
#define __MOD_MONO_H

#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "http_config.h"


#ifdef APACHE13
/* Functions needed for making Apache 1.3 module as similar
as possible to Apache 2 module, reducing ifdefs in the code itself*/
#ifdef HAVE_HTTP_PROTOCOL_H
#include "http_protocol.h"
#endif
#define STATUS_AND_SERVER NULL
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

#include "multithread.h"
#define apr_pool_t ap_pool
#define apr_pcalloc_t ap_pcalloc_t
#define apr_pcalloc ap_pcalloc

#define apr_table_setn ap_table_setn
#define apr_table_get ap_table_get
#define apr_table_elts ap_table_elts
#define apr_table_entry_t table_entry

#define apr_array_header array_header
#define apr_array_header_t array_header
#define apr_pstrdup ap_pstrdup
#define apr_psprintf ap_psprintf
#define apr_status_t int
#define apr_os_sock_t int
#define APR_SUCCESS 0
#define apr_os_sock_get(fdptr, sock) (*(fdptr) = (sock)->fd)
#define apr_socket_timeout_set(sock, t) ((sock)->timeout = t)
#define apr_socket_close(sock) (ap_pclosesocket ((sock)->pool, (sock)->fd))
#define APR_INET PF_INET

typedef time_t apr_interval_time_t;
typedef size_t apr_size_t;
typedef struct apr_socket apr_socket_t;
struct apr_socket {
	apr_pool_t *pool;
	int fd;
	time_t timeout;
};

typedef struct mysockaddr apr_sockaddr_t;
struct mysockaddr {
	apr_pool_t *pool;
	size_t  addrlen;
	struct sockaddr *addr;
};

static apr_status_t
apr_wait_for_io_or_timeout (void *unused, apr_socket_t *s, int for_read);

static apr_status_t
apr_socket_send (apr_socket_t *sock, const char *buf, apr_size_t *len);

static apr_status_t
apr_socket_recv (apr_socket_t *sock, char *buf, apr_size_t *len);

#include <ap_alloc.h>
/* End Apache 1.3 only */
#else
/* Apache 2 only */
#define STATUS_AND_SERVER 0, NULL
#include <http_protocol.h>
#include <apr_strings.h>
#include <apr_support.h>
/* End Apache 2 only */
#endif

/* Some defaults */
#ifndef MONO_PREFIX
#define MONO_PREFIX "/usr"
#endif

#define EXECUTABLE_PATH 	MONO_PREFIX "/bin/mono"
#define MONO_PATH		MONO_PREFIX "/lib"
#define MODMONO_SERVER_PATH 	MONO_PREFIX "/bin/mod-mono-server.exe"
#define WAPIDIR				"/tmp"
#define DOCUMENT_ROOT		NULL
#define APPCONFIG_FILE		NULL
#define APPCONFIG_DIR		NULL
#define SOCKET_FILE		"/tmp/mod_mono_server"
#define LISTEN_ADDRESS		"127.0.0.1"

/* Converts every int sent into little endian */
#ifdef WORDS_BIGENDIAN
#define INT_FROM_LE(val) LE_FROM_INT (val)
#define LE_FROM_INT(val)	((unsigned int) ( \
    (((unsigned int) (val) & (unsigned int) 0x000000ffU) << 24) | \
    (((unsigned int) (val) & (unsigned int) 0x0000ff00U) <<  8) | \
    (((unsigned int) (val) & (unsigned int) 0x00ff0000U) >>  8) | \
    (((unsigned int) (val) & (unsigned int) 0xff000000U) >> 24)))

#else
#define LE_FROM_INT(val) val
#define INT_FROM_LE(val) val
#endif

/* Configuration functions that only set a field */
#define CONFIG_FUNCTION_NAME(directive) mono_config_ ##directive
#define CONFIG_FUNCTION(directive, field) \
	static const char *\
	mono_config_ ##directive (cmd_parms *cmd, void *config,\
				const char *parm) \
	{ \
		mono_server_rec *sr; \
		sr = (mono_server_rec *) \
			ap_get_module_config (cmd->server->module_config, \
					&mono_module); \
		sr->field = (char *) parm; \
		DEBUG_PRINT (0, #directive ": %s", parm == NULL ? "(null)" : \
				parm); \
		return NULL; \
	}

/* Commands */
enum Cmd {
	FIRST_COMMAND,
	SEND_FROM_MEMORY = 0,
	GET_SERVER_VARIABLE,
	SET_RESPONSE_HEADER,
	GET_LOCAL_PORT,
	FLUSH,
	CLOSE,
	SHOULD_CLIENT_BLOCK,
	SETUP_CLIENT_BLOCK,
	GET_CLIENT_BLOCK,
	SET_STATUS,
	DECLINE_REQUEST,
	MYNOT_FOUND, /* apache 1.3 already defines NOT_FOUND */
	LAST_COMMAND
};

static char *cmdNames [] = {
	"SEND_FROM_MEMORY",
	"GET_SERVER_VARIABLE",
	"SET_RESPONSE_HEADER",
	"GET_LOCAL_PORT",
	"FLUSH",
	"CLOSE",
	"SHOULD_CLIENT_BLOCK",
	"SETUP_CLIENT_BLOCK",
	"GET_CLIENT_BLOCK",
	"SET_STATUS",
	"DECLINE_REQUEST",
	"NOT_FOUND"
};

/* Module definition */
#ifdef APACHE13
#define DEFINE_MODULE(x) module MODULE_VAR_EXPORT x
#else 
#define DEFINE_MODULE(x) module AP_MODULE_DECLARE_DATA x
#endif

/* Directives */
#ifdef APACHE13
#define MAKE_CMD(name, function_name, description) \
	{ #name, CONFIG_FUNCTION_NAME (function_name), NULL, RSRC_CONF, TAKE1, description }
#else
#define MAKE_CMD(name, function_name, description) \
	AP_INIT_TAKE1 (#name, CONFIG_FUNCTION_NAME(function_name), NULL, RSRC_CONF, description)
#endif

/* Debugging */
#ifdef DEBUG
#define DEBUG_PRINT(a,...) \
	if (a >= DEBUG_LEVEL) { \
		errno = 0; \
		ap_log_error (APLOG_MARK, APLOG_WARNING, STATUS_AND_SERVER, \
				__VA_ARGS__); \
	}
#else
#define DEBUG_PRINT dummy_print
static void
dummy_print (int a, ...)
{
}
#endif /* DEBUG */

#endif /* __MOD_MONO_H */

