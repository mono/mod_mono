/*
 * mod_mono.c
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
#ifdef HAVE_CONFIG_H
#include "mod_mono_config.h"
#endif

#include <errno.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <sys/select.h>
#include "httpd.h"
#include "http_core.h"
#include "http_log.h"
#include "http_config.h"


#ifdef APACHE13
/* Apache 1.3 only */
/* Functions needed for making Apache 1.3 module as similar
as possible to Apache 2 module, reducing ifdefs in the code itself*/

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
#define apr_proc_mutex_t mutex
#define apr_proc_mutex_lock ap_acquire_mutex
#define apr_proc_mutex_unlock ap_release_mutex

typedef struct apr_socket apr_socket_t;
struct apr_socket {
	apr_pool_t *pool;
	int fd;
};

#define apr_os_sock_get(fdptr, sock) (*(fdptr) = (sock)->fd)
#define apr_socket_close(sock) (ap_pclosesocket ((sock)->pool, (sock)->fd))

#include <ap_alloc.h>
/* End Apache 1.3 only */
#else
/* Apache 2 only */
#define STATUS_AND_SERVER 0, NULL
#include <http_protocol.h>
#include <apr_strings.h>
/* End Apache 2 only */
#endif

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

/* define this to get tons of messages in the log */
#undef DEBUG

#define DEBUG_LEVEL 0

#ifdef DEBUG
#define DEBUG_PRINT(a,...) if (a >= DEBUG_LEVEL) { \
				errno = 0; \
				ap_log_error (APLOG_MARK, APLOG_WARNING, STATUS_AND_SERVER, __VA_ARGS__); \
			}
#else
#define DEBUG_PRINT dummy_print
static void
dummy_print (int a, ...)
{
}
#endif

#define CONFIG_FUNCTION_NAME(directive) mono_config_ ##directive
#define CONFIG_FUNCTION(directive, field) static const char *\
			mono_config_ ##directive (cmd_parms *cmd, void *config, const char *parm) \
			{ \
				mono_server_rec *sr; \
				sr = (mono_server_rec *) \
					ap_get_module_config (cmd->server->module_config, &mono_module); \
 			\
				sr->field = (char *) parm; \
				DEBUG_PRINT (0, #directive ": %s", parm == NULL ? "(null)" : parm); \
				return NULL; \
			}

enum Cmd {
	FIRST_COMMAND,
	SEND_FROM_MEMORY = 0,
	GET_SERVER_VARIABLE,
	GET_SERVER_PORT,
	SET_RESPONSE_HEADER,
	GET_REMOTE_ADDRESS,
	GET_LOCAL_ADDRESS,
	GET_REMOTE_PORT,
	GET_LOCAL_PORT,
	GET_REMOTE_NAME,
	FLUSH,
	CLOSE,
	SHOULD_CLIENT_BLOCK,
	SETUP_CLIENT_BLOCK,
	GET_CLIENT_BLOCK,
	SET_STATUS,
	DECLINE_REQUEST,
	LAST_COMMAND
};

static char *cmdNames [] = {
	"SEND_FROM_MEMORY",
	"GET_SERVER_VARIABLE",
	"GET_SERVER_PORT",
	"SET_RESPONSE_HEADER",
	"GET_REMOTE_ADDRESS",
	"GET_LOCAL_ADDRESS",
	"GET_REMOTE_PORT",
	"GET_LOCAL_PORT",
	"GET_REMOTE_NAME",
	"FLUSH",
	"CLOSE",
	"SHOULD_CLIENT_BLOCK",
	"SETUP_CLIENT_BLOCK",
	"GET_CLIENT_BLOCK",
	"SET_STATUS",
	"DECLINE_REQUEST"
};

#ifdef APACHE13
module MODULE_VAR_EXPORT mono_module;
#else 
module AP_MODULE_DECLARE_DATA mono_module;
#endif

/* Configuration pool. Cleared on restart. */
static apr_pool_t *pconf;
static apr_proc_mutex_t *runmono_mutex;

typedef struct {
	char *filename;
	char *run_xsp;
	char *executable_path;
	char *path;
	char *server_path;
	char *applications;
	char *wapidir;
	char *document_root;
	char *appconfig_file;
	char *appconfig_dir;
} mono_server_rec;

CONFIG_FUNCTION (unix_socket, filename)
CONFIG_FUNCTION (run_xsp, run_xsp)
CONFIG_FUNCTION (executable_path, executable_path)
CONFIG_FUNCTION (path, path)
CONFIG_FUNCTION (server_path, server_path)
CONFIG_FUNCTION (applications, applications)
CONFIG_FUNCTION (wapidir, wapidir)
CONFIG_FUNCTION (document_root, document_root)
CONFIG_FUNCTION (appconfig_file, appconfig_file)
CONFIG_FUNCTION (appconfig_dir, appconfig_dir)

static void *
create_mono_server_config (apr_pool_t *p, server_rec *s)
{
	mono_server_rec *server;

	DEBUG_PRINT (1, "create_mono_server_config");

	server = apr_pcalloc (p, sizeof (mono_server_rec));
	server->filename = SOCKET_FILE;
	server->run_xsp = "True";
	server->executable_path = EXECUTABLE_PATH;
	server->path = MONO_PATH;
	server->server_path = MODMONO_SERVER_PATH;
	server->applications = NULL;
	server->wapidir = WAPIDIR;
	server->document_root = DOCUMENT_ROOT;
	server->appconfig_file = APPCONFIG_FILE;
	server->appconfig_dir = APPCONFIG_DIR;

	return server;
}

static void
request_send_response_from_memory (request_rec *r, char *byteArray, int size)
{
#ifdef APACHE13
	if (r->sent_bodyct == 0)
		ap_send_http_header (r);
#endif

	ap_rwrite (byteArray, size, r);
}

/* Not connection because actual port will vary depending on Apache configuration */
static int
request_get_server_port (request_rec *r)
{
	return ap_get_server_port (r);
}

static int
connection_get_remote_port (conn_rec *c)
{ 
#ifdef APACHE13
	return  ntohs (c->remote_addr.sin_port);
#else
	apr_port_t port;
	apr_sockaddr_port_get (&port, c->remote_addr);
	return port;
#endif
  
}

static int
connection_get_local_port (request_rec *r)
{
#ifdef APACHE13  
	return ap_get_server_port (r);
#else
	apr_port_t port;
	apr_sockaddr_port_get (&port, r->connection->local_addr);
	return port;  
#endif
}

static const char *
connection_get_remote_name (request_rec *r)
{
#ifdef APACHE13
	return ap_get_remote_host (r->connection, r->per_dir_config, REMOTE_NAME);
#else
	return ap_get_remote_host (r->connection, r->per_dir_config, REMOTE_NAME, NULL);
#endif
}

static void
connection_flush (request_rec *r)
{
#ifdef APACHE13
	ap_rflush (r);
#else
	ap_flush_conn (r->connection);
#endif
}

static void
set_response_header (request_rec *r,
		     const char *name,
		     const char *value)
{
	if (!strcasecmp(name,"Content-Type")) {
		r->content_type = value;
	} else {
		apr_table_setn (r->headers_out, name, value);
	}
}

static const char *
request_get_request_header (request_rec *r, const char *header_name)
{
	return apr_table_get (r->headers_in, header_name);
}

static const char *
request_get_server_variable (request_rec *r, const char *name)
{
	return apr_table_get (r->subprocess_env, name);
}

static char *
request_get_query_string (request_rec *r)
{
	return r->args ? r->args : "";
}

static int
setup_client_block (request_rec *r)
{
	if (r->read_length)
		return APR_SUCCESS;

	return ap_setup_client_block (r, REQUEST_CHUNKED_ERROR);
}

static int
write_data (int fd, const void *str, int size)
{
	return write (fd, str, size);
}

static int
write_data_string_no_prefix (int fd, const char *str)
{
	int l;
	int lel;

	l = (str == NULL) ? 0 : strlen (str);
	lel = LE_FROM_INT (l);
	if (write (fd, &lel, sizeof (int)) != sizeof (int))
		return -1;

	if (l == 0)
		return 0;

	return write (fd, str, l);
}

static int
write_data_string (int fd, const char *str)
{
	return write_data_string_no_prefix (fd, str);
}

static char *
read_data_string (apr_pool_t *pool, int fd, char **ptr, int *size)
{
	int l, count;
	char *buf;

	if (read (fd, &l, sizeof (int)) != sizeof (int))
		return NULL;

	l = INT_FROM_LE (l);
	buf = apr_pcalloc (pool, l + 1);
	count = l;
	while (count > 0) {
		count -= read (fd, buf + l - count, count);
	}

	if (ptr)
		*ptr = buf;

	if (size)
		*size = l;

	return buf;
}

static int
read_data (int fd, void *ptr, int size)
{
	return (read (fd, ptr, size) == size) ? size : -1;
}

static int
do_command (int command, int fd, request_rec *r, int *result)
{
	int size;
	char *str;
	char *str2;
	int i;
	int status = 0;

	ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER, "Command received: %s", cmdNames [command]);
	*result = OK;
	switch (command) {
	case SEND_FROM_MEMORY:
		if (read_data_string (r->pool, fd, &str, &size) == NULL) {
			status = -1;
			break;
		}
		request_send_response_from_memory (r, str, size);
		break;
	case GET_SERVER_VARIABLE:
		if (read_data_string (r->pool, fd, &str, NULL) == NULL) {
			break;
		}
		str = (char *) request_get_server_variable (r, str);
		status = write_data_string (fd, str);
		break;
	case GET_SERVER_PORT:
		i = request_get_server_port (r);
		i = LE_FROM_INT (i);
		status = write_data (fd, &i, sizeof (int));
		break;
	case SET_RESPONSE_HEADER:
		if (read_data_string (r->pool, fd, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		if (read_data_string (r->pool, fd, &str2, NULL) == NULL) {
			status = -1;
			break;
		}
		set_response_header (r, str, str2);
		break;
	case GET_REMOTE_ADDRESS:
		status = write_data_string (fd, r->connection->remote_ip);
		break;
	case GET_LOCAL_ADDRESS:
		status = write_data_string (fd, r->connection->local_ip);
		break;
	case GET_REMOTE_PORT:
		i = connection_get_remote_port (r->connection);
		i = LE_FROM_INT (i);
		status = write_data (fd, &i, sizeof (int));
		break;
	case GET_LOCAL_PORT:
		i = connection_get_local_port (r);
		i = LE_FROM_INT (i);
		status = write_data (fd, &i, sizeof (int));
		break;
	case GET_REMOTE_NAME:
		str = (char *) connection_get_remote_name (r);
		status = write_data_string (fd, str);
		break;
	case FLUSH:
		connection_flush (r);
		break;
	case CLOSE:
		return FALSE;
		break;
	case SHOULD_CLIENT_BLOCK:
		size = ap_should_client_block (r);
		size = LE_FROM_INT (size);
		status = write_data (fd, &size, sizeof (int));
		break;
	case SETUP_CLIENT_BLOCK:
		if (setup_client_block (r) != APR_SUCCESS) {
			size = LE_FROM_INT (-1);
			status = write_data (fd, &size, sizeof (int));
			break;
		}

		size = LE_FROM_INT (0);
		status = write_data (fd, &size, sizeof (int));
		break;
	case GET_CLIENT_BLOCK:
		status = read_data (fd, &i, sizeof (int));
		if (status == -1)
			break;

		i = INT_FROM_LE (i);
		str = apr_pcalloc (r->pool, i);
		i = ap_get_client_block (r, str, i);
		i = LE_FROM_INT (i);
		status = write_data (fd, &i, sizeof (int));
		i = INT_FROM_LE (i);
		status = write (fd, str, i);
		break;
	case SET_STATUS:
		status = read_data (fd, &i, sizeof (int));
		if (status == -1)
			break;

		if (read_data_string (r->pool, fd, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		r->status = INT_FROM_LE (i);
		r->status_line = apr_pstrdup (r->pool, str);
		break;
	case DECLINE_REQUEST:
		*result = DECLINED;
		return FALSE;
	default:
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	if (status == -1) {
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	return TRUE;
}

static apr_status_t 
try_connect (const char *filename, apr_socket_t **sock)
{
	char *error;
	struct sockaddr_un address;
	struct sockaddr *ptradd;
	apr_os_sock_t sock_fd;

	apr_os_sock_get (&sock_fd, *sock);
	ptradd = (struct sockaddr *) &address;
	address.sun_family = PF_UNIX;
	memcpy (address.sun_path, filename, strlen (filename) + 1);
	if (connect (sock_fd, ptradd, sizeof (address)) != -1)
		return APR_SUCCESS;

	switch (errno) {
	case ENOENT:
	case ECONNREFUSED:
		return -1; /* Can try to launch mod-mono-server */
	case EPERM:
		error = strerror (errno);
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: file %s exists, but wrong permissions.", filename);

		apr_socket_close (*sock);
		return -2; /* Unrecoverable */
	default:
		error = strerror (errno);
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: connect error (%s). File: %s", error, filename);

		apr_socket_close (*sock);
		return -2; /* Unrecoverable */
	}
}

static char *
get_directory (apr_pool_t *pool, const char *filepath)
{
	char *sep;
	char *result;

	sep = strrchr (filepath, '/');
	if (sep == NULL || sep == filepath)
		return "/";
	
	result = apr_pcalloc (pool, sep - filepath + 1);
	strncpy (result, filepath, sep - filepath);
	return result;
}

#ifdef HAVE_SETENV
#	define SETENV(pool, name, value) setenv (name, value, 1)
#else
#	ifdef HAVE_PUTENV
#	define SETENV(pool, name, value) setenv_to_putenv (pool, name, value)
static int
setenv_to_putenv (apr_pool_t *pool, char *name, char *value)
{
	char *arg;

	arg = apr_pcalloc (pool, strlen (name) + strlen (value) + 2);
	sprintf (arg, "%s=%s", name, value);
	return putenv (arg);
}

#	else
#	error No setenv or putenv found!
#endif
#endif

static void
fork_mod_mono_server (apr_pool_t *pool, mono_server_rec *server_conf)
{
	pid_t pid;
	int status;
	int i;
	const int maxargs = 14;
	char *argv [maxargs];
	int argi;
	char *path;
	char *tmp;
	char *monodir;
	char *serverdir;
	char *wapidir;

	pid = fork ();
	if (pid > 0) {
#ifdef APACHE2
		apr_proc_t *proc;

		proc = apr_pcalloc (pconf, sizeof (apr_proc_t));
		proc->pid = pid;
		apr_pool_note_subprocess (pconf, proc, APR_KILL_AFTER_TIMEOUT);
#else
		ap_note_subprocess (pconf, pid, kill_after_timeout);
#endif
		return;
	}

	chdir ("/");
	umask (0077);
	DEBUG_PRINT (1, "child started");
	
	for (i = getdtablesize () - 1; i >= 3; i--)
		close (i);

	tmp = getenv ("PATH");
	DEBUG_PRINT (1, "PATH: %s", tmp);
	if (tmp == NULL)
		tmp = "";

	monodir = get_directory (pool, server_conf->executable_path);
	DEBUG_PRINT (1, "monodir: %s", monodir);
	serverdir = get_directory (pool, server_conf->server_path);
	DEBUG_PRINT (1, "serverdir: %s", serverdir);
	if (strcmp (monodir, serverdir)) {
		path = apr_pcalloc (pool, strlen (tmp) + 1 +
					  strlen (monodir) + 1 +
					  strlen (serverdir) + 1);
		sprintf (path, "%s:%s:%s", monodir, serverdir, tmp);
	} else {
		path = apr_pcalloc (pool, strlen (tmp) + 1 +
					  strlen (monodir) + 1);

		sprintf (path, "%s:%s", monodir, tmp);
	}

	DEBUG_PRINT (1, "PATH after: %s", path);
	SETENV (pool, "PATH", path);
	SETENV (pool, "MONO_PATH", server_conf->path);
	wapidir = apr_pcalloc (pool, strlen (server_conf->wapidir) + 5 + 2);
	sprintf (wapidir, "%s/%s", server_conf->wapidir, ".wapi");
	mkdir (wapidir, 0700);
	chmod (wapidir, 0700);
	SETENV (pool, "MONO_SHARED_DIR", server_conf->wapidir);

	memset (argv, 0, sizeof (char *) * maxargs);
	argi = 0;
	argv [argi++] = server_conf->executable_path;
	argv [argi++] = server_conf->server_path;
	argv [argi++] = "--filename";
	argv [argi++] = server_conf->filename;
	if (server_conf->applications != NULL) {
		argv [argi++] = "--applications";
		argv [argi++] = server_conf->applications;
	}

	argv [argi++] = "--nonstop";
        if (server_conf->document_root != NULL) {
                argv [argi++] = "--root";
                argv [argi++] = server_conf->document_root;
        }

	if (server_conf->appconfig_file != NULL) {
		argv [argi++] = "--appconfigfile";
		argv [argi++] = server_conf->appconfig_file;
	}

	if (server_conf->appconfig_dir != NULL) {
		argv [argi++] = "--appconfigdir";
		argv [argi++] = server_conf->appconfig_dir;
	}

	/*
	 * The last element in the argv array must always be NULL
	 * to terminate the array for execv().
	 *
	 * Any new argi++'s that are added here must also increase
	 * the maxargs argument at the top of this method to prevent
 	 * array out-of-bounds. 
	 */

	ap_log_error (APLOG_MARK, APLOG_DEBUG,
		      STATUS_AND_SERVER,
                      "running '%s %s %s %s %s %s %s %s %s %s %s %s %s'",
                      argv [0], argv [1], argv [2], argv [3], argv [4],
		      argv [5], argv [6], argv [7], argv [8], 
		      argv [9], argv [10], argv [11], argv [12]);

	execv (argv [0], argv);
	ap_log_error (APLOG_MARK, APLOG_ERR,
		      STATUS_AND_SERVER,
                      "Failed running '%s %s %s %s %s %s %s %s %s %s %s %s %s'. Reason: %s",
                      argv [0], argv [1], argv [2], argv [3], argv [4],
		      argv [5], argv [6], argv [7], argv [8],
		      argv [9], argv [10], argv [11], argv [12],
		      strerror (errno));
	exit (1);
}

static apr_status_t
setup_socket (apr_socket_t **sock, mono_server_rec *server_conf, apr_pool_t *pool)
{
	char *filename;
	pid_t pid;
	int status;
	int i;
	apr_status_t rv;

#ifdef APACHE2
	rv = apr_socket_create (sock, PF_UNIX, SOCK_STREAM, pool);
#else
	(*sock)->fd = ap_psocket (pool, PF_UNIX, SOCK_STREAM, 0);
	(*sock)->pool = pool;
	rv = ((*sock)->fd != -1) ? APR_SUCCESS : -1;
#endif
	if (rv != APR_SUCCESS) {
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: error creating socket.");

		return rv;
	}

	rv = try_connect (server_conf->filename, sock);
	DEBUG_PRINT (1, "try_connect: %d", (void *) rv);
	if (rv == APR_SUCCESS)
		return rv;

	if (rv == -2)
		return -1;

	/* Running mod-mono-server not requested */
	if (!strcasecmp (server_conf->run_xsp, "false")) {
		DEBUG_PRINT (1, "Not running mod-mono-server: %s", server_conf->run_xsp);
		ap_log_error (APLOG_MARK, APLOG_DEBUG,
			      STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe");

		apr_socket_close (*sock);
		return -1;
	}

	/* At least one of MonoApplications, MonoApplicationsConfigFile or
	 * MonoApplicationsConfigDir must be specified */
	DEBUG_PRINT (1, "Applications: %s", server_conf->applications);
	DEBUG_PRINT (1, "Config file: %s", server_conf->appconfig_file);
	DEBUG_PRINT (1, "Config dir.: %s", server_conf->appconfig_dir);
	if (server_conf->applications == NULL &&
	    server_conf->appconfig_file == NULL &&
	    server_conf->appconfig_dir == NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR,
			      STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because no MonoApplications, "
			      "MonoApplicationsConfigFile or MonoApplicationConfigDir specified.");
		apr_socket_close (*sock);
		return -1;
	}

	rv = apr_proc_mutex_lock (runmono_mutex);
	if (rv == APR_SUCCESS) {
		fork_mod_mono_server (pool, server_conf);
	}

	DEBUG_PRINT (1, "parent waiting");
	for (i = 0; i < 3; i++) {
		sleep (1);
		DEBUG_PRINT (1, "try_connect %d", i);
		if (try_connect (server_conf->filename, sock) == APR_SUCCESS) {
			if (rv == APR_SUCCESS)
				apr_proc_mutex_unlock (runmono_mutex);

			return APR_SUCCESS;
		}
	}

	ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
		      "Failed connecting and child didn't exit!");

	if (rv == APR_SUCCESS)
		apr_proc_mutex_unlock (runmono_mutex);

	apr_socket_close (*sock);
	return -1;
}

static int
send_headers (request_rec *r, int fd)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;
	int tmp;

	elts = apr_table_elts (r->headers_in);
	DEBUG_PRINT (3, "Elements: %d", (int) elts->nelts);
	tmp = LE_FROM_INT (elts->nelts);
	write (fd, &tmp, sizeof (int));
	if (elts->nelts == 0)
		return TRUE;

	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		DEBUG_PRINT (3, "%s: %s", t_elt->key, t_elt->val);
		if (write_data_string_no_prefix (fd, t_elt->key) <= 0)
			return FALSE;
		if (write_data_string_no_prefix (fd, t_elt->val) < 0)
			return FALSE;


		t_elt++;
	} while (t_elt < t_end);

	return TRUE;
}

static int
mono_execute_request (request_rec *r)
{
	apr_socket_t *sock;
	apr_os_sock_t fd;
	apr_status_t rv;
	int command;
	int result;
	int input;
	int status;
	char *str;
	mono_server_rec *server_conf;

	server_conf = ap_get_module_config (r->server->module_config, &mono_module);

#ifdef APACHE13
	sock = apr_pcalloc (r->pool, sizeof (apr_socket_t));
#endif
	rv = setup_socket (&sock, server_conf, r->pool);
	DEBUG_PRINT (2, "After setup_socket");
	if (rv != APR_SUCCESS)
		return HTTP_SERVICE_UNAVAILABLE;

	apr_os_sock_get (&fd, sock);
	DEBUG_PRINT (2, "Writing method: %s", r->method);
	if (write_data_string_no_prefix (fd, r->method) <= 0) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing uri: %s", r->uri);
	if (write_data_string_no_prefix (fd, r->uri) <= 0) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing query string: %s", request_get_query_string (r));
	if (write_data_string_no_prefix (fd, request_get_query_string (r)) < 0) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing protocol: %s", r->protocol);
	if (write_data_string_no_prefix (fd, r->protocol) <= 0) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	
	DEBUG_PRINT (2, "Sending headers");
	if (!send_headers (r, fd)) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}
		
	do {
		input = read (fd, &command, sizeof (int));
		if (input > 0) {
			command = INT_FROM_LE (command);
			result = do_command (command, fd, r, &status);
		}
	} while (input > 0 && result == TRUE);

	apr_socket_close (sock);
	if (input <= 0)
		status = HTTP_INTERNAL_SERVER_ERROR;

	DEBUG_PRINT (2, "Done. Status: %d", status);
	return status;
}

static int
mono_handler (request_rec *r)
{
	if (strcmp (r->handler, "mono"))
		return DECLINED;

	DEBUG_PRINT (1, "handler: %s", r->handler);
	return mono_execute_request (r);
}

static int
create_runmono_mutex (apr_pool_t *ptemp)
{
	char *fname, *tmp;

	tmp = (char *) apr_pcalloc (ptemp, L_tmpnam);
	tmp = tmpnam (tmp);
	fname = apr_psprintf (pconf, "%s.%d", tmp, getpid ());

	DEBUG_PRINT (0, "fname: %s", fname);
#ifdef APACHE2
	return apr_proc_mutex_create (&runmono_mutex, fname, APR_LOCK_DEFAULT, pconf);
#else
	runmono_mutex = ap_create_mutex (fname);
	return 0;
#endif
}

#ifdef APACHE13
static void
mono_init_handler (server_rec *s, pool *p)
{
	DEBUG_PRINT (0, "Initializing handler");
	ap_add_version_component ("mod_mono/" VERSION);
	pconf = p;
	create_runmono_mutex (p);
}
#else
static int
mono_init_handler (apr_pool_t *p,
		      apr_pool_t *plog,
		      apr_pool_t *ptemp,
		      server_rec *s)
{
	DEBUG_PRINT (0, "Initializing handler");
	ap_add_version_component (p, "mod_mono/" VERSION);
	pconf = s->process->pconf;
	return create_runmono_mutex (ptemp);
}
#endif

#ifdef APACHE13
static const handler_rec mono_handlers [] = {
	{ "mono", mono_handler },
	{ NULL }
};

#define MAKE_CMD(name, function_name, description) \
	{ #name, CONFIG_FUNCTION_NAME (function_name), NULL, RSRC_CONF, TAKE1, description }
#else
static void
mono_register_hooks (apr_pool_t * p)
{
	ap_hook_handler (mono_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config (mono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

#define MAKE_CMD(name, function_name, description) \
	AP_INIT_TAKE1 (#name, CONFIG_FUNCTION_NAME(function_name), NULL, RSRC_CONF, description)
#endif

static const command_rec mono_cmds [] = {
MAKE_CMD (MonoUnixSocket, unix_socket,
	"Named pipe file name. Default: /tmp/mod_mono_server"
	),

MAKE_CMD (MonoRunXSP, run_xsp,
	"It can be False or True. If it is True, asks the module to "
	"start mod-mono-server.exe if it's not already there. Default: False"
	),

MAKE_CMD (MonoExecutablePath, executable_path,
	"If MonoRunXSP is True, this is the full path where mono is located. "
	"Default: /usr/bin/mono"
	),

MAKE_CMD (MonoPath, path,
	"If MonoRunXSP is True, this will be the content of MONO_PATH "
	"environment variable. Default: \"\""
	),

MAKE_CMD (MonoServerPath, server_path,
	"If MonoRunXSP is True, this is the full path to mod-mono-server.exe. "
	"Default: /usr/bin/mod-mono-server.exe"
	),

MAKE_CMD (MonoApplications, applications,
	"Comma separated list with virtual directories and real directories. "
	"One ASP.NET application will be created for each pair. Default: \"\" "
	),

MAKE_CMD (MonoWapiDir, wapidir,
	"The directory where mono runtime will create the '.wapi' directory "
	"used to emulate windows I/O. It's used to set MONO_SHARED_DIR. "
	"Default value: \"/tmp\""
	),

MAKE_CMD (MonoDocumentRootDir, document_root,
	"The argument passed in --root argument to mod-mono-server. "
	"This tells mod-mono-server to change the directory to the "
	"value specified before doing anything else. Default: /"
	),

MAKE_CMD (MonoApplicationsConfigFile, appconfig_file,
	"Adds application definitions from the  XML configuration file. "
	"See Appendix C for details on the file format. "
	"Default value: \"\""
	),

MAKE_CMD (MonoApplicationsConfigDir, appconfig_dir,
	"Adds application definitions from all XML files found in the "
	"specified directory DIR. Files must have '.webapp' extension. "
	"Default value: \"\""
	),

NULL
};

#ifdef APACHE13
module MODULE_VAR_EXPORT mono_module =
  {
    STANDARD_MODULE_STUFF,
    mono_init_handler,       /* initializer */
    NULL,      /* dir config creater */
    NULL,      /* dir merger --- default is to override */
    create_mono_server_config,	/* server config */
    NULL,                       /* merge server configs */
    mono_cmds,            /* command table */
    mono_handlers,         /* handlers */
    NULL,                       /* filename translation */
    NULL,                       /* check_user_id */
    NULL,                       /* check auth */
    NULL,                       /* check access */
    NULL,                       /* type_checker */
    NULL,           /* fixups */
    NULL,                       /* logger */
    NULL,                       /* header parser */
    NULL,                       /* child_init */
    NULL,                       /* child_exit */
    NULL                        /* post read-request */
  };
#else
module AP_MODULE_DECLARE_DATA mono_module = {
	STANDARD20_MODULE_STUFF,
	NULL,				/* dir config creater */
	NULL,				/* dir merger --- default is to override */
	create_mono_server_config,	/* server config */
	NULL,				/* merge server configs */
	mono_cmds,			/* command apr_table_t */
	mono_register_hooks		/* register hooks */
};
#endif


