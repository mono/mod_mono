/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Authors:
 * 	Daniel Lopez Ridruejo
 * 	Gonzalo Paniagua Javier <gonzalo @ ximian.com >
 * 	
 * Copyright (c) 2002 Daniel Lopez Ridruejo.
 *           (c) 2002,2003 Ximian, Inc.
 *           (c) 2004 Novell, Inc.
 *           All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by 
 *        Daniel Lopez Ridruejo (daniel@rawbyte.com) and
 *        Ximian Inc. (http://www.ximian.com)"
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "mod_mono" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono",
 *    nor may "mod_mono" appear in their name, without prior written
 *    permission of Daniel Lopez Ridruejo and Ximian Inc.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL DANIEL LOPEZ RIDRUEJO OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <httpd.h>
#include <http_config.h>
#include <errno.h>
#include <sys/wait.h>

#ifdef APACHE13
/* Apache 1.3 only */
/* Functions needed for making Apache 1.3 module as similar
as possible to Apache 2 module, reducing ifdefs in the code itself*/

#define STATUS_AND_SERVER NULL
#ifndef TRUE
#define TRUE 1
#define FALSE 0
#endif

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
#define APR_SUCCESS 0

#include <ap_alloc.h>
/* End Apache 1.3 only */
#else
/* Apache 2 only */
#define STATUS_AND_SERVER 0, NULL
#include <http_protocol.h>
#include <apr_strings.h>
/* End Apache 2 only */
#endif

#include <http_core.h>
#include <http_log.h>
#include <mod_mono_config.h>
#include <sys/un.h>
#include <sys/select.h>

#ifndef PREFIX
#define PREFIX "/usr"
#endif

#define EXECUTABLE_PATH 	PREFIX "/bin/mono"
#define MONO_PATH		PREFIX "/lib"
#define MODMONO_SERVER_PATH 	PREFIX "/bin/mod-mono-server.exe"
#define WAPIDIR				"/tmp"
#define DOCUMENT_ROOT		NULL
#define APPCONFIG_FILE		NULL
#define APPCONFIG_DIR		NULL
#define SOCKET_FILE		"/tmp/mod_mono_server"

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
	GET_REQUEST_LINE = 0,
	SEND_FROM_MEMORY,
	GET_PATH_INFO,
	GET_SERVER_VARIABLE,
	GET_PATH_TRANSLATED,
	GET_SERVER_PORT,
	SET_RESPONSE_HEADER,
	GET_FILENAME,
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
	SET_STATUS_LINE,
	SET_STATUS_CODE,
	DECLINE_REQUEST,
	LAST_COMMAND
};

static char *cmdNames [] = {
	"GET_REQUEST_LINE",
	"SEND_FROM_MEMORY",
	"GET_PATH_INFO",
	"GET_SERVER_VARIABLE",
	"GET_PATH_TRANSLATED",
	"GET_SERVER_PORT",
	"SET_RESPONSE_HEADER",
	"GET_FILENAME",
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
	"SET_STATUS_LINE",
	"SET_STATUS_CODE",
	"DECLINE_REQUEST"
};

#ifdef APACHE13
module MODULE_VAR_EXPORT mono_module;
#else 
module AP_MODULE_DECLARE_DATA mono_module;
#endif

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
  return  ntohs(c->remote_addr.sin_port);
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
  return ap_get_server_port(r);
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
	/* Is there a more efficient way to do this w/o breaking encapsulation at HttpWorkerRequest level?. 
	Apache requires content_type to be set and will insert content type header itself later on.
	-- daniel
	*/
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
request_get_path_translated (request_rec *r)
{
	return ap_make_dirstr_parent (r->pool, r->filename);
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
write_ok (int fd)
{
	int i = 0;
	
	return write (fd, &i, 1);
}

static int
write_data (int fd, const void *str, int size)
{
	if (write_ok (fd) == -1)
		return -1;

	return write (fd, str, size);
}

static int
write_err (int fd)
{
	int i = -1;
	
	return write (fd, &i, 1);
}

static int
write_data_string_no_prefix (int fd, const char *str)
{
	int l;

	l = (str == NULL) ? 0 : strlen (str);
	if (write (fd, &l, sizeof (int)) != sizeof (int))
		return -1;

	if (l == 0)
		return 0;

	return write (fd, str, l);
}

static int
write_data_string (int fd, const char *str)
{
	if (write_ok (fd) == -1)
		return;

	return write_data_string_no_prefix (fd, str);
}

static char *
read_data_string (apr_pool_t *pool, int fd, char **ptr, int *size)
{
	int l, count;
	char *buf;

	if (read (fd, &l, sizeof (int)) != sizeof (int))
		return NULL;

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
	int status;

	ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER, "Command received: %s", cmdNames [command]);
	*result = OK;
	switch (command) {
	case SEND_FROM_MEMORY:
		if (read_data_string (r->pool, fd, &str, &size) == NULL) {
			status = -1;
			break;
		}
		request_send_response_from_memory (r, str, size);
		status = write_ok (fd);
		break;
	case GET_PATH_INFO:
		status = write_data_string (fd, r->path_info);
		break;
	case GET_SERVER_VARIABLE:
		if (read_data_string (r->pool, fd, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		str = (char *) request_get_server_variable (r, str);
		status = write_data_string (fd, str);
		break;
	case GET_PATH_TRANSLATED:
		str = request_get_path_translated (r);
		status = write_data_string (fd, str);
		break;
	case GET_SERVER_PORT:
		i = request_get_server_port (r);
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
		status = write_ok (fd);
		break;
	case GET_FILENAME:
		status = write_data_string (fd, r->filename);
		break;
	case GET_REMOTE_ADDRESS:
		status = write_data_string (fd, r->connection->remote_ip);
		break;
	case GET_LOCAL_ADDRESS:
		status = write_data_string (fd, r->connection->local_ip);
		break;
	case GET_REMOTE_PORT:
		i = connection_get_remote_port (r->connection);
		status = write_data (fd, &i, sizeof (int));
		break;
	case GET_LOCAL_PORT:
		i = connection_get_local_port (r);
		status = write_data (fd, &i, sizeof (int));
		break;
	case GET_REMOTE_NAME:
		str = (char *) connection_get_remote_name (r);
		status = write_data_string (fd, str);
		break;
	case FLUSH:
		connection_flush (r);
		status = write_ok (fd);
		break;
	case CLOSE:
		status = write_ok (fd);
		return FALSE;
		break;
	case SHOULD_CLIENT_BLOCK:
		size = ap_should_client_block (r);
		status = write_data (fd, &size, sizeof (int));
		break;
	case SETUP_CLIENT_BLOCK:
		if (setup_client_block (r) != APR_SUCCESS) {
			size = -1;
			status = write_data (fd, &size, sizeof (int));
			break;
		}

		size = 0;
		status = write_data (fd, &size, sizeof (int));
		break;
	case GET_CLIENT_BLOCK:
		status = read_data (fd, &i, sizeof (int));
		if (status == -1)
			break;

		str = apr_pcalloc (r->pool, i);
		i = ap_get_client_block (r, str, i);
		status = write_data (fd, &i, sizeof (int));
		status = write (fd, str, i);
		break;
	case SET_STATUS_LINE:
		if (read_data_string (r->pool, fd, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		status = write_ok (fd);
		r->status_line = apr_pstrdup (r->pool, str);
		break;
	case SET_STATUS_CODE:
		status = read_data (fd, &i, sizeof (int));
		if (status == -1)
			break;

		r->status = i;
		status = write_ok (fd);
		break;
	case DECLINE_REQUEST:
		status = write_ok (fd);
		*result = DECLINED;
		return FALSE;
	default:
		*result = HTTP_INTERNAL_SERVER_ERROR;
		write_err (fd);
		return FALSE;
	}

	if (status == -1) {
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	return TRUE;
}

static int
try_connect (const char *filename, int fd)
{
	char *error;
	struct sockaddr_un address;
	struct sockaddr *ptradd;

	ptradd = (struct sockaddr *) &address;
	address.sun_family = PF_UNIX;
	memcpy (address.sun_path, filename, strlen (filename) + 1);
	if (connect (fd, ptradd, sizeof (address)) != -1)
		return fd;

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

		close (fd);
		return -2; /* Unrecoverable */
	default:
		error = strerror (errno);
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: connect error (%s). File: %s", error, filename);

		close (fd);
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
		wait (&status);
		return;
	}

	pid = fork ();
	if (pid > 0) {
		exit (0);
	}

	setsid ();
	chdir ("/");
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
	setsid ();
	chdir ("/");
	umask (0077);
	setenv ("PATH", path, 1);
	setenv ("MONO_PATH", server_conf->path, 1);
	wapidir = apr_pcalloc (pool, strlen (server_conf->wapidir) + 5 + 2);
	sprintf (wapidir, "%s/%s", server_conf->wapidir, ".wapi");
	mkdir (wapidir, 0700);
	chmod (wapidir, 0700);
	setenv ("MONO_SHARED_DIR", server_conf->wapidir, 1);

	memset (argv, 0, sizeof (char *) * maxargs);
	argi = 0;
	argv [argi++] = server_conf->executable_path;
	argv [argi++] = server_conf->server_path;
	argv [argi++] = "--filename";
	argv [argi++] = server_conf->filename;
	argv [argi++] = "--applications";
	argv [argi++] = server_conf->applications;
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
	// The last element in the argv array must always be NULL
	// to terminate the array for execv().

	// Any new argi++'s that are added here must also increase
	// the maxargs argument at the top of this method to prevent
	// array out-of-bounds. 

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

static int
setup_socket (apr_pool_t *pool, mono_server_rec *server_conf)
{
	int fd;
	int result;
	char *filename;
	pid_t pid;
	int status;
	int i;
	
	fd = socket (PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: error creating socket.");

		return -1;
	}

	result = try_connect (server_conf->filename, fd);
	DEBUG_PRINT (1, "try_connect: %d", (void *) result);
	if (result > 0)
		return fd;

	if (result == -2)
		return -1;

	/* Running mod-mono-server not requested */
	if (!strcasecmp (server_conf->run_xsp, "false")) {
		DEBUG_PRINT (1, "Not running mod-mono-server: %s", server_conf->run_xsp);
		ap_log_error (APLOG_MARK, APLOG_DEBUG,
			      STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe");
		return -1;
	}

	/* MonoApplications is mandatory when running mod-mono-server */
	DEBUG_PRINT (1, "Applications: %s", server_conf->applications);
	if (server_conf->applications == NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR,
			      STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because no "
			      "MonoApplications specified.");
		return -1;
	}

	fork_mod_mono_server (pool, server_conf);
	DEBUG_PRINT (1, "parent waiting");
	for (i = 0; i < 3; i++) {
		sleep (1);
		DEBUG_PRINT (1, "try_connect %d", i);
		result = try_connect (server_conf->filename, fd);
		if (result > 0)
			return fd;
	}

	ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
		      "Failed connecting and child didn't exit!");

	return -1;
}

static int
send_headers (request_rec *r, int fd)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;

	elts = apr_table_elts (r->headers_in);
	DEBUG_PRINT (3, "Elements: %d", (int) elts->nelts);
	write (fd, &elts->nelts, sizeof (int));
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
	int fd;
	int command;
	int result;
	int input;
	int status;
	char *str;
	mono_server_rec *server_conf;

	server_conf = ap_get_module_config (r->server->module_config, &mono_module);
	DEBUG_PRINT (2, "Tengo server conf: %X %X", server_conf, server_conf->filename);

	fd = setup_socket (r->pool, server_conf);
	DEBUG_PRINT (2, "After setup_socket");
	if (fd == -1)
		return HTTP_SERVICE_UNAVAILABLE;

	DEBUG_PRINT (2, "Writing method: %s", r->method);
	if (write_data_string_no_prefix (fd, r->method) <= 0) {
		close (fd);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing uri: %s", r->uri);
	if (write_data_string_no_prefix (fd, r->uri) <= 0) {
		close (fd);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing query string: %s", request_get_query_string (r));
	if (write_data_string_no_prefix (fd, request_get_query_string (r)) < 0) {
		close (fd);
		return HTTP_SERVICE_UNAVAILABLE;
	}

	DEBUG_PRINT (2, "Writing protocol: %s", r->protocol);
	if (write_data_string_no_prefix (fd, r->protocol) <= 0) {
		close (fd);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	
	DEBUG_PRINT (2, "Sending headers");
	if (!send_headers (r, fd)) {
		close (fd);
		return HTTP_SERVICE_UNAVAILABLE;
	}
		
	do {
		input = read (fd, &command, sizeof (int));
		if (input > 0)
			result = do_command (command, fd, r, &status);
	} while (input > 0 && result == TRUE);

	close (fd);
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

#ifdef APACHE13
static void
mono_init_handler (server_rec *s, pool *p)
{
	DEBUG_PRINT (0, "Initializing handler");
	ap_add_version_component ("mod_mono/" VERSION);
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
	return OK;
}
#endif

#ifdef APACHE13
static const handler_rec mono_handlers [] = {
	{ "mono", mono_handler },
	{ NULL }
};
#else
static void
mono_register_hooks (apr_pool_t * p)
{
	ap_hook_handler (mono_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config (mono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

#ifdef APACHE13
#define MAKE_CMD(name, function_name, description) \
	{ #name, CONFIG_FUNCTION_NAME (function_name), NULL, RSRC_CONF, TAKE1, description }
#else
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


