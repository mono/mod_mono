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

/* define this to get tons of messages in the log */
#undef DEBUG
#define DEBUG_LEVEL 0

#include "mod_mono.h"

DEFINE_MODULE (mono_module);

/* Configuration pool. Cleared on restart. */
static apr_pool_t *pconf;

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
	char *listen_port;
	char *listen_address;
	char *max_cpu_time;
	char *max_memory;
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
CONFIG_FUNCTION (listen_port, listen_port)
CONFIG_FUNCTION (listen_address, listen_address)
CONFIG_FUNCTION (max_cpu_time, max_cpu_time)
CONFIG_FUNCTION (max_memory, max_memory)

static void *
create_mono_server_config (apr_pool_t *p, server_rec *s)
{
	mono_server_rec *server;

	DEBUG_PRINT (1, "create_mono_server_config");

	server = apr_pcalloc (p, sizeof (mono_server_rec));
	server->filename = NULL;
	server->run_xsp = "True";
	server->executable_path = EXECUTABLE_PATH;
	server->path = MONO_PATH;
	server->server_path = MODMONO_SERVER_PATH;
	server->applications = NULL;
	server->wapidir = WAPIDIR;
	server->document_root = DOCUMENT_ROOT;
	server->appconfig_file = APPCONFIG_FILE;
	server->appconfig_dir = APPCONFIG_DIR;
	server->listen_port = NULL;
	server->listen_address = NULL;
	server->max_cpu_time = NULL;
	server->max_memory = NULL;

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

/* Do nothing
 * This does a kind of final flush which is not what we want.
 * It caused bug 60117.
static void
connection_flush (request_rec *r)
{
#ifdef APACHE13
	ap_rflush (r);
#else
	ap_flush_conn (r->connection);
#endif
}
*/

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

static int
setup_client_block (request_rec *r)
{
	if (r->read_length)
		return APR_SUCCESS;

	return ap_setup_client_block (r, REQUEST_CHUNKED_ERROR);
}

static int
write_data (apr_socket_t *sock, const void *str, int size)
{
	int prevsize = size;

	if (apr_socket_send (sock, str, &size) != APR_SUCCESS)
		return -1;

	return (prevsize == size) ? size : -1;
}

static int
write_data_string (apr_socket_t *sock, const char *str)
{
	int l;
	int lel;

	l = (str == NULL) ? 0 : strlen (str);
	lel = LE_FROM_INT (l);
	if (write_data (sock, &lel, sizeof (int)) != sizeof (int))
		return -1;

	if (l == 0)
		return 0;

	return write_data (sock, str, l);
}

static int
read_data (apr_socket_t *sock, void *ptr, int size)
{
	int prevsize = size;

	if (apr_socket_recv (sock, ptr, &size) != APR_SUCCESS)
		return -1;

	return (prevsize == size) ? size : -1;
}

static char *
read_data_string (apr_pool_t *pool, apr_socket_t *sock, char **ptr, int *size)
{
	int l, count;
	char *buf;
	apr_status_t result;

	if (read_data (sock, &l, sizeof (int)) == -1)
		return NULL;

	l = INT_FROM_LE (l);
	buf = apr_pcalloc (pool, l + 1);
	count = l;
	while (count > 0) {
		result = read_data (sock, buf + l - count, count);
		if (result == -1)
			return NULL;

		count -= result;
	}

	if (ptr)
		*ptr = buf;

	if (size)
		*size = l;

	return buf;
}

static int
do_command (int command, apr_socket_t *sock, request_rec *r, int *result)
{
	int size;
	char *str;
	char *str2;
	int i;
	int status = 0;

	if (command < 0 || command >= LAST_COMMAND) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				"Unknown command: %d", command);
		*result = HTTP_INTERNAL_SERVER_ERROR;
		return FALSE;
	}

	DEBUG_PRINT (2, "Command received: %s", cmdNames [command]);
	ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
			"Command received: %s", cmdNames [command]);
	*result = OK;
	switch (command) {
	case SEND_FROM_MEMORY:
		if (read_data_string (r->pool, sock, &str, &size) == NULL) {
			status = -1;
			break;
		}
		request_send_response_from_memory (r, str, size);
		break;
	case GET_SERVER_VARIABLE:
		if (read_data_string (r->pool, sock, &str, NULL) == NULL) {
			break;
		}
		str = (char *) apr_table_get (r->subprocess_env, str);
		status = write_data_string (sock, str);
		break;
	case SET_RESPONSE_HEADER:
		if (read_data_string (r->pool, sock, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		if (read_data_string (r->pool, sock, &str2, NULL) == NULL) {
			status = -1;
			break;
		}
		set_response_header (r, str, str2);
		break;
	case GET_LOCAL_PORT:
		i = connection_get_local_port (r);
		i = LE_FROM_INT (i);
		status = write_data (sock, &i, sizeof (int));
		break;
	case FLUSH: /* The case will be removed after next release */
		/* connection_flush (r); */
		break;
	case CLOSE:
		return FALSE;
		break;
	case SHOULD_CLIENT_BLOCK:
		size = ap_should_client_block (r);
		size = LE_FROM_INT (size);
		status = write_data (sock, &size, sizeof (int));
		break;
	case SETUP_CLIENT_BLOCK:
		if (setup_client_block (r) != APR_SUCCESS) {
			size = LE_FROM_INT (-1);
			status = write_data (sock, &size, sizeof (int));
			break;
		}

		size = LE_FROM_INT (0);
		status = write_data (sock, &size, sizeof (int));
		break;
	case GET_CLIENT_BLOCK:
		status = read_data (sock, &i, sizeof (int));
		if (status == -1)
			break;

		i = INT_FROM_LE (i);
		str = apr_pcalloc (r->pool, i);
		i = ap_get_client_block (r, str, i);
		i = LE_FROM_INT (i);
		status = write_data (sock, &i, sizeof (int));
		i = INT_FROM_LE (i);
		status = write_data (sock, str, i);
		break;
	case SET_STATUS:
		status = read_data (sock, &i, sizeof (int));
		if (status == -1)
			break;

		if (read_data_string (r->pool, sock, &str, NULL) == NULL) {
			status = -1;
			break;
		}
		r->status = INT_FROM_LE (i);
		r->status_line = apr_pstrdup (r->pool, str);
		break;
	case DECLINE_REQUEST:
		*result = DECLINED;
		return FALSE;
	case MYNOT_FOUND:
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				"No application found for %s", r->uri);

		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				"Host header was %s",
				apr_table_get (r->headers_in, "host"));

		*result = HTTP_NOT_FOUND;
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

#ifndef APACHE2
static apr_status_t
apr_sockaddr_info_get (apr_sockaddr_t **sa, const char *hostname,
			int family, int port, int flags, apr_pool_t *p)
{
	struct addrinfo hints, *list;
	int error;
	struct sockaddr_in *addr;

	if (port < 0 || port > 65535)
		return EINVAL;

	memset (&hints, 0, sizeof (hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_STREAM;
	error = getaddrinfo (hostname, NULL, &hints, &list);
	if (error != 0) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			"mod_mono: getaddrinfo failed (%s) hostname: '%s' port: '%d'.",
			strerror (error), hostname, port);

		return error;
	}

	*sa = apr_pcalloc (p, sizeof (apr_sockaddr_t));
	(*sa)->pool = p;
	(*sa)->addrlen = list->ai_addrlen;
	(*sa)->addr = apr_pcalloc (p, list->ai_addrlen);
	memcpy ((*sa)->addr, list->ai_addr, list->ai_addrlen);
	addr = (struct sockaddr_in *) (*sa)->addr;
	addr->sin_port = htons (port);

	freeaddrinfo (list);

	return APR_SUCCESS;
}

static apr_status_t
apr_socket_connect (apr_socket_t *sock, apr_sockaddr_t *sa)
{
	int sock_fd;

	apr_os_sock_get (&sock_fd, sock);
	if (connect (sock_fd, sa->addr, sa->addrlen) != 0)
		return errno;

	return APR_SUCCESS;
}

static apr_status_t
apr_socket_send (apr_socket_t *sock, const char *buf, apr_size_t *len)
{
	int result;
	int total;

	total = 0;
	do {
		result = write (sock->fd, buf + total, (*len) - total);
		if (result >= 0)
			total += result;
	} while ((result >= 0 && total < *len) || (result == -1 && errno == EINTR));

	return (total == *len) ? 0 : -1;
}

static apr_status_t
apr_socket_recv (apr_socket_t *sock, char *buf, apr_size_t *len)
{
	int result;
	int total;
	apr_os_sock_t sock_fd;

	apr_os_sock_get (&sock_fd, sock);
	total = 0;
	do {
		result = read (sock_fd, buf + total, (*len) - total);
		if (result >= 0)
			total += result;
	} while ((result >= 0 && total < *len) || (result == -1 && errno == EINTR));

	return (total == *len) ? 0 : -1;
}

static apr_status_t
apr_wait_for_io_or_timeout (void *unused, apr_socket_t *s, int for_read)
{
	fd_set fds;
	int ret;
	struct timeval tv, *tvptr;
	div_t divvy;
	time_t timeout;
	int fd;

	fd = s->fd;
	timeout = s->timeout;
	divvy = div (timeout, 1000);
	do {
		FD_ZERO (&fds);
		FD_SET (fd, &fds);
		if (timeout >= 0) {
			tv.tv_sec = divvy.quot;
			tv.tv_usec = divvy.rem;
			tvptr = &tv;
		} else {
			tvptr = NULL;
		}

		if (for_read)
			ret = select (fd + 1, &fds, NULL, NULL, tvptr);
		else
			ret = select (fd + 1, NULL, &fds, NULL, tvptr);

	} while (ret == -1 && errno == EINTR);

	return (ret == 1) ? 0 : -1;
}
#elif !defined (HAVE_APR_SOCKET_CONNECT)
	/* libapr-0 <= 0.9.3 (or 0.9.2?) */
#	define apr_socket_connect apr_connect
#endif

static apr_status_t 
try_connect (mono_server_rec *conf, apr_socket_t **sock, apr_pool_t *pool)
{
	char *error;
	struct sockaddr_un unix_address;
	struct sockaddr *ptradd;
	char *fn, *la;

	fn = conf->filename ? conf->filename : SOCKET_FILE;
	la = conf->listen_address ? conf->listen_address : LISTEN_ADDRESS;
	if (conf->listen_port == NULL) {
		apr_os_sock_t sock_fd;

		apr_os_sock_get (&sock_fd, *sock);
		unix_address.sun_family = PF_UNIX;
		memcpy (unix_address.sun_path, fn, strlen (fn) + 1);
		ptradd = (struct sockaddr *) &unix_address;
		if (connect (sock_fd, ptradd, sizeof (unix_address)) != -1)
			return APR_SUCCESS;
	} else {
		apr_status_t rv;
		apr_sockaddr_t *sa;

		rv = apr_sockaddr_info_get (&sa, la, APR_INET,
					atoi (conf->listen_port), 0, pool);

		if (rv != APR_SUCCESS) {
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: error in address ('%s') or port ('%s').",
				      la, conf->listen_port);
			return -2;
		}

		rv = apr_socket_connect (*sock, sa);
		if (rv == APR_SUCCESS)
			return APR_SUCCESS;
		errno = rv;
	}

	switch (errno) {
	case ENOENT:
	case ECONNREFUSED:
		return -1; /* Can try to launch mod-mono-server */
	case EPERM:
		error = strerror (errno);
		if (conf->listen_port == NULL)
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: file %s exists, but wrong permissions.", fn);
		else
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: no permission to listen on %s.",
				      conf->listen_port);


		apr_socket_close (*sock);
		return -2; /* Unrecoverable */
	default:
		error = strerror (errno);
		if (conf->listen_port == NULL)
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: connect error (%s). File: %s",
				      error, fn);
		else
			ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
				      "mod_mono: connect error (%s). Address: %s Port: %s",
				      error, la, conf->listen_port);


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
set_process_limits (int max_cpu_time, int max_memory)
{
#ifdef HAVE_SETRLIMIT
	struct rlimit limit;

	if (max_cpu_time > 0) {
		/* We don't want SIGXCPU */
		limit.rlim_cur = max_cpu_time;
		limit.rlim_max = max_cpu_time;
		DEBUG_PRINT (1, "Setting CPU time limit to %d", max_cpu_time);
		(void) setrlimit (RLIMIT_CPU, &limit);
	}

	if (max_memory > 0) {
		/* We don't want ENOMEM */
		limit.rlim_cur = max_memory;
		limit.rlim_max = max_memory;
		DEBUG_PRINT (1, "Setting memory limit to %d", max_memory);
		(void) setrlimit (RLIMIT_DATA, &limit);
	}
#endif
}

static void
fork_mod_mono_server (apr_pool_t *pool, mono_server_rec *server_conf)
{
	pid_t pid;
	int i;
	const int MAXARGS = 20;
	char *argv [MAXARGS];
	int argi;
	char *path;
	char *tmp;
	char *monodir;
	char *serverdir;
	char *wapidir;
	int max_memory = 0;
	int max_cpu_time = 0;

	if (server_conf->max_memory != NULL)
		max_memory = atoi (server_conf->max_memory);

	if (server_conf->max_cpu_time != NULL)
		max_cpu_time = atoi (server_conf->max_cpu_time);

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

	set_process_limits (max_cpu_time, max_memory);
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
	if (chmod (wapidir, 0700) != 0 && (errno == EPERM || errno == EACCES)) {
		ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
			"%s: %s", wapidir, strerror (errno));
		exit (1);
	}
	
	SETENV (pool, "MONO_SHARED_DIR", server_conf->wapidir);

	memset (argv, 0, sizeof (char *) * MAXARGS);
	argi = 0;
	argv [argi++] = server_conf->executable_path;
	argv [argi++] = "--debug";
	argv [argi++] = server_conf->server_path;
	if (server_conf->listen_port != NULL) {
		char *la;

		la = server_conf->listen_address;
		la = la ? la : LISTEN_ADDRESS;
		argv [argi++] = "--address";
		argv [argi++] = la;
		argv [argi++] = "--port";
		argv [argi++] = server_conf->listen_port;
	} else {
		char *fn;

		fn = server_conf->filename;
		fn = fn ? fn : SOCKET_FILE;
		argv [argi++] = "--filename";
		argv [argi++] = fn;
	}

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

	ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
                      "running '%s %s %s %s %s %s %s %s %s %s %s %s %s'",
                      argv [0], argv [1], argv [2], argv [3], argv [4],
		      argv [5], argv [6], argv [7], argv [8], 
		      argv [9], argv [10], argv [11], argv [12]);

	execv (argv [0], argv);
	ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
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
	int i;
	apr_status_t rv;
	int family;

	family = (server_conf->listen_port != NULL) ? PF_INET : PF_UNIX;
#ifdef APACHE2
	rv = apr_socket_create (sock, family, SOCK_STREAM, pool);
#else
	(*sock)->fd = ap_psocket (pool, family, SOCK_STREAM, 0);
	(*sock)->pool = pool;
	rv = ((*sock)->fd != -1) ? APR_SUCCESS : -1;
#endif
	if (rv != APR_SUCCESS) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "mod_mono: error creating socket.");

		return rv;
	}

	rv = try_connect (server_conf, sock, pool);
	DEBUG_PRINT (1, "try_connect: %d", (int) rv);
	if (rv == APR_SUCCESS)
		return rv;

	if (rv == -2)
		return -1;

	/* Running mod-mono-server not requested */
	if (!strcasecmp (server_conf->run_xsp, "false")) {
		DEBUG_PRINT (1, "Not running mod-mono-server: %s", server_conf->run_xsp);
		ap_log_error (APLOG_MARK, APLOG_DEBUG, STATUS_AND_SERVER,
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

	/* Only one of MonoUnixSocket and MonoListenPort. */
	DEBUG_PRINT (1, "Listen port: %s", server_conf->listen_port);
	if (server_conf->listen_port != NULL && server_conf->filename != NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because both MonoUnixSocket and "
			      "MonoListenPort specified.");
		apr_socket_close (*sock);
		return -1;
	}

	/* MonoListenAddress must be used together with MonoListenPort */
	DEBUG_PRINT (1, "Listen address: %s", server_conf->listen_address);
	if (server_conf->listen_port == NULL && server_conf->listen_address != NULL) {
		ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
			      "Not running mod-mono-server.exe because MonoListenAddress "
			      "is present and there is no MonoListenPort.");
		apr_socket_close (*sock);
		return -1;
	}


	fork_mod_mono_server (pool, server_conf);

	DEBUG_PRINT (1, "parent waiting");
	for (i = 0; i < 3; i++) {
		sleep (1);
		DEBUG_PRINT (1, "try_connect %d", i);
		rv = try_connect (server_conf, sock, pool);
		if (rv == APR_SUCCESS)
			return APR_SUCCESS;

		if (rv == -2)
			break;
	}

	ap_log_error (APLOG_MARK, APLOG_ERR, STATUS_AND_SERVER,
		      "Failed connecting. %s", strerror (errno));

	apr_socket_close (*sock);
	return -1;
}

static int
write_string_to_buffer (char *buffer, int offset, const char *str)
{
	int tmp;
	int le;

	buffer += offset;
	tmp = (str != NULL) ? strlen (str) : 0;
	le = LE_FROM_INT (tmp);
	(*(int *) buffer) = le;
	if (tmp > 0) {
		buffer += sizeof (int);
		memcpy (buffer, str, tmp);
	}

	return tmp + sizeof (int);
}

static int
send_headers (request_rec *r, apr_socket_t *sock)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;
	int tmp;
	int size;
	char *buffer;
	char *ptr;

	elts = apr_table_elts (r->headers_in);
	DEBUG_PRINT (3, "Elements: %d", (int) elts->nelts);
	if (elts->nelts == 0)
		return (write_data (sock, &elts->nelts, sizeof (int)) == sizeof (int));

	size = sizeof (int);
	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;
	tmp = 0;

	do {
		size += sizeof (int) * 2;
		size += strlen (t_elt->key);
		size += strlen (t_elt->val);
		t_elt++;
		tmp++;
	} while (t_elt < t_end);

	buffer = apr_pcalloc (r->pool, size);
	ptr = buffer;

	tmp = LE_FROM_INT (tmp);
	(*(int *) ptr) = tmp;
	ptr += sizeof (int);
	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		DEBUG_PRINT (3, "%s: %s", t_elt->key, t_elt->val);
		ptr += write_string_to_buffer (ptr, 0, t_elt->key);
		ptr += write_string_to_buffer (ptr, 0, t_elt->val);

		t_elt++;
	} while (t_elt < t_end);

	return (write_data (sock, buffer, size) == size);
}

static int
send_initial_data (request_rec *r, apr_socket_t *sock)
{
	int i;
	char *str, *ptr;
	int size;

	DEBUG_PRINT (2, "Send init1");
	size = ((r->method != NULL) ? strlen (r->method) : 0) + sizeof (int);
	size += ((r->uri != NULL) ? strlen (r->uri) : 0) + sizeof (int);
	size += ((r->args != NULL) ? strlen (r->args) : 0) + sizeof (int);
	size += ((r->protocol != NULL) ? strlen (r->protocol) : 0) + sizeof (int);

	ptr = str = apr_pcalloc (r->pool, size);
	ptr += write_string_to_buffer (ptr, 0, r->method);
	ptr += write_string_to_buffer (ptr, 0, r->uri);
	ptr += write_string_to_buffer (ptr, 0, r->args);
	ptr += write_string_to_buffer (ptr, 0, r->protocol);
	if (write_data (sock, str, size) != size)
		return -1;

	DEBUG_PRINT (2, "Sending headers (init2)");
	if (!send_headers (r, sock))
		return -1;

	DEBUG_PRINT (2, "Done headers (init2)");

	size = strlen (r->connection->local_ip) + sizeof (int);
	size += sizeof (int);
	size += strlen (r->connection->remote_ip) + sizeof (int);
	size += sizeof (int);
	size += strlen (connection_get_remote_name (r)) + sizeof (int);

	ptr = str = apr_pcalloc (r->pool, size);
	ptr += write_string_to_buffer (ptr, 0, r->connection->local_ip);
	i = request_get_server_port (r);
	i = LE_FROM_INT (i);
	(*(int *) ptr) = i;
	ptr += sizeof (int);
	ptr += write_string_to_buffer (ptr, 0, r->connection->remote_ip);
	i = connection_get_remote_port (r->connection);
	i = LE_FROM_INT (i);
	(*(int *) ptr) = i;
	ptr += sizeof (int);
	ptr += write_string_to_buffer (ptr, 0, connection_get_remote_name (r));

	DEBUG_PRINT (2, "Sending init3");
	if (write_data (sock, str, size) != size)
		return -1;

	DEBUG_PRINT (2, "Done init3");

	return 0;
}

static int
mono_execute_request (request_rec *r)
{
	apr_socket_t *sock;
	apr_status_t rv;
	int command;
	int result;
	apr_status_t input;
	int status;
	mono_server_rec *server_conf;

	server_conf = ap_get_module_config (r->server->module_config, &mono_module);
#ifdef APACHE13
	sock = apr_pcalloc (r->pool, sizeof (apr_socket_t));
#endif
	rv = setup_socket (&sock, server_conf, r->pool);
	DEBUG_PRINT (2, "After setup_socket");
	if (rv != APR_SUCCESS)
		return HTTP_SERVICE_UNAVAILABLE;

	if (send_initial_data (r, sock) != 0) {
		apr_socket_close (sock);
		return HTTP_SERVICE_UNAVAILABLE;
	}
	
	do {
		input = read_data (sock, (char *) &command, sizeof (int));
		if (input == sizeof (int)) {
			command = INT_FROM_LE (command);
			result = do_command (command, sock, r, &status);
		}
	} while (input == sizeof (int) && result == TRUE);

	apr_socket_close (sock);
	if (input != sizeof (int))
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
	pconf = p;
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
	return OK;
}
#endif

#ifdef APACHE13
static const handler_rec mono_handlers [] = {
	{ "mono", mono_handler },
	{ NULL, NULL }
};
#else
static void
mono_register_hooks (apr_pool_t * p)
{
	ap_hook_handler (mono_handler, NULL, NULL, APR_HOOK_FIRST);
	ap_hook_post_config (mono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

static const command_rec mono_cmds [] = {
MAKE_CMD (MonoUnixSocket, unix_socket,
	"Named pipe file name. Mutually exclusive with MonoListenPort. "
	"Default: /tmp/mod_mono_server"
	),

MAKE_CMD (MonoListenPort, listen_port,
	"TCP port on which mod-mono-server should listen/is listening on. Mutually "
	"exclusive with MonoUnixSocket. "
	"When this options is specified, "
	"mod-mono-server and mod_mono will use a TCP socket for communication. "
	"Default: none"
	),

MAKE_CMD (MonoListenAddress, listen_address,
	"IP address where mod-mono-server should listen/is listening on. Can "
	"only be used when MonoListenPort is specified."
	"Default: \"127.0.0.1\""
	),

MAKE_CMD (MonoRunXSP, run_xsp,
	"It can be False or True. If it is True, asks the module to "
	"start mod-mono-server.exe if it's not already there. Default: True"
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

#ifndef HAVE_SETRLIMIT
MAKE_CMD (MonoMaxMemory, max_memory,
	"If MonoRunXSP is True, the maximum size of the process's data segment "
	"(data size) in bytes allowed for the spawned mono process. It will "
	"be restarted when the limit is reached.  .. but your system doesn't "
	"support setrlimit. Sorry, this feature will not be available. "
	"Default value: system default"
	),
#else
MAKE_CMD (MonoMaxMemory, max_memory,
	"If MonoRunXSP is True, the maximum size of the process's data "
	"segment (data size) in bytes allowed "
	"for the spawned mono process. It will be restarted when the limit "
	"is reached."
	" Default value: system default"
	),
#endif

#ifndef HAVE_SETRLIMIT
MAKE_CMD (MonoMaxCPUTime, max_cpu_time,
	"If MonoRunXSP is True, CPU time limit in seconds allowed for "
	"the spawned mono process. Beyond that, it will be restarted."
	".. but your system doesn't support setrlimit. Sorry, this feature "
	"will not be available."
	" Default value: system default"
	),
#else
MAKE_CMD (MonoMaxCPUTime, max_cpu_time,
	"If MonoRunXSP is True, CPU time limit in seconds allowed for "
	"the spawned mono process. Beyond that, it will be restarted."
	" Default value: system default"
	),
#endif
	{ NULL }
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


