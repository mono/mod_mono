/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Authors:
 * 	Daniel Lopez Ridruejo
 * 	Gonzalo Paniagua Javier <gonzalo @ ximian.com >
 * 	
 * Copyright (c) 2002 Daniel Lopez Ridruejo.
 *           (c) 2002,2003 Ximian, Inc.
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
 * 4. The name "mod_mono_unix" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono_unix",
 *    nor may "mod_mono_unix" appear in their name, without prior written
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
#ifdef APACHE13

/* Functions needed for making Apache 1.3 module as similar
as possible to Apache 2 module, reducing ifdefs in the code itself*/

#define TRUE 1
#define FALSE 0

#define apr_pool_t pool
#define apr_pcalloc_t ap_pcalloc
#define apr_table_setn ap_table_setn
#define APR_SUCCESS 0

#else
#include <http_protocol.h>
#endif

#include <http_core.h>
#include <http_log.h>
#include <mod_mono_config.h>
#include <sys/un.h>
#include <sys/select.h>

enum Cmd {
	FIRST_COMMAND,
	GET_PROTOCOL = 0,
	GET_METHOD,
	SEND_FROM_MEMORY,
	GET_PATH_INFO,
	GET_SERVER_VARIABLE,
	GET_PATH_TRANSLATED,
	GET_SERVER_PORT,
	SET_RESPONSE_HEADER,
	GET_REQUEST_HEADER,
	GET_FILENAME,
	GET_URI,
	GET_QUERY_STRING,
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

char *cmdNames [] = {
	"GET_PROTOCOL",
	"GET_METHOD",
	"SEND_FROM_MEMORY",
	"GET_PATH_INFO",
	"GET_SERVER_VARIABLE",
	"GET_PATH_TRANSLATED",
	"GET_SERVER_PORT",
	"SET_RESPONSE_HEADER",
	"GET_REQUEST_HEADER",
	"GET_FILENAME",
	"GET_URI",
	"GET_QUERY_STRING",
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
module MODULE_VAR_EXPORT mono_unix_module;
#else 
module AP_MODULE_DECLARE_DATA mono_unix_module;
#endif

typedef struct {
	const char *filename;
} modmono_server_rec;


static const char *
modmono_application_directive (cmd_parms *cmd,
			       void *config,
			       const char *filename)
{
	modmono_server_rec *server_rec = (modmono_server_rec *)
			ap_get_module_config (cmd->server->module_config, &mono_unix_module);

	server_rec->filename = filename;
	return NULL;
}


static void *
create_modmono_server_config (apr_pool_t *p, server_rec *s)
{
	return apr_pcalloc (p, sizeof (modmono_server_rec));
}

static void
request_send_response_from_memory (request_rec *r, char *byteArray, int size)
{
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

#ifdef APACHE13  
static int
connection_get_local_port (request_rec *r)
{
  return ap_get_server_port(r);
}
#else
static int
connection_get_local_port (conn_rec *c) {
  apr_port_t port;
  apr_sockaddr_port_get (&port, c->local_addr);
  return port;  
}
#endif

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
connection_flush (conn_rec *c)
{
  ap_flush_conn (c);
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
	if (!strcmp(name,"Content-Type")) {
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
	return r->parsed_uri.query ? r->parsed_uri.query : "";
}

static int
should_client_block (request_rec *r)
{
	return r->read_length || ap_should_client_block (r);
}

static int
setup_client_block (request_rec *r)
{
	if (r->read_length) {
	  return APR_SUCCESS;
	} else {
		return ap_setup_client_block (r, REQUEST_CHUNKED_ERROR);
	}
}

static void
write_data (int fd, const void *str, int size)
{
	write (fd, str, size);
}

static void
write_ok (int fd)
{
	int i = 0;
	
	write (fd, &i, 1);
}

static void
write_err (int fd)
{
	int i = -1;
	
	write (fd, &i, 1);
}

static void
write_data_string (int fd, const char *str)
{
	int l;

	l = (str == NULL) ? 0 : strlen (str);
	write (fd, &l, sizeof (int));
	write (fd, str, l);
}

static char *
read_data_string (apr_pool_t *pool, int fd, char **ptr, int *size)
{
	int l;
	char *buf;

	read (fd, &l, sizeof (int));
	buf = apr_pcalloc (pool, l + 1);
	read (fd, buf, l);
	/* buf [l] = '\0'; */
	if (ptr)
		*ptr = buf;

	if (size)
		*size = l;

	return buf;
}

static void
read_data (int fd, void *ptr, int size)
{
	read (fd, ptr, size);
}

static int
do_command (int command, int fd, request_rec *r, int *result)
{
	int size;
	char *str;
	char *str2;
	int i;

	ap_log_error (APLOG_MARK, APLOG_DEBUG, 0, NULL, "Command received: %s", cmdNames [command]);
	*result = OK;
	switch (command) {
	case GET_PROTOCOL:
		write_ok (fd);
		write_data_string (fd, r->protocol);
		break;
	case GET_METHOD:
		write_ok (fd);
		write_data_string (fd, r->method);
		break;
	case SEND_FROM_MEMORY:
		read_data_string (r->pool, fd, &str, &size);
		request_send_response_from_memory (r, str, size);
		write_ok (fd);
		break;
	case GET_PATH_INFO:
		write_ok (fd);
		write_data_string (fd, r->path_info);
		break;
	case GET_SERVER_VARIABLE:
		str = read_data_string (r->pool, fd, &str, NULL);
		str = (char *) request_get_server_variable (r, str);
		write_ok (fd);
		write_data_string (fd, str);
		break;
	case GET_PATH_TRANSLATED:
		str = request_get_path_translated (r);
		write_ok (fd);
		write_data_string (fd, str);
		break;
	case GET_SERVER_PORT:
		i = request_get_server_port (r);
		write_ok (fd);
		write_data (fd, &i, sizeof (int));
		break;
	case SET_RESPONSE_HEADER:
		read_data_string (r->pool, fd, &str, NULL);
		read_data_string (r->pool, fd, &str2, NULL);
		set_response_header (r, str, str2);
		write_ok (fd);
		break;
	case GET_REQUEST_HEADER:
		str = read_data_string (r->pool, fd, &str, NULL);
		write_ok (fd);
		str = (char *) request_get_request_header (r, str);
		write_data_string (fd, str);
		break;
	case GET_FILENAME:
		write_ok (fd);
		write_data_string (fd, r->filename);
		break;
	case GET_URI:
		write_ok (fd);
		write_data_string (fd, r->uri);
		break;
	case GET_QUERY_STRING:
		write_ok (fd);
		str = request_get_query_string (r);
		write_data_string (fd, str);
		break;
	case GET_REMOTE_ADDRESS:
		write_ok (fd);
		write_data_string (fd, r->connection->remote_ip);
		break;
	case GET_LOCAL_ADDRESS:
		write_ok (fd);
		write_data_string (fd, r->connection->local_ip);
		break;
	case GET_REMOTE_PORT:
		write_ok (fd);
		i = connection_get_remote_port (r->connection);
		write_data (fd, &i, sizeof (int));
		break;
	case GET_LOCAL_PORT:
		write_ok (fd);
#ifdef APACHE13		
		i = connection_get_local_port (r);
#else
		i = connection_get_local_port (r->connection);
#endif
		write_data (fd, &i, sizeof (int));
		break;
	case GET_REMOTE_NAME:
		write_ok (fd);
		str = (char *) connection_get_remote_name (r);
		write_data_string (fd, str);
		break;
	case FLUSH:
		connection_flush (r->connection);
		write_ok (fd);
		break;
	case CLOSE:
		write_ok (fd);
		return FALSE;
		break;
	case SHOULD_CLIENT_BLOCK:
		size = should_client_block (r);
		write_ok (fd);
		write_data (fd, &size, sizeof (int));
		break;
	case SETUP_CLIENT_BLOCK:
		size = setup_client_block (r);
		write_ok (fd);
		write_data (fd, &size, sizeof (int));
		break;
	case GET_CLIENT_BLOCK:
		read_data (fd, &i, sizeof (int));
		str = apr_pcalloc (r->pool, i);
		i = ap_get_client_block (r, str, i);
		write_ok (fd);
		write_data (fd, &i, sizeof (int));
		write_data (fd, str, i);
		break;
	case SET_STATUS_LINE:
		read_data_string (r->pool, fd, &str, NULL);
		write_ok (fd);
		r->status_line = strdup (str);
		break;
	case SET_STATUS_CODE:
		read_data (fd, &i, sizeof (int));
		r->status = i;
		write_ok (fd);
		break;
	case DECLINE_REQUEST:
		write_ok (fd);
		*result = DECLINED;
		return FALSE;
	default:
		*result = HTTP_INTERNAL_SERVER_ERROR;
		write_err (fd);
		return FALSE;
	}

	return TRUE;
}

static int
setup_socket (const char *filename)
{
	int fd;
	struct sockaddr_un address;

	fd = socket (PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      0,
			      NULL,
			      "mod_mono_unix: error creating socket.");


		return -1;
	}

	address.sun_family = PF_UNIX;
	memcpy (address.sun_path, filename, strlen (filename) + 1);
	if (connect (fd, (struct sockaddr *) &address, sizeof (struct sockaddr_un)) == -1) {
		char *s = strerror (errno);
		ap_log_error (APLOG_MARK,
			      APLOG_DEBUG,
			      0,
			      NULL,
			      "mod_mono_unix: connect error (%s). File: %s", s, filename);

		close (fd);
		return -1;
	}

	return fd;
}

static int
modmono_execute_request (request_rec *r)
{
	int fd;
	int command;
	int result;
	int input;
	int status;
	modmono_server_rec *server_conf;

	server_conf = ap_get_module_config (r->server->module_config, &mono_unix_module);

	fd = setup_socket (server_conf->filename);
	if (fd == -1)
		return HTTP_INTERNAL_SERVER_ERROR;

	do {
		input = read (fd, &command, sizeof (int));
		if (input > 0)
			result = do_command (command, fd, r, &status);
	} while (input != -1 && result == TRUE);

	close (fd);
	if (input == -1)
		status = HTTP_INTERNAL_SERVER_ERROR;

	return status;
}

static int
modmono_handler (request_rec *r)
{
	if (strcmp (r->content_type, "application/x-asp-net"))
		return DECLINED;

	return modmono_execute_request (r);
}

#ifdef APACHE13
static void
modmono_init_handler (server_rec *s, pool *p)
{
	ap_add_version_component ("mod_mono_unix/" VERSION);
}
#else
static int
modmono_init_handler (apr_pool_t *p,
		      apr_pool_t *plog,
		      apr_pool_t *ptemp,
		      server_rec *s)
{
  ap_add_version_component (p, "mod_mono_unix/" VERSION);
  return OK;
}
#endif

#ifdef APACHE13
static const handler_rec modmono_handlers[] =
  {
    {"modmono-handler", modmono_handler},
    {NULL}
  };
#else
static void
register_modmono_hooks (apr_pool_t * p)
{
  ap_hook_handler (modmono_handler, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_post_config (modmono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}
#endif

#ifdef APACHE13
static const command_rec
modmono_cmds [] =
{
	{"MonoApplicationUnix",
	 modmono_application_directive,
	 NULL,
	 RSRC_CONF,
	 TAKE1,
	 "Create a Mono Application. The unique argument "
	 "is the unix socket file name."
	},
	{NULL}
};

module MODULE_VAR_EXPORT mono_unix_module =
  {
    STANDARD_MODULE_STUFF,
    modmono_init_handler,       /* initializer */
    NULL,      /* dir config creater */
    NULL,      /* dir merger --- default is to override */
    create_modmono_server_config,	/* server config */
    NULL,                       /* merge server configs */
    modmono_cmds,            /* command table */
    modmono_handlers,         /* handlers */
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
static const command_rec
modmono_cmds [] =
  {
    AP_INIT_TAKE1 ("MonoApplicationUnix",
		   modmono_application_directive,
		   NULL,
		   RSRC_CONF,
		   "Create a Mono Application. The unique argument "
		   "is the unix socket file name."
		  ),
    NULL

  };

module AP_MODULE_DECLARE_DATA mono_unix_module =
  {
    STANDARD20_MODULE_STUFF,
    NULL,/* dir config creater */
    NULL,/* dir merger --- default is to override */
    create_modmono_server_config,/* server config */
    NULL,/* merge server configs */
    modmono_cmds,/* command apr_table_t */
    register_modmono_hooks/* register hooks */
  };
#endif


