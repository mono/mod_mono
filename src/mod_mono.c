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
#ifdef APACHE13

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
#else
#define STATUS_AND_SERVER 0, NULL
#include <http_protocol.h>
#include <apr_strings.h>
#endif

#include <http_core.h>
#include <http_log.h>
#include <mod_mono_config.h>
#include <sys/un.h>
#include <sys/select.h>

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

char *cmdNames [] = {
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
	const char *filename;
} modmono_server_rec;


static const char *
modmono_application_directive (cmd_parms *cmd,
			       void *config,
			       const char *filename)
{
	modmono_server_rec *server_rec = (modmono_server_rec *)
			ap_get_module_config (cmd->server->module_config, &mono_module);

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
	return r->args  ? r->args : "";
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

static int
write_data_no_prefix (int fd, const void *str, int size)
{
	return write (fd, str, size);
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

	return write_data_no_prefix (fd, str, size);
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
		status = write_data_no_prefix (fd, str, i);
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
setup_socket (const char *filename)
{
	int fd;
	struct sockaddr_un address;

	fd = socket (PF_UNIX, SOCK_STREAM, 0);
	if (fd == -1) {
		ap_log_error (APLOG_MARK,
			      APLOG_ERR,
			      STATUS_AND_SERVER,
			      "mod_mono: error creating socket.");

		return -1;
	}

	address.sun_family = PF_UNIX;
	memcpy (address.sun_path, filename, strlen (filename) + 1);
	if (connect (fd, (struct sockaddr *) &address, sizeof (struct sockaddr_un)) == -1) {
		char *s = strerror (errno);
		ap_log_error (APLOG_MARK,
			      APLOG_DEBUG,
			      STATUS_AND_SERVER,
			      "mod_mono: connect error (%s). File: %s", s, filename);

		close (fd);
		return -1;
	}

	return fd;
}

static int
send_headers (request_rec *r, int fd)
{
	const apr_array_header_t *elts;
	const apr_table_entry_t *t_elt;
	const apr_table_entry_t *t_end;

	elts = apr_table_elts (r->headers_in);
	write_data_no_prefix (fd, &elts->nelts, sizeof (int));
	if (elts->nelts == 0)
		return TRUE;

	t_elt = (const apr_table_entry_t *) (elts->elts);
	t_end = t_elt + elts->nelts;

	do {
		if (write_data_string_no_prefix (fd, t_elt->key) <= 0)
			return FALSE;
		if (write_data_string_no_prefix (fd, t_elt->val) < 0)
			return FALSE;


		t_elt++;
	} while (t_elt < t_end);

	return TRUE;
}

static int
modmono_execute_request (request_rec *r)
{
	int fd;
	int command;
	int result;
	int input;
	int status;
	char *str;
	modmono_server_rec *server_conf;

	server_conf = ap_get_module_config (r->server->module_config, &mono_module);

	fd = setup_socket (server_conf->filename);
	if (fd == -1)
		return HTTP_SERVICE_UNAVAILABLE;

	if (write_data_string_no_prefix (fd, r->method) <= 0)
		return HTTP_SERVICE_UNAVAILABLE;

	if (write_data_string_no_prefix (fd, r->uri) <= 0)
		return HTTP_SERVICE_UNAVAILABLE;

	if (write_data_string_no_prefix (fd, request_get_query_string (r)) < 0)
		return HTTP_SERVICE_UNAVAILABLE;

	if (write_data_string_no_prefix (fd, r->protocol) <= 0)
		return HTTP_SERVICE_UNAVAILABLE;
	
	if (!send_headers (r, fd))
		return HTTP_SERVICE_UNAVAILABLE;
		
	do {
		input = read (fd, &command, sizeof (int));
		if (input > 0)
			result = do_command (command, fd, r, &status);
	} while (input > 0 && result == TRUE);

	close (fd);
	if (input <= 0)
		status = HTTP_INTERNAL_SERVER_ERROR;

	return status;
}

static int
modmono_handler (request_rec *r)
{
	if (!r->content_type || strcmp (r->content_type, "application/x-asp-net"))
		return DECLINED;

	return modmono_execute_request (r);
}

#ifdef APACHE13
static void
modmono_init_handler (server_rec *s, pool *p)
{
	ap_add_version_component ("mod_mono/" VERSION);
}
#else
static int
modmono_init_handler (apr_pool_t *p,
		      apr_pool_t *plog,
		      apr_pool_t *ptemp,
		      server_rec *s)
{
  ap_add_version_component (p, "mod_mono/" VERSION);
  return OK;
}
#endif

#ifdef APACHE13
static const handler_rec modmono_handlers[] =
  {
    {"application/x-asp-net", modmono_handler},
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
	{"MonoUnixSocket",
	 modmono_application_directive,
	 NULL,
	 RSRC_CONF,
	 TAKE1,
	 "Create a Mono Application. The unique argument "
	 "is the unix socket file name."
	},
	{NULL}
};

module MODULE_VAR_EXPORT mono_module =
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
    AP_INIT_TAKE1 ("MonoUnixSocket",
		   modmono_application_directive,
		   NULL,
		   RSRC_CONF,
		   "Create a Mono Application. The unique argument "
		   "is the unix socket file name."
		  ),
    NULL

  };

module AP_MODULE_DECLARE_DATA mono_module =
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


