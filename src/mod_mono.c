/* ====================================================================
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 2002 Daniel Lopez Ridruejo.  All rights
 * reserved.
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
 *        Daniel Lopez Ridruejo (daniel@rawbyte.com)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The name "mod_mono" must not be used to endorse or promote products 
 *    derived from this software without prior written permission. For written
 *    permission, please contact daniel@rawbyte.com.
 *
 * 5. Products derived from this software may not be called "mod_mono",
 *    nor may "mod_mono" appear in their name, without prior written
 *    permission of Daniel Lopez Ridruejo.
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
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>
#include <mono/jit/jit.h>
#include <mono/metadata/appdomain.h>
#include <mono/metadata/debug-helpers.h>
#include <mod_mono_config.h>

#define MODMONO_MAGIC_TYPE "application/x-httpd-mono"

module AP_MODULE_DECLARE_DATA mono_module;

#define EXPOSE_REQUEST_FIELD_STRING(funcname, fieldname) static MonoString * funcname (request_rec *r) {  return mono_string_new(mono_domain_get(), r->fieldname);}

#define EXPOSE_CONNECTION_FIELD_STRING(funcname, fieldname) static MonoString * funcname (conn_rec *c) {  return mono_string_new(mono_domain_get(), c->fieldname);}


EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_request, the_request);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_protocol, protocol);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_hostname, hostname);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_status_line, status_line);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_method, method);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_range, range);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_content_type, content_type);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_handler, handler);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_content_encoding, content_encoding);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_user, user);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_auth_type, ap_auth_type);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_unparsed_uri, unparsed_uri);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_uri, uri);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_filename, filename);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_canonical_filename, canonical_filename);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_path_info, path_info);
EXPOSE_REQUEST_FIELD_STRING(mono_apache_request_get_args, args);

EXPOSE_CONNECTION_FIELD_STRING(mono_apache_connection_get_remote_address, remote_ip);
EXPOSE_CONNECTION_FIELD_STRING(mono_apache_connection_get_local_address, local_ip);

typedef struct {
  const char *modmono_dll;
} modmono_server_rec;


static const char *load_modmono_dll(cmd_parms *cmd, void *config,
                                        const char *name)
{
  modmono_server_rec *server_rec = (modmono_server_rec *)
    ap_get_module_config(cmd->server->module_config,
			 &mono_module);
  server_rec->modmono_dll = name;
  return NULL;
}


static void *create_modmono_server_config(apr_pool_t *p, server_rec *s)
{
  modmono_server_rec *new_config = (modmono_server_rec *)
  apr_pcalloc(p, sizeof(*new_config));
  return new_config;
}



static void mono_apache_request_send_response_from_memory (request_rec *r, MonoArray* byteArray, int size)
{
  ap_rwrite(mono_array_to_lparray(byteArray), size, r);
}

/*Not connection because actual port will vary depending on Apache configuration*/
static guint16 mono_apache_request_get_server_port (request_rec *r) {
  return (guint16)ap_get_server_port(r);
}

static guint16 mono_apache_connection_get_remote_port (conn_rec *c) {
  apr_port_t port;
  apr_sockaddr_port_get(&port, c->remote_addr);
  return (guint16)port;
}

static guint16 mono_apache_connection_get_local_port (conn_rec *c) {
  apr_port_t port;
  apr_sockaddr_port_get(&port, c->local_addr);
  return (guint16)port;
}
static MonoString *mono_apache_connection_get_remote_name (request_rec *r) {
  return mono_string_new(mono_domain_get(),  ap_get_remote_host(r->connection, r->per_dir_config,
                                              REMOTE_NAME, NULL));
}

static void mono_apache_connection_flush (conn_rec *c) {
  ap_flush_conn(c);
}

static void mono_apache_request_set_response_header(request_rec *r, MonoString *header_name, MonoString *header_value) {
  apr_table_setn(r->headers_out, mono_string_to_utf8(header_name), mono_string_to_utf8(header_value));
}

static MonoString *mono_apache_request_get_request_header(request_rec *r, MonoString *header_name) {
  return mono_string_new(mono_domain_get(), apr_table_get(r->headers_in, mono_string_to_utf8(header_name)));
}

static conn_rec *mono_apache_request_get_connection (request_rec *r) {
  return r->connection;
}

static conn_rec *mono_apache_connection_close (conn_rec *c) {
  ap_lingering_close(c);
}

static MonoString *mono_apache_request_get_server_variable(request_rec *r, MonoString *name) {
  return mono_string_new(mono_domain_get(), apr_table_get(r->subprocess_env, mono_string_to_utf8(name)));
}

static MonoString *mono_apache_request_get_path_translated(request_rec *r) {
  return mono_string_new(mono_domain_get(), ap_make_dirstr_parent(r->pool, r->filename));
}

static MonoString *mono_apache_request_get_query_string(request_rec *r) {
  return mono_string_new(mono_domain_get(), r->parsed_uri.query);
}
void register_wrappers () {
  mono_add_internal_call("Apache.Web.Request::GetProtocol", mono_apache_request_get_protocol);
  mono_add_internal_call("Apache.Web.Request::GetHttpVersion", mono_apache_request_get_protocol);
  mono_add_internal_call("Apache.Web.Request::GetHttpVerbName", mono_apache_request_get_method);
  mono_add_internal_call("Apache.Web.Request::SendResponseFromMemory", mono_apache_request_send_response_from_memory);
  mono_add_internal_call("Apache.Web.Request::GetConnection", mono_apache_request_get_connection);
  mono_add_internal_call("Apache.Web.Request::GetPathInfo", mono_apache_request_get_path_info);
  mono_add_internal_call("Apache.Web.Request::GetServerVariable", mono_apache_request_get_server_variable);
  mono_add_internal_call("Apache.Web.Request::GetAppPathTranslated", mono_apache_request_get_path_translated);
  mono_add_internal_call("Apache.Web.Request::GetServerPort", mono_apache_request_get_server_port);
  mono_add_internal_call("Apache.Web.Request::SetResponseHeader", mono_apache_request_set_response_header);
  mono_add_internal_call("Apache.Web.Request::GetRequestHeader", mono_apache_request_get_request_header);
  mono_add_internal_call("Apache.Web.Request::GetFileName", mono_apache_request_get_filename);
  mono_add_internal_call("Apache.Web.Request::GetUnparsedUri", mono_apache_request_get_unparsed_uri);
  mono_add_internal_call("Apache.Web.Request::GetUri", mono_apache_request_get_uri);
  mono_add_internal_call("Apache.Web.Request::GetQueryString", mono_apache_request_get_query_string);
  mono_add_internal_call("Apache.Web.Connection::GetRemoteAddress", mono_apache_connection_get_remote_address);
  mono_add_internal_call("Apache.Web.Connection::GetLocalAddress", mono_apache_connection_get_local_address);
  mono_add_internal_call("Apache.Web.Connection::GetRemotePort", mono_apache_connection_get_remote_port);
  mono_add_internal_call("Apache.Web.Connection::GetLocalPort", mono_apache_connection_get_local_port);
  mono_add_internal_call("Apache.Web.Connection::GetRemoteName", mono_apache_connection_get_remote_name);
  mono_add_internal_call("Apache.Web.Connection::Flush", mono_apache_connection_flush);
  mono_add_internal_call("Apache.Web.Connection::Close", mono_apache_connection_close);
}

int modmono_handler (request_rec* r) {
    if (strcmp(r->handler,MODMONO_MAGIC_TYPE)) {
      return DECLINED;
    } else {
      return modmono_request_handler(r);
    }
}

MonoAssembly * modmono_assembly_setup (MonoDomain *domain, const char *file) {
  MonoAssembly *assembly;
  gchar *str;
  if ((assembly = mono_domain_assembly_open(domain, file)) == NULL) {
    return NULL;
  }
  /* See object.c, usually setup when executing assembly, necesary because vpath will be obtained from there*/
  domain->entry_assembly = assembly;
  domain->setup->application_base = mono_string_new (domain, assembly->basedir);
  str = g_strconcat (assembly->basedir, assembly->aname.name,
		     ".exe.config", NULL);
  domain->setup->configuration_file = mono_string_new (domain, str);
  g_free (str);
  return assembly;
}

MonoObject * modmono_create_apache_worker_request(MonoDomain *domain, MonoAssembly *assembly, request_rec *r) {
  MonoMethodDesc *desc;
  MonoObject *ApacheWorkerRequest;
  MonoClass *class;
  MonoMethod *constructorMethod;
  gpointer params[1];

  class = mono_class_from_name (assembly->image, "Apache.Web", "ApacheWorkerRequest");
  if (class == NULL) {
    return NULL;
  }
  ApacheWorkerRequest = mono_object_new(domain, class);
  desc = mono_method_desc_new("::.ctor(intptr)",0);
  constructorMethod = mono_method_desc_search_in_class(desc, class);
  params[0] = &r;
  mono_runtime_invoke (constructorMethod, ApacheWorkerRequest, params, NULL);
  return ApacheWorkerRequest;
}

int modmono_execute_request(MonoObject *ApacheWorkerRequest, gchar *basedir) {
  MonoMethodDesc *desc;
  MonoClass *class;
  MonoMethod *processRequestMethod;
  gchar *cwd;

  desc = mono_method_desc_new ("::ProcessRequest", 0);
  processRequestMethod = mono_method_desc_search_in_class(desc, mono_object_class(ApacheWorkerRequest));

  /* xxx Hack because of the tmp*.dll files, which are created in the current current directory.*/
  cwd = g_malloc(APR_PATH_MAX);
  getcwd(cwd, APR_PATH_MAX);
  if(cwd == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not get current working directory");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  chdir(basedir);
  mono_runtime_invoke (processRequestMethod, ApacheWorkerRequest, NULL, NULL);
  chdir(cwd);
  g_free(cwd);
  return OK;

}
int modmono_request_handler (request_rec* r) {
  MonoDomain *domain;
  MonoAssembly *assembly;
  MonoObject *ApacheWorkerRequest;
  gchar *str;
  modmono_server_rec *server_conf;
  const char *file;
  int retval = 5;
  int result;
  
  server_conf = ap_get_module_config(r->server->module_config, &mono_module);
  file = server_conf->modmono_dll;
  if (file == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: No LoadModMonoDLL directive found");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  register_wrappers();
  domain = mono_jit_init (file);

  if (domain == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not initialize domain");
    return HTTP_INTERNAL_SERVER_ERROR;
  }
  assembly = modmono_assembly_setup(domain, file);
  if (assembly == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not open assembly");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  ApacheWorkerRequest = modmono_create_apache_worker_request(domain, assembly, r);
  if (ApacheWorkerRequest == NULL) {
    ap_log_error(APLOG_MARK, APLOG_NOERRNO|APLOG_ERR, 0, NULL, "mod_mono: Could not locate ApacheWorkerRequest");
    return HTTP_INTERNAL_SERVER_ERROR;
  }

  r->content_type = "text/html";
  result = modmono_execute_request(ApacheWorkerRequest, assembly->basedir);
  /*mono_jit_cleanup(domain); Goes in infinite loop*/
  return result;
}


static int modmono_init_handler (apr_pool_t *p, apr_pool_t *plog, apr_pool_t *ptemp,
			  server_rec *s) {
  ap_add_version_component(p, "mod_mono/0.1");  
  return OK;
}

static void register_modmono_hooks(apr_pool_t * p)
{
  ap_hook_handler(modmono_handler, NULL, NULL, APR_HOOK_FIRST);
  ap_hook_post_config(modmono_init_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec modmono_cmds[] =
  {
    AP_INIT_TAKE1("LoadModMonoDLL", load_modmono_dll, NULL, RSRC_CONF,
                  "Path to ModMono.dll"),
    NULL
  };


module AP_MODULE_DECLARE_DATA mono_module =
  {
    STANDARD20_MODULE_STUFF,
    NULL,             /* dir config creater */
    NULL,              /* dir merger --- default is to override */
    create_modmono_server_config,      /* server config */
    NULL,                          /* merge server configs */
    modmono_cmds,                      /* command apr_table_t */
    register_modmono_hooks                 /* register hooks */
  };

